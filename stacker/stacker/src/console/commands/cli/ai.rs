use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use crate::cli::ai_client::{
    all_write_mode_tools, create_provider, AiProvider, AiResponse, ChatMessage, ToolCall, ToolDef,
};
use crate::cli::ai_scenarios::{load_scenario_prompt_context, ScenarioSelection};
use crate::cli::config_parser::{AiConfig, AiProviderType, StackerConfig};
use crate::cli::error::CliError;
use crate::cli::service_catalog::{catalog_summary_for_ai, ServiceCatalog};
use crate::console::commands::CallableTrait;

const DEFAULT_CONFIG_FILE: &str = "stacker.yml";
const CHAT_MULTILINE_MAX_LINES: usize = 512;
const CHAT_MULTILINE_SEND_MARKER: &str = "::send";
const CHAT_MULTILINE_CANCEL_MARKER: &str = "::cancel";

/// Condensed stacker.yml schema reference injected as the AI system prompt
/// so the model can answer "how do I …" questions with precise YAML examples.
const STACKER_SCHEMA_SYSTEM_PROMPT: &str = "\
You are a helpful assistant for the Stacker CLI — a single-file deployment tool \
that reads `stacker.yml` to auto-generate Dockerfiles, docker-compose definitions, \
and deploy applications locally or to cloud/server infrastructure.

\
Below is the complete stacker.yml configuration schema. \
Use it to answer user questions with concrete YAML examples.

\
## Top-level fields\n\
  name: (string, REQUIRED) Project name\n\
  version: (string) Version label\n\
  organization: (string) Org slug for TryDirect account\n\
  env_file: (path) Path to .env file (loaded before config parsing)\n\
  env: (map) Inline env vars passed to all containers; supports ${VAR} interpolation\n\
\n\
## app — Application source\n\
  app.type: static|node|python|rust|go|php|custom (default: static, auto-detected)\n\
  app.path: (path, default '.') Source directory\n\
  app.dockerfile: (path) Custom Dockerfile (skips generation)\n\
  app.image: (string) Pre-built image (mutually exclusive with dockerfile)\n\
  app.build.context: (string, default '.') Docker build context\n\
  app.build.args: (map) --build-arg key/value pairs\n\
  app.ports: (string[]) e.g. ['8080:3000'] — auto-derived from type if omitted\n\
  app.volumes: (string[]) Bind mounts or named volumes\n\
  app.environment: (map) Per-app env vars merged with top-level env\n\
\n\
## services — Sidecar containers\n\
  Array of: { name, image, ports[], environment{}, volumes[], depends_on[] }\n\
\n\
## proxy — Reverse proxy\n\
  proxy.type: nginx|nginx-proxy-manager|traefik|none (default: none)\n\
  proxy.auto_detect: (bool, default true) Detect running proxy containers\n\
  proxy.domains: [{ domain, ssl: auto|manual|off, upstream }]\n\
  proxy.config: (path) Custom proxy config file\n\
\n\
## deploy — Deployment target\n\
  deploy.target: local|cloud|server (default: local)\n\
  deploy.compose_file: (path) Use existing compose instead of generating\n\
  deploy.cloud: (required when target=cloud)\n\
    provider: hetzner|digitalocean|aws|linode|vultr\n\
    orchestrator: local|remote\n\
    region: (string)\n\
    size: (string)\n\
    ssh_key: (path)\n\
  deploy.server: (required when target=server)\n\
    host: (string, REQUIRED) Hostname or IP\n\
    user: (string, default 'root') SSH user\n\
    port: (int, default 22) SSH port\n\
    ssh_key: (path) SSH private key\n\
  deploy.registry: Docker registry credentials\n\
    username, password, server (default: Docker Hub)\n\
    Env var overrides: STACKER_DOCKER_USERNAME, STACKER_DOCKER_PASSWORD, STACKER_DOCKER_REGISTRY\n\
\n\
## ai — AI assistant\n\
  ai.enabled: (bool, default false)\n\
  ai.provider: openai|anthropic|ollama|custom\n\
  ai.model: (string)\n\
  ai.api_key: (string, supports ${VAR})\n\
  ai.endpoint: (string)\n\
  ai.timeout: (int, default 300)\n\
  ai.tasks: [dockerfile, troubleshoot, compose, security]\n\
\n\
## monitoring\n\
  monitoring.status_panel: (bool)\n\
  monitoring.healthcheck: { endpoint: '/health', interval: '30s' }\n\
  monitoring.metrics: { enabled: bool, telegraf: bool }\n\
\n\
## hooks — Lifecycle scripts\n\
  hooks.pre_build: (path) Before docker build\n\
  hooks.post_deploy: (path) After successful deploy\n\
  hooks.on_failure: (path) On deploy failure\n\
\n\
## Environment variable interpolation\n\
  Syntax: ${VAR_NAME} — resolved from process env or env_file at parse time.\n\
  Undefined vars cause a hard error (fail-fast).\n\
  Only applies to actual YAML values, not comments.\n\
\n\
## CLI commands\n\
  stacker init [--app-type T] [--with-proxy] [--with-ai] [--with-cloud]\n\
  stacker deploy [--target local|cloud|server] [--dry-run] [--force-rebuild]\n\
  stacker status [--json] [--watch]\n\
  stacker logs [--service S] [--follow] [--tail N]\n\
  stacker destroy --confirm [--volumes]\n\
  stacker config validate | show | fix | example\n\
  stacker ai ask \"question\" [--context file] [--scenario website-deploy] [--step STEP]\n\
  stacker proxy add DOMAIN --upstream URL --ssl[=auto|off]\n\
  stacker proxy detect\n\
  stacker ssh-key generate --server-id N [--save-to PATH]\n\
  stacker ssh-key show --server-id N [--json]\n\
  stacker ssh-key upload --server-id N --public-key FILE --private-key FILE\n\
  stacker service add NAME [--file stacker.yml]\n\
  stacker service list [--online]\n\
  stacker login\n\
  stacker update [--channel beta]\n\
\n\
## Available tools (in --write mode)\n\
You have direct access to these tools. Prefer reading before writing.\n\
  read_file(path)                    — read any project file\n\
  list_directory(path)               — list files in a directory\n\
  config_validate()                  — validate stacker.yml\n\
  config_show()                      — show resolved configuration\n\
  stacker_status()                   — show container status\n\
  stacker_logs(service?, tail?)      — get container logs\n\
  proxy_detect()                     — detect running proxy containers\n\
  write_file(path, content)          — write stacker.yml or .stacker/* only\n\
  add_service(service_name, custom_ports?, custom_env?) — add a service template to stacker.yml\n\
  stacker_deploy(target?, dry_run?, force_rebuild?) — deploy the stack\n\
  proxy_add(domain, upstream?, ssl?) — add a proxy entry\n\
\n\
IMPORTANT tool rules:\n\
  - Never use stacker_deploy without first calling stacker_deploy(dry_run=true)\n\
    to preview the plan and confirm with the user.\n\
  - Never delete files or call destroy.\n\
  - write_file is sandboxed: only stacker.yml and .stacker/* are permitted.\n\
  - When the user asks to 'add wordpress' or 'add redis' etc., use the add_service tool \
    rather than manually writing YAML — it handles defaults, dependencies, and backup.\n\
\n\
When answering, always provide concrete stacker.yml YAML snippets. \
Keep answers concise and actionable.";

/// Load AI config from stacker.yml.
fn load_ai_config(config_path: &str) -> Result<AiConfig, CliError> {
    let path = Path::new(config_path);
    if !path.exists() {
        return Err(CliError::ConfigNotFound {
            path: PathBuf::from(config_path),
        });
    }
    let config = StackerConfig::from_file(path)?;
    if !config.ai.enabled {
        return Err(CliError::AiNotConfigured);
    }
    Ok(config.ai)
}

fn parse_ai_provider(s: &str) -> Result<AiProviderType, CliError> {
    let json = format!("\"{}\"", s.trim().to_lowercase());
    serde_json::from_str::<AiProviderType>(&json).map_err(|_| {
        CliError::ConfigValidation(
            "Unknown AI provider. Use: openai, anthropic, ollama, custom".to_string(),
        )
    })
}

fn prompt_line(prompt: &str) -> Result<String, CliError> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn prompt_with_default(prompt: &str, default: &str) -> Result<String, CliError> {
    let line = prompt_line(&format!("{} [{}]: ", prompt, default))?;
    if line.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(line)
    }
}

fn read_input_line<R: BufRead>(reader: &mut R) -> Result<Option<String>, CliError> {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line)?;
    if bytes == 0 {
        return Ok(None);
    }

    Ok(Some(line.trim_end_matches(['\n', '\r']).to_string()))
}

#[derive(Debug, PartialEq, Eq)]
enum ChatReplCommand {
    Exit,
    Help,
    Clear,
    Paste,
    Message(String),
    Empty,
}

fn parse_chat_repl_command(line: String) -> ChatReplCommand {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return ChatReplCommand::Empty;
    }

    match trimmed.to_ascii_lowercase().as_str() {
        "exit" | "quit" | ":q" => ChatReplCommand::Exit,
        "help" | ":help" | "?" => ChatReplCommand::Help,
        "clear" | ":clear" => ChatReplCommand::Clear,
        "paste" | ":paste" | "/paste" => ChatReplCommand::Paste,
        _ => ChatReplCommand::Message(line),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum MultilineInputResult {
    Submit(String),
    Cancelled,
    Eof,
    LimitExceeded { max_lines: usize },
}

fn collect_multiline_input<R: BufRead, W: Write>(
    reader: &mut R,
    prompt_writer: &mut W,
) -> Result<MultilineInputResult, CliError> {
    let mut lines = Vec::new();

    loop {
        write!(prompt_writer, "\x1b[1;36m…\x1b[0m ")?;
        prompt_writer.flush()?;

        let Some(line) = read_input_line(reader)? else {
            return Ok(MultilineInputResult::Eof);
        };

        let trimmed = line.trim();
        match trimmed.to_ascii_lowercase().as_str() {
            CHAT_MULTILINE_SEND_MARKER => {
                if lines.is_empty() {
                    return Ok(MultilineInputResult::Cancelled);
                }

                return Ok(MultilineInputResult::Submit(lines.join("\n")));
            }
            CHAT_MULTILINE_CANCEL_MARKER => return Ok(MultilineInputResult::Cancelled),
            _ => {}
        }

        if lines.len() == CHAT_MULTILINE_MAX_LINES {
            return Ok(MultilineInputResult::LimitExceeded {
                max_lines: CHAT_MULTILINE_MAX_LINES,
            });
        }

        lines.push(line);
    }
}

fn configure_ai_interactive(config_path: &str) -> Result<AiConfig, CliError> {
    let path = Path::new(config_path);
    if !path.exists() {
        return Err(CliError::ConfigNotFound {
            path: PathBuf::from(config_path),
        });
    }

    let mut config = StackerConfig::from_file_raw(path)?;
    let current = config.ai.clone();

    eprintln!("AI interactive setup for {}", config_path);

    let provider_default = current.provider.to_string();
    let provider_input = prompt_with_default(
        "AI provider (openai|anthropic|ollama|custom)",
        &provider_default,
    )?;
    let provider = parse_ai_provider(&provider_input)?;

    let model_default = current.model.as_deref().unwrap_or("");
    let model_input = prompt_with_default("Model (empty = provider default)", model_default)?;
    let model = if model_input.trim().is_empty() {
        None
    } else {
        Some(model_input)
    };

    let api_key_default = current.api_key.as_deref().unwrap_or("");
    let api_key_input = prompt_with_default("API key (empty = keep/none)", api_key_default)?;
    let api_key = if api_key_input.trim().is_empty() {
        current.api_key.clone()
    } else {
        Some(api_key_input)
    };

    let endpoint_default = current
        .endpoint
        .as_deref()
        .unwrap_or("http://localhost:11434");
    let endpoint_input = prompt_with_default("Endpoint", endpoint_default)?;
    let endpoint = if endpoint_input.trim().is_empty() {
        None
    } else {
        Some(endpoint_input)
    };

    let timeout_default = current.timeout.to_string();
    let timeout_input = prompt_with_default("Timeout seconds", &timeout_default)?;
    let timeout = timeout_input.parse::<u64>().unwrap_or(current.timeout);

    let tasks = if current.tasks.is_empty() {
        vec!["dockerfile".to_string(), "compose".to_string()]
    } else {
        current.tasks.clone()
    };

    config.ai = AiConfig {
        enabled: true,
        provider,
        model,
        api_key,
        endpoint,
        timeout,
        tasks,
    };

    let backup_path = format!("{}.bak", config_path);
    std::fs::copy(config_path, &backup_path)?;
    let yaml = serde_yaml::to_string(&config)
        .map_err(|e| CliError::ConfigValidation(format!("Failed to serialize config: {}", e)))?;
    std::fs::write(config_path, yaml)?;

    eprintln!("✓ AI configuration saved to {}", config_path);
    eprintln!("  Backup written to {}", backup_path);
    Ok(config.ai)
}

/// Build a prompt from the question and optional context file content.
pub fn build_ai_prompt(question: &str, context_content: Option<&str>) -> String {
    match context_content {
        Some(ctx) => format!(
            "Given the following context:\n\n```\n{}\n```\n\nQuestion: {}",
            ctx, question
        ),
        None => question.to_string(),
    }
}

pub fn build_system_prompt_base(
    project_dir: &Path,
    ai_config: &AiConfig,
    scenario: Option<&ScenarioSelection>,
    include_catalog: bool,
) -> Result<String, CliError> {
    let mut sections = vec![STACKER_SCHEMA_SYSTEM_PROMPT.to_string()];
    if include_catalog {
        sections.push(catalog_summary_for_ai());
    }

    if let Some(selection) = scenario {
        sections
            .push(load_scenario_prompt_context(project_dir, ai_config, selection)?.rendered_prompt);
    }

    Ok(sections.join("\n\n"))
}

fn build_default_project_context(project_dir: &Path) -> Option<String> {
    let mut blocks: Vec<String> = Vec::new();

    let stacker_path = project_dir.join("stacker.yml");
    if let Ok(content) = std::fs::read_to_string(&stacker_path) {
        blocks.push(format!("stacker.yml:\n{}", content));
    }

    let package_json_path = project_dir.join("package.json");
    if let Ok(content) = std::fs::read_to_string(&package_json_path) {
        blocks.push(format!("package.json:\n{}", content));
    }

    let dockerfile_path = project_dir.join("Dockerfile");
    if let Ok(content) = std::fs::read_to_string(&dockerfile_path) {
        blocks.push(format!("Dockerfile:\n{}", content));
    }

    let generated_dockerfile_path = project_dir.join(".stacker").join("Dockerfile");
    if let Ok(content) = std::fs::read_to_string(&generated_dockerfile_path) {
        blocks.push(format!(".stacker/Dockerfile:\n{}", content));
    }

    let compose_path = project_dir.join("docker-compose.yml");
    if let Ok(content) = std::fs::read_to_string(&compose_path) {
        blocks.push(format!("docker-compose.yml:\n{}", content));
    }

    let generated_compose_path = project_dir.join(".stacker").join("docker-compose.yml");
    if let Ok(content) = std::fs::read_to_string(&generated_compose_path) {
        blocks.push(format!(".stacker/docker-compose.yml:\n{}", content));
    }

    if blocks.is_empty() {
        None
    } else {
        Some(blocks.join("\n\n"))
    }
}

/// Core AI ask logic, extracted for testability.
pub fn run_ai_ask(
    question: &str,
    context: Option<&str>,
    provider: &dyn AiProvider,
) -> Result<String, CliError> {
    run_ai_ask_with_system_prompt(question, context, provider, STACKER_SCHEMA_SYSTEM_PROMPT)
}

pub fn run_ai_ask_with_system_prompt(
    question: &str,
    context: Option<&str>,
    provider: &dyn AiProvider,
    system_prompt: &str,
) -> Result<String, CliError> {
    let context_content = match context {
        Some(path) => {
            let p = Path::new(path);
            if !p.exists() {
                return Err(CliError::ConfigNotFound {
                    path: PathBuf::from(path),
                });
            }
            Some(std::fs::read_to_string(p)?)
        }
        None => {
            let cwd = std::env::current_dir()?;
            build_default_project_context(&cwd)
        }
    };

    let prompt = build_ai_prompt(question, context_content.as_deref());
    provider.complete(&prompt, system_prompt)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Agentic write loop
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Try to extract tool calls embedded as JSON text.
///
/// Many Ollama models (qwen2.5-coder, deepseek-r1, etc.) do not return a
/// structured `tool_calls` field — they write the call as JSON in the content
/// text.  This function detects the common patterns and converts them to
/// `Vec<ToolCall>` so the agentic loop can execute them.
///
/// Supported patterns (with or without surrounding markdown code fences):
///   {"name": "tool_name", "arguments": {...}}
///   [{"name": ..., "arguments": ...}, ...]
///   {"tool": "tool_name", "parameters": {...}}
///   {"function": {"name": ..., "arguments": ...}}
fn try_extract_tool_calls_from_text(text: &str) -> Vec<ToolCall> {
    // Strip markdown code fences and collect candidate JSON substrings
    let stripped = text
        .replace("```json", "")
        .replace("```", "")
        .trim()
        .to_string();

    // Try full string first, then scan for the first '{' / '['
    let candidates: Vec<&str> = {
        let mut v = vec![stripped.as_str()];
        if let Some(idx) = stripped.find('{') {
            v.push(&stripped[idx..]);
        }
        if let Some(idx) = stripped.find('[') {
            v.push(&stripped[idx..]);
        }
        v
    };

    for candidate in candidates {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(candidate.trim()) {
            let calls = parse_tool_calls_from_json(&json);
            if !calls.is_empty() {
                return calls;
            }
        }
    }
    vec![]
}

/// Recursively normalise different JSON shapes into ToolCall list.
fn parse_tool_calls_from_json(json: &serde_json::Value) -> Vec<ToolCall> {
    // Array of calls
    if let Some(arr) = json.as_array() {
        let calls: Vec<ToolCall> = arr
            .iter()
            .flat_map(|v| parse_tool_calls_from_json(v))
            .collect();
        if !calls.is_empty() {
            return calls;
        }
    }

    // {"name": ..., "arguments": {...}}
    if let (Some(name), Some(args)) = (json["name"].as_str(), json.get("arguments")) {
        let arguments = if args.is_object() {
            args.clone()
        } else if let Some(s) = args.as_str() {
            serde_json::from_str(s).unwrap_or(serde_json::json!({}))
        } else {
            serde_json::json!({})
        };
        return vec![ToolCall {
            id: None,
            name: name.to_string(),
            arguments,
        }];
    }

    // {"tool": ..., "parameters": {...}}
    if let (Some(name), Some(args)) = (json["tool"].as_str(), json.get("parameters")) {
        return vec![ToolCall {
            id: None,
            name: name.to_string(),
            arguments: if args.is_object() {
                args.clone()
            } else {
                serde_json::json!({})
            },
        }];
    }

    // {"function": {"name": ..., "arguments": ...}}
    if let Some(func) = json.get("function") {
        return parse_tool_calls_from_json(func);
    }

    vec![]
}

/// Maximum number of tool-call iterations to prevent runaway loops.
const MAX_TOOL_ITERATIONS: usize = 10;

/// Guard: returns true only for paths the AI is allowed to write.
/// Permitted: `stacker.yml` (project root) and anything under `.stacker/`.
fn is_write_allowed(path_str: &str) -> bool {
    // Normalise away leading "./" or "/" so the AI cannot escape with "../"
    let p = path_str
        .trim_start_matches("./")
        .trim_start_matches('/')
        .trim_start_matches('\\');
    // Reject any path that tries to escape with "../"
    if p.contains("../") || p.contains("..\\") || p == ".." {
        return false;
    }
    p == "stacker.yml" || p.starts_with(".stacker/") || p.starts_with(".stacker\\")
}

/// Run a stacker-cli subprocess, capture combined stdout+stderr, return the output.
/// Uses the same binary that is currently executing so the path resolves correctly.
fn run_subprocess(args: &[&str]) -> String {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return format!("Error: could not resolve binary path: {}", e),
    };

    match std::process::Command::new(&exe).args(args).output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let combined = format!("{}{}", stdout, stderr).trim().to_string();
            if out.status.success() {
                if combined.is_empty() {
                    "OK (no output)".to_string()
                } else {
                    combined
                }
            } else {
                format!("Exit {}: {}", out.status.code().unwrap_or(-1), combined)
            }
        }
        Err(e) => format!("Error running subprocess: {}", e),
    }
}

/// Execute a single tool call, return the result string to feed back to the AI.
/// Writes are sandboxed: only `stacker.yml` and `.stacker/*` are allowed.
fn execute_tool(call: &ToolCall, cwd: &Path) -> String {
    match call.name.as_str() {
        // ── file primitives ────────────────────────────────────────────────
        "write_file" => {
            let path_str = match call.arguments["path"].as_str() {
                Some(p) => p,
                None => return "Error: missing 'path' argument".to_string(),
            };
            // Enforce sandbox
            if !is_write_allowed(path_str) {
                return format!(
                    "Error: write denied — AI may only write to `stacker.yml` \
                     or files inside `.stacker/`. Requested path: {}",
                    path_str
                );
            }
            let content = match call.arguments["content"].as_str() {
                Some(c) => c,
                None => return "Error: missing 'content' argument".to_string(),
            };
            let full_path = cwd.join(path_str);
            // Create parent directories if needed
            if let Some(parent) = full_path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    return format!("Error creating directories: {}", e);
                }
            }
            match std::fs::write(&full_path, content) {
                Ok(()) => {
                    eprintln!("  ✓ wrote {}", path_str);
                    format!("Successfully wrote {} bytes to {}", content.len(), path_str)
                }
                Err(e) => format!("Error writing {}: {}", path_str, e),
            }
        }
        "read_file" => {
            let path_str = match call.arguments["path"].as_str() {
                Some(p) => p,
                None => return "Error: missing 'path' argument".to_string(),
            };
            let full_path = cwd.join(path_str);
            match std::fs::read_to_string(&full_path) {
                Ok(content) => content,
                Err(e) => format!("Error reading {}: {}", path_str, e),
            }
        }
        "list_directory" => {
            let path_str = call.arguments["path"].as_str().unwrap_or(".");
            // Prevent escaping the project directory
            let p = path_str.trim_start_matches("./").trim_start_matches('/');
            if p.contains("../") || p == ".." {
                return "Error: path traversal denied".to_string();
            }
            let dir = cwd.join(p);
            match std::fs::read_dir(&dir) {
                Ok(entries) => {
                    let mut lines: Vec<String> = entries
                        .filter_map(|e| e.ok())
                        .map(|e| {
                            let name = e.file_name().to_string_lossy().to_string();
                            let suffix = if e.path().is_dir() { "/" } else { "" };
                            format!("{}{}", name, suffix)
                        })
                        .collect();
                    lines.sort();
                    if lines.is_empty() {
                        format!("(empty directory: {})", path_str)
                    } else {
                        lines.join("\n")
                    }
                }
                Err(e) => format!("Error listing {}: {}", path_str, e),
            }
        }

        // ── read-only CLI tools ────────────────────────────────────────────
        "config_validate" => {
            eprintln!("  ⚙ running: stacker config validate");
            run_subprocess(&["config", "validate"])
        }
        "config_show" => {
            eprintln!("  ⚙ running: stacker config show");
            run_subprocess(&["config", "show"])
        }
        "stacker_status" => {
            eprintln!("  ⚙ running: stacker status");
            run_subprocess(&["status"])
        }
        "stacker_logs" => {
            let mut args: Vec<String> = vec!["logs".to_string()];
            if let Some(svc) = call.arguments["service"].as_str() {
                args.push("--service".to_string());
                args.push(svc.to_string());
            }
            let tail = call.arguments["tail"].as_u64().unwrap_or(50);
            args.push("--tail".to_string());
            args.push(tail.to_string());
            let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            eprintln!("  ⚙ running: stacker {}", args.join(" "));
            run_subprocess(&arg_refs)
        }
        "proxy_detect" => {
            eprintln!("  ⚙ running: stacker proxy detect");
            run_subprocess(&["proxy", "detect"])
        }

        // ── agent CLI tools ────────────────────────────────────────────────
        "agent_health" => {
            let mut args: Vec<String> = vec![
                "agent".to_string(),
                "health".to_string(),
                "--json".to_string(),
            ];
            if let Some(app) = call.arguments["app"].as_str() {
                args.push("--app".to_string());
                args.push(app.to_string());
            }
            if let Some(dep) = call.arguments["deployment"].as_str() {
                args.push("--deployment".to_string());
                args.push(dep.to_string());
            }
            eprintln!("  ⚙ running: stacker agent health");
            run_subprocess(&args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        }
        "agent_status" => {
            let mut args: Vec<String> = vec![
                "agent".to_string(),
                "status".to_string(),
                "--json".to_string(),
            ];
            if let Some(dep) = call.arguments["deployment"].as_str() {
                args.push("--deployment".to_string());
                args.push(dep.to_string());
            }
            eprintln!("  ⚙ running: stacker agent status");
            run_subprocess(&args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        }
        "agent_logs" => {
            let app = match call.arguments["app"].as_str() {
                Some(a) => a,
                None => return "Error: missing 'app' argument".to_string(),
            };
            let mut args: Vec<String> = vec![
                "agent".to_string(),
                "logs".to_string(),
                app.to_string(),
                "--json".to_string(),
            ];
            if let Some(limit) = call.arguments["limit"].as_u64() {
                args.push("--limit".to_string());
                args.push(limit.to_string());
            }
            if let Some(dep) = call.arguments["deployment"].as_str() {
                args.push("--deployment".to_string());
                args.push(dep.to_string());
            }
            eprintln!("  ⚙ running: stacker agent logs {}", app);
            run_subprocess(&args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        }

        // ── action CLI tools ───────────────────────────────────────────────
        "stacker_deploy" => {
            let dry_run = call.arguments["dry_run"].as_bool().unwrap_or(true);
            let mut args: Vec<String> = vec!["deploy".to_string()];
            if let Some(target) = call.arguments["target"].as_str() {
                args.push("--target".to_string());
                args.push(target.to_string());
            }
            if dry_run {
                args.push("--dry-run".to_string());
            }
            if call.arguments["force_rebuild"].as_bool().unwrap_or(false) {
                args.push("--force-rebuild".to_string());
            }
            let label = if dry_run {
                "stacker deploy --dry-run"
            } else {
                "stacker deploy"
            };
            eprintln!("  ⚙ running: {}", label);
            run_subprocess(&args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        }
        "proxy_add" => {
            let domain = match call.arguments["domain"].as_str() {
                Some(d) => d,
                None => return "Error: missing 'domain' argument".to_string(),
            };
            let mut args: Vec<String> =
                vec!["proxy".to_string(), "add".to_string(), domain.to_string()];
            if let Some(upstream) = call.arguments["upstream"].as_str() {
                args.push("--upstream".to_string());
                args.push(upstream.to_string());
            }
            if let Some(ssl) = call.arguments["ssl"].as_str() {
                args.push("--ssl".to_string());
                args.push(ssl.to_string());
            }
            eprintln!("  ⚙ running: stacker proxy add {}", domain);
            run_subprocess(&args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        }

        // ── add_service — add a service template to stacker.yml ────────────
        "add_service" => {
            let service_name = match call.arguments["service_name"].as_str() {
                Some(n) => n,
                None => return "Error: missing 'service_name' argument".to_string(),
            };
            eprintln!("  ⚙ adding service: {}", service_name);

            // Resolve the template from offline catalog
            let catalog = ServiceCatalog::offline();
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => return format!("Error creating runtime: {}", e),
            };
            let entry = match rt.block_on(catalog.resolve(service_name)) {
                Ok(entry) => entry,
                Err(e) => return format!("Error: {}", e),
            };

            // Apply custom overrides from AI arguments
            let mut svc = entry.service.clone();
            if let Some(ports) = call.arguments["custom_ports"].as_array() {
                let custom: Vec<String> = ports
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                if !custom.is_empty() {
                    svc.ports = custom;
                }
            }
            if let Some(env_obj) = call.arguments["custom_env"].as_object() {
                for (k, v) in env_obj {
                    if let Some(val) = v.as_str() {
                        svc.environment.insert(k.clone(), val.to_string());
                    }
                }
            }

            // Load stacker.yml, check for duplicates, append, save
            let config_path = cwd.join("stacker.yml");
            if !config_path.exists() {
                return format!(
                    "Error: stacker.yml not found at {}. Run `stacker init` first.",
                    config_path.display()
                );
            }

            match StackerConfig::from_file_raw(&config_path) {
                Ok(mut config) => {
                    // Duplicate check
                    if config.services.iter().any(|s| s.name == svc.name) {
                        return format!(
                            "Service '{}' already exists in stacker.yml. \
                             Remove it first or choose a different name.",
                            svc.name
                        );
                    }

                    // Auto-add dependencies
                    let mut deps_added: Vec<String> = Vec::new();
                    for dep in &entry.related {
                        if !config.services.iter().any(|s| s.name == *dep) {
                            if let Ok(dep_entry) = rt.block_on(catalog.resolve(dep)) {
                                config.services.push(dep_entry.service);
                                deps_added.push(dep.clone());
                            }
                        }
                    }

                    config.services.push(svc.clone());

                    // Backup then write
                    let backup = config_path.with_extension("yml.bak");
                    let _ = std::fs::copy(&config_path, &backup);

                    match serde_yaml::to_string(&config) {
                        Ok(yaml) => match std::fs::write(&config_path, &yaml) {
                            Ok(()) => {
                                let mut msg = format!(
                                    "✓ Added service '{}' ({}) to stacker.yml",
                                    svc.name, entry.name
                                );
                                if !deps_added.is_empty() {
                                    msg.push_str(&format!(
                                        "\n  Also added dependencies: {}",
                                        deps_added.join(", ")
                                    ));
                                }
                                eprintln!("  {}", msg);
                                msg
                            }
                            Err(e) => format!("Error writing stacker.yml: {}", e),
                        },
                        Err(e) => format!("Error serializing config: {}", e),
                    }
                }
                Err(e) => format!("Error parsing stacker.yml: {}", e),
            }
        }

        unknown => format!("Unknown tool: {}", unknown),
    }
}

/// Drive one tool-loop turn over an **existing** message history.
///
/// Appends the user input, executes any tool calls the AI requests, and
/// returns the AI's final plain-text reply.  The `messages` vec is mutated
/// in-place so the caller can keep multi-turn context.
fn run_chat_turn(
    messages: &mut Vec<ChatMessage>,
    user_input: &str,
    provider: &dyn AiProvider,
    with_tools: bool,
) -> Result<String, CliError> {
    messages.push(ChatMessage::user(user_input));
    let cwd = std::env::current_dir()?;

    if !with_tools || !provider.supports_tools() {
        // Plain completion — feed the whole history as a single concatenated
        // prompt so the provider's simple `complete()` path gets the context.
        let history_text: String = messages
            .iter()
            .filter(|m| m.role != "system")
            .map(|m| format!("{}: {}", m.role, m.content))
            .collect::<Vec<_>>()
            .join("\n");
        let system = messages
            .first()
            .filter(|m| m.role == "system")
            .map(|m| m.content.as_str())
            .unwrap_or("");
        let reply = provider.complete(&history_text, system)?;
        messages.push(ChatMessage {
            role: "assistant".to_string(),
            content: reply.clone(),
            tool_calls: None,
            tool_call_id: None,
        });
        return Ok(reply);
    }

    let tools: Vec<ToolDef> = all_write_mode_tools();

    for iteration in 0..MAX_TOOL_ITERATIONS {
        let response = provider.complete_with_tools(messages, &tools)?;

        match response {
            AiResponse::Text(text) => {
                // Fallback: some models embed tool calls as JSON text instead
                // of the structured tool_calls API field (common with Ollama).
                let embedded = try_extract_tool_calls_from_text(&text);
                if !embedded.is_empty() {
                    // Treat exactly like a proper ToolCalls response
                    messages.push(ChatMessage {
                        role: "assistant".to_string(),
                        content: String::new(),
                        tool_calls: Some(embedded.clone()),
                        tool_call_id: None,
                    });
                    for call in &embedded {
                        let result = execute_tool(call, &cwd);
                        messages.push(ChatMessage::tool_result(call.id.clone(), result));
                    }
                    if iteration + 1 == MAX_TOOL_ITERATIONS {
                        return Err(CliError::AiProviderError {
                            provider: provider.name().to_string(),
                            message: format!(
                                "Reached maximum tool iterations ({})",
                                MAX_TOOL_ITERATIONS
                            ),
                        });
                    }
                    continue;
                }
                messages.push(ChatMessage {
                    role: "assistant".to_string(),
                    content: text.clone(),
                    tool_calls: None,
                    tool_call_id: None,
                });
                return Ok(text);
            }
            AiResponse::ToolCalls(narration, calls) => {
                if !narration.is_empty() {
                    eprintln!("{}", narration);
                }
                messages.push(ChatMessage {
                    role: "assistant".to_string(),
                    content: narration,
                    tool_calls: Some(calls.clone()),
                    tool_call_id: None,
                });
                for call in &calls {
                    let result = execute_tool(call, &cwd);
                    messages.push(ChatMessage::tool_result(call.id.clone(), result));
                }
                if iteration + 1 == MAX_TOOL_ITERATIONS {
                    return Err(CliError::AiProviderError {
                        provider: provider.name().to_string(),
                        message: format!(
                            "Reached maximum tool iterations ({})",
                            MAX_TOOL_ITERATIONS
                        ),
                    });
                }
            }
        }
    }
    Ok(String::new())
}

/// Agentic loop: send question to AI with write_file / read_file tools, execute
/// any tool calls, feed results back, repeat until the AI returns plain text
/// or the iteration limit is reached.
pub fn run_ai_ask_agentic(
    question: &str,
    context: Option<&str>,
    provider: &dyn AiProvider,
    system_prompt: &str,
) -> Result<String, CliError> {
    if !provider.supports_tools() {
        return Err(CliError::AiProviderError {
            provider: provider.name().to_string(),
            message: "--write requires a provider that supports tool calling. \
                      Configure ollama (llama3.1/qwen2.5-coder) or openai."
                .to_string(),
        });
    }

    let context_content = match context {
        Some(path) => {
            let p = Path::new(path);
            if !p.exists() {
                return Err(CliError::ConfigNotFound {
                    path: PathBuf::from(path),
                });
            }
            Some(std::fs::read_to_string(p)?)
        }
        None => {
            let cwd = std::env::current_dir()?;
            build_default_project_context(&cwd)
        }
    };

    let user_message = build_ai_prompt(question, context_content.as_deref());
    let cwd = std::env::current_dir()?;
    let tools: Vec<ToolDef> = all_write_mode_tools();

    let mut messages: Vec<ChatMessage> = vec![
        ChatMessage::system(system_prompt),
        ChatMessage::user(user_message),
    ];

    for iteration in 0..MAX_TOOL_ITERATIONS {
        let response = provider.complete_with_tools(&messages, &tools)?;

        match response {
            AiResponse::Text(text) => {
                // Fallback for models that emit tool calls as JSON text
                let embedded = try_extract_tool_calls_from_text(&text);
                if !embedded.is_empty() {
                    if !text.trim().is_empty() {
                        // strip the JSON before showing narration to user
                        let narration = text
                            .lines()
                            .filter(|l| {
                                !l.trim().starts_with('{')
                                    && !l.trim().starts_with('[')
                                    && !l.trim().starts_with('`')
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        if !narration.trim().is_empty() {
                            eprintln!("{}", narration.trim());
                        }
                    }
                    messages.push(ChatMessage {
                        role: "assistant".to_string(),
                        content: String::new(),
                        tool_calls: Some(embedded.clone()),
                        tool_call_id: None,
                    });
                    for call in &embedded {
                        let result = execute_tool(call, &cwd);
                        messages.push(ChatMessage::tool_result(call.id.clone(), result));
                    }
                    if iteration + 1 == MAX_TOOL_ITERATIONS {
                        return Err(CliError::AiProviderError {
                            provider: provider.name().to_string(),
                            message: format!(
                                "Reached maximum tool iterations ({})",
                                MAX_TOOL_ITERATIONS
                            ),
                        });
                    }
                    continue;
                }
                return Ok(text);
            }
            AiResponse::ToolCalls(narration, calls) => {
                if !narration.is_empty() {
                    eprintln!("{}", narration);
                }
                // Record the assistant turn (with its tool calls)
                messages.push(ChatMessage {
                    role: "assistant".to_string(),
                    content: narration,
                    tool_calls: Some(calls.clone()),
                    tool_call_id: None,
                });

                // Execute each tool and append results
                for call in &calls {
                    let result = execute_tool(call, &cwd);
                    messages.push(ChatMessage::tool_result(call.id.clone(), result));
                }

                if iteration + 1 == MAX_TOOL_ITERATIONS {
                    return Err(CliError::AiProviderError {
                        provider: provider.name().to_string(),
                        message: format!(
                            "Reached maximum tool iterations ({})",
                            MAX_TOOL_ITERATIONS
                        ),
                    });
                }
            }
        }
    }

    Ok(String::new())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AiAskCommand
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker ai ask "<question>" [--context <file>] [--write]`
///
/// Sends a question to the configured AI provider for assistance
/// with Dockerfile, docker-compose, or deployment troubleshooting.
///
/// With `--write` the command activates an agentic loop: the AI may call
/// `write_file` / `read_file` tools to directly create or modify project files.
/// Requires a tool-capable model (Ollama: llama3.1, qwen2.5-coder; OpenAI: any).
pub struct AiAskCommand {
    pub question: String,
    pub context: Option<String>,
    pub configure: bool,
    pub write: bool,
    pub scenario: Option<String>,
    pub step: Option<String>,
}

impl AiAskCommand {
    pub fn new(question: String, context: Option<String>) -> Self {
        Self {
            question,
            context,
            configure: false,
            write: false,
            scenario: None,
            step: None,
        }
    }

    pub fn with_configure(mut self, configure: bool) -> Self {
        self.configure = configure;
        self
    }

    pub fn with_write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    pub fn with_scenario(mut self, scenario: Option<String>, step: Option<String>) -> Self {
        self.scenario = scenario;
        self.step = step;
        self
    }
}

impl CallableTrait for AiAskCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ai_config = if self.configure {
            configure_ai_interactive(DEFAULT_CONFIG_FILE)?
        } else {
            load_ai_config(DEFAULT_CONFIG_FILE)?
        };
        let provider = create_provider(&ai_config)?;
        let cwd = std::env::current_dir()?;
        let scenario_selection = self
            .scenario
            .as_ref()
            .map(|name| ScenarioSelection::new(name.clone(), self.step.clone()));

        if self.write {
            let enriched_prompt =
                build_system_prompt_base(&cwd, &ai_config, scenario_selection.as_ref(), true)?;
            let response = run_ai_ask_agentic(
                &self.question,
                self.context.as_deref(),
                provider.as_ref(),
                &enriched_prompt,
            )?;
            if !response.is_empty() {
                println!("{}", response);
            }
        } else {
            let system_prompt = build_system_prompt_base(
                &cwd,
                &ai_config,
                scenario_selection.as_ref(),
                scenario_selection.is_some(),
            )?;
            let response = run_ai_ask_with_system_prompt(
                &self.question,
                self.context.as_deref(),
                provider.as_ref(),
                &system_prompt,
            )?;
            println!("{}", response);
        }
        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AiChatCommand — interactive REPL
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Help text shown inside the REPL.
const CHAT_HELP: &str = "\
Commands available in the AI chat session:
  help          Show this message
  clear         Reset conversation history (keeps system context)
  paste         Enter multiline paste mode
  exit / quit   End the session
  Ctrl-D        End the session

Tips:
  - Ask anything about your stacker.yml, Dockerfile, or deployment.
  - With --write the AI can create/edit files in .stacker/ and stacker.yml.
  - Run `paste`, then finish with `::send` to submit a multiline prompt.
  - Use `::cancel` to discard multiline input.
  - Multiline input is limited to 512 lines per message.
  - Conversation history is kept across turns — the AI remembers context.";

/// `stacker ai [--write]`
///
/// Starts an interactive chat session with the configured AI provider.
/// History is preserved across turns for multi-step conversations.
/// With `--write` the AI may call `write_file` / `read_file` tools,
/// but only for `stacker.yml` and files inside `.stacker/`.
pub struct AiChatCommand {
    pub write: bool,
    pub scenario: Option<String>,
    pub step: Option<String>,
}

impl AiChatCommand {
    pub fn new(write: bool, scenario: Option<String>, step: Option<String>) -> Self {
        Self {
            write,
            scenario,
            step,
        }
    }
}

impl CallableTrait for AiChatCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ai_config = load_ai_config(DEFAULT_CONFIG_FILE)?;
        let provider = create_provider(&ai_config)?;
        let model_name = ai_config.model.as_deref().unwrap_or("default");
        let provider_name = provider.name();
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        let mut stdout = io::stdout();

        let write_active = self.write && provider.supports_tools();

        // Banner
        eprintln!(
            "Stacker AI  ({provider} · {model}){tools}",
            provider = provider_name,
            model = model_name,
            tools = if write_active {
                "  [write mode — .stacker/ + stacker.yml]"
            } else {
                ""
            }
        );
        eprintln!("Type your question and press Enter. Use `paste` for multiline input.");
        eprintln!("`help` for tips, `exit` to quit.");
        eprintln!();

        // Seed project context into the initial system message
        let cwd = std::env::current_dir()?;
        let project_ctx = build_default_project_context(&cwd);
        let scenario_selection = self
            .scenario
            .as_ref()
            .map(|name| ScenarioSelection::new(name.clone(), self.step.clone()));
        let base_system =
            build_system_prompt_base(&cwd, &ai_config, scenario_selection.as_ref(), true)?;
        let system = match project_ctx {
            Some(ctx) => format!("{}\n\n## Current project files\n{}", base_system, ctx),
            None => base_system,
        };

        let mut messages: Vec<ChatMessage> = vec![ChatMessage::system(&system)];

        loop {
            // Prompt
            write!(stdout, "\x1b[1;36m>\x1b[0m ")?;
            stdout.flush()?;

            // Read a line (Ctrl-D → EOF → break)
            let Some(line) = read_input_line(&mut reader)? else {
                eprintln!("\nBye!");
                break;
            };

            let user_input = match parse_chat_repl_command(line) {
                ChatReplCommand::Exit => {
                    eprintln!("Bye!");
                    break;
                }
                ChatReplCommand::Help => {
                    eprintln!("{}", CHAT_HELP);
                    continue;
                }
                ChatReplCommand::Clear => {
                    messages.truncate(1); // keep system message
                    eprintln!("  ↺ conversation cleared");
                    continue;
                }
                ChatReplCommand::Paste => {
                    eprintln!(
                        "Paste mode — finish with `{}`, cancel with `{}`, max {} lines.",
                        CHAT_MULTILINE_SEND_MARKER,
                        CHAT_MULTILINE_CANCEL_MARKER,
                        CHAT_MULTILINE_MAX_LINES
                    );

                    match collect_multiline_input(&mut reader, &mut stdout)? {
                        MultilineInputResult::Submit(message) => message,
                        MultilineInputResult::Cancelled => {
                            eprintln!("  ↺ paste cancelled");
                            continue;
                        }
                        MultilineInputResult::Eof => {
                            eprintln!("\nBye!");
                            break;
                        }
                        MultilineInputResult::LimitExceeded { max_lines } => {
                            eprintln!(
                                "  ✗ paste too large: maximum {} lines per message",
                                max_lines
                            );
                            continue;
                        }
                    }
                }
                ChatReplCommand::Message(input) => input,
                ChatReplCommand::Empty => continue,
            };

            match run_chat_turn(&mut messages, &user_input, provider.as_ref(), write_active) {
                Ok(reply) => {
                    println!("\n{}\n", reply);
                }
                Err(e) => {
                    eprintln!("  ✗ error: {}", e);
                }
            }
        }

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::config_parser::AiProviderType;

    fn scenario_ai_config() -> AiConfig {
        AiConfig {
            enabled: true,
            provider: AiProviderType::Ollama,
            model: Some("qwen2.5-coder:latest".to_string()),
            api_key: None,
            endpoint: Some("http://localhost:11434".to_string()),
            timeout: 300,
            tasks: vec![],
        }
    }

    struct MockProvider {
        response: String,
    }

    impl MockProvider {
        fn new(response: &str) -> Self {
            Self {
                response: response.to_string(),
            }
        }
    }

    impl AiProvider for MockProvider {
        fn name(&self) -> &str {
            "mock"
        }
        fn complete(&self, _prompt: &str, _context: &str) -> Result<String, CliError> {
            Ok(self.response.clone())
        }
    }

    #[test]
    fn test_build_prompt_without_context() {
        let prompt = build_ai_prompt("How do I optimize my Dockerfile?", None);
        assert_eq!(prompt, "How do I optimize my Dockerfile?");
    }

    #[test]
    fn test_schema_system_prompt_covers_key_sections() {
        assert!(STACKER_SCHEMA_SYSTEM_PROMPT.contains("deploy.server"));
        assert!(STACKER_SCHEMA_SYSTEM_PROMPT.contains("deploy.cloud"));
        assert!(STACKER_SCHEMA_SYSTEM_PROMPT.contains("proxy"));
        assert!(STACKER_SCHEMA_SYSTEM_PROMPT.contains("services"));
        assert!(STACKER_SCHEMA_SYSTEM_PROMPT.contains("hooks"));
        assert!(STACKER_SCHEMA_SYSTEM_PROMPT.contains("${VAR_NAME}"));
    }

    #[test]
    fn test_build_prompt_with_context() {
        let prompt = build_ai_prompt("Explain this", Some("FROM node:18\nRUN npm install"));
        assert!(prompt.contains("context"));
        assert!(prompt.contains("FROM node:18"));
        assert!(prompt.contains("Explain this"));
    }

    #[test]
    fn test_run_ai_ask_returns_response() {
        let provider = MockProvider::new("Use multi-stage builds for smaller images.");
        let result = run_ai_ask("How to optimize?", None, &provider).unwrap();
        assert_eq!(result, "Use multi-stage builds for smaller images.");
    }

    #[test]
    fn test_run_ai_ask_with_context_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let ctx_path = dir.path().join("Dockerfile");
        std::fs::write(&ctx_path, "FROM rust:1.75\nCOPY . .").unwrap();

        let provider = MockProvider::new("Looks good!");
        let result =
            run_ai_ask("Review this", Some(ctx_path.to_str().unwrap()), &provider).unwrap();
        assert_eq!(result, "Looks good!");
    }

    #[test]
    fn test_run_ai_ask_missing_context_file_errors() {
        let provider = MockProvider::new("unreachable");
        let result = run_ai_ask("question", Some("/does/not/exist.txt"), &provider);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_system_prompt_base_includes_scenario_step() {
        let dir = tempfile::TempDir::new().unwrap();
        let state = crate::cli::ai_scenarios::ScenarioState::new("website-deploy", "init-validate");
        crate::cli::ai_scenarios::save_scenario_state(dir.path(), &state).unwrap();

        let prompt = build_system_prompt_base(
            dir.path(),
            &scenario_ai_config(),
            Some(&ScenarioSelection::new(
                "website-deploy",
                Some("init-validate".to_string()),
            )),
            true,
        )
        .unwrap();

        assert!(prompt.contains("Active deployment scenario"));
        assert!(prompt.contains("init-validate"));
        assert!(prompt.contains("Validate generated stacker config"));
    }

    #[test]
    fn test_parse_chat_repl_command_detects_paste_mode() {
        assert_eq!(
            parse_chat_repl_command("  :paste  ".to_string()),
            ChatReplCommand::Paste
        );
    }

    #[test]
    fn test_collect_multiline_input_submits_joined_message() {
        let mut reader = std::io::Cursor::new(b"first line\nsecond line\n::send\n");
        let mut prompt = Vec::new();

        let result = collect_multiline_input(&mut reader, &mut prompt).unwrap();
        assert_eq!(
            result,
            MultilineInputResult::Submit("first line\nsecond line".to_string())
        );
        assert!(!prompt.is_empty());
    }

    #[test]
    fn test_collect_multiline_input_can_cancel() {
        let mut reader = std::io::Cursor::new(b"first line\n::cancel\n");
        let mut prompt = Vec::new();

        let result = collect_multiline_input(&mut reader, &mut prompt).unwrap();
        assert_eq!(result, MultilineInputResult::Cancelled);
    }

    #[test]
    fn test_collect_multiline_input_rejects_more_than_512_lines() {
        let mut input = String::new();
        for idx in 0..=CHAT_MULTILINE_MAX_LINES {
            input.push_str(&format!("line-{idx}\n"));
        }
        input.push_str("::send\n");

        let mut reader = std::io::Cursor::new(input.into_bytes());
        let mut prompt = Vec::new();

        let result = collect_multiline_input(&mut reader, &mut prompt).unwrap();
        assert_eq!(
            result,
            MultilineInputResult::LimitExceeded {
                max_lines: CHAT_MULTILINE_MAX_LINES,
            }
        );
    }
}
