use std::collections::HashMap;
use std::path::Path;

use crate::cli::ai_client::AiProvider;
use crate::cli::detector::{detect_project, FileSystem, ProjectDetection, RealFileSystem};
use crate::cli::error::CliError;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ProjectScanResult — rich project context for AI prompt
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Rich project context gathered by scanning files, used to build the AI prompt
/// for stacker.yml generation.
#[derive(Debug, Clone, Default)]
pub struct ProjectScanResult {
    /// Base detection (app type, has_dockerfile, etc.)
    pub detection: ProjectDetection,

    /// All filenames found at project root
    pub root_files: Vec<String>,

    /// Partial contents of key config files (package.json, requirements.txt, etc.)
    /// Key = filename, Value = content (truncated to MAX_FILE_CONTENT_LEN)
    pub file_contents: HashMap<String, String>,

    /// Inferred project name (from directory name)
    pub project_name: String,

    /// Existing Dockerfile content, if found
    pub existing_dockerfile: Option<String>,

    /// Existing docker-compose content, if found
    pub existing_compose: Option<String>,

    /// Existing .env keys (values redacted for safety)
    pub env_keys: Vec<String>,

    /// Locally inferred pipe opportunities discovered from dependencies,
    /// env keys, and existing compose/services. These are advisory hints for
    /// init-time AI generation, not runtime-verified endpoints.
    pub pipe_hints: Vec<PipeHint>,
}

/// Advisory local integration hint derived from static project evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeHint {
    pub source: String,
    pub target: String,
    pub kind: String,
    pub confidence: PipeHintConfidence,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeHintConfidence {
    High,
    Medium,
}

impl PipeHintConfidence {
    fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
        }
    }
}

/// Max bytes to read from any single file for AI context.
const MAX_FILE_CONTENT_LEN: usize = 4096;

/// Files worth reading for richer AI context, mapped by app type.
const CONTEXT_FILES: &[&str] = &[
    "package.json",
    "requirements.txt",
    "Pipfile",
    "pyproject.toml",
    "Cargo.toml",
    "go.mod",
    "composer.json",
    "Gemfile",
    "Makefile",
    "README.md",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    ".env",
    ".env.example",
    "tsconfig.json",
    "next.config.js",
    "next.config.mjs",
    "nuxt.config.ts",
    "vite.config.ts",
    "vite.config.js",
    "webpack.config.js",
    "angular.json",
    "manage.py",
    "setup.py",
    "setup.cfg",
    "pom.xml",
    "build.gradle",
];

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// scan_project — deep project scan for AI context
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Scan a project directory gathering rich context for AI-powered config generation.
///
/// This goes beyond `detect_project()` by also reading key config files
/// so the AI can make informed decisions about services, ports, env vars, etc.
pub fn scan_project(project_dir: &Path, fs: &dyn FileSystem) -> ProjectScanResult {
    let detection = detect_project(project_dir, fs);

    let root_files = fs.list_dir(project_dir).unwrap_or_default();

    let project_name = project_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("my-app")
        .to_string();

    let mut file_contents = HashMap::new();
    let mut existing_dockerfile = None;
    let mut existing_compose = None;
    let mut env_keys = Vec::new();

    for filename in &root_files {
        // Only read files we recognise as valuable context
        if !CONTEXT_FILES.iter().any(|cf| cf == filename) {
            continue;
        }

        let file_path = project_dir.join(filename);
        let content = match std::fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Truncate large files
        let truncated = if content.len() > MAX_FILE_CONTENT_LEN {
            format!("{}... (truncated)", &content[..MAX_FILE_CONTENT_LEN])
        } else {
            content.clone()
        };

        // Capture special files
        if filename == "Dockerfile" {
            existing_dockerfile = Some(truncated.clone());
        }

        if filename == "docker-compose.yml"
            || filename == "docker-compose.yaml"
            || filename == "compose.yml"
            || filename == "compose.yaml"
        {
            existing_compose = Some(truncated.clone());
        }

        // For .env files, extract keys only (redact values for security)
        if filename == ".env" || filename == ".env.example" {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some(key) = trimmed.split('=').next() {
                    env_keys.push(key.trim().to_string());
                }
            }
            // Store only the key list, not values
            file_contents.insert(
                filename.clone(),
                format!("# Environment keys: {}", env_keys.join(", ")),
            );
            continue;
        }

        file_contents.insert(filename.clone(), truncated);
    }

    let pipe_hints = discover_local_pipe_hints(
        &project_name,
        detection.app_type.to_string(),
        &root_files,
        &file_contents,
        &env_keys,
    );

    ProjectScanResult {
        detection,
        root_files,
        file_contents,
        project_name,
        existing_dockerfile,
        existing_compose,
        env_keys,
        pipe_hints,
    }
}

fn discover_local_pipe_hints(
    project_name: &str,
    detected_app_type: String,
    root_files: &[String],
    file_contents: &HashMap<String, String>,
    env_keys: &[String],
) -> Vec<PipeHint> {
    let mut hints = Vec::new();
    let lower_env_keys: Vec<String> = env_keys.iter().map(|k| k.to_lowercase()).collect();

    let package_json = file_contents
        .get("package.json")
        .map(|c| c.to_lowercase())
        .unwrap_or_default();
    let requirements = file_contents
        .get("requirements.txt")
        .map(|c| c.to_lowercase())
        .unwrap_or_default();
    let pyproject = file_contents
        .get("pyproject.toml")
        .map(|c| c.to_lowercase())
        .unwrap_or_default();
    let compose = file_contents
        .get("docker-compose.yml")
        .or_else(|| file_contents.get("docker-compose.yaml"))
        .or_else(|| file_contents.get("compose.yml"))
        .or_else(|| file_contents.get("compose.yaml"))
        .map(|c| c.to_lowercase())
        .unwrap_or_default();

    let mut push_hint =
        |target: &str, kind: &str, confidence: PipeHintConfidence, evidence: Vec<String>| {
            if evidence.is_empty() {
                return;
            }
            hints.push(PipeHint {
                source: project_name.to_string(),
                target: target.to_string(),
                kind: kind.to_string(),
                confidence,
                evidence,
            });
        };

    let mut webhook_evidence = Vec::new();
    if package_json.contains("webhook")
        || requirements.contains("webhook")
        || pyproject.contains("webhook")
    {
        webhook_evidence.push("webhook-related dependency detected".to_string());
    }
    if lower_env_keys.iter().any(|k| k.contains("webhook")) {
        webhook_evidence.push("env keys reference webhooks".to_string());
    }
    if lower_env_keys.iter().any(|k| k.contains("slack")) {
        webhook_evidence.push("env keys reference Slack integration".to_string());
    }
    if lower_env_keys.iter().any(|k| k.contains("discord")) {
        webhook_evidence.push("env keys reference Discord integration".to_string());
    }
    if !webhook_evidence.is_empty() {
        push_hint(
            "external-webhook",
            "webhook",
            PipeHintConfidence::Medium,
            webhook_evidence,
        );
    }

    let mut postgres_evidence = Vec::new();
    if compose.contains("postgres") {
        postgres_evidence.push("compose references postgres".to_string());
    }
    if lower_env_keys
        .iter()
        .any(|k| k == "database_url" || k.contains("postgres"))
    {
        postgres_evidence.push("env keys reference postgres/database".to_string());
    }
    if !postgres_evidence.is_empty() {
        push_hint(
            "postgres",
            "database",
            PipeHintConfidence::High,
            postgres_evidence,
        );
    }

    let mut redis_evidence = Vec::new();
    if compose.contains("redis") {
        redis_evidence.push("compose references redis".to_string());
    }
    if lower_env_keys
        .iter()
        .any(|k| k == "redis_url" || k.contains("redis"))
    {
        redis_evidence.push("env keys reference redis".to_string());
    }
    if !redis_evidence.is_empty() {
        push_hint(
            "redis",
            "cache-or-queue",
            PipeHintConfidence::High,
            redis_evidence,
        );
    }

    let mut qdrant_evidence = Vec::new();
    if compose.contains("qdrant") {
        qdrant_evidence.push("compose references qdrant".to_string());
    }
    if lower_env_keys.iter().any(|k| k.contains("qdrant")) {
        qdrant_evidence.push("env keys reference qdrant".to_string());
    }
    if !qdrant_evidence.is_empty() {
        push_hint(
            "qdrant",
            "vector-store",
            PipeHintConfidence::High,
            qdrant_evidence,
        );
    }

    let mut llm_evidence = Vec::new();
    if package_json.contains("openai")
        || requirements.contains("openai")
        || pyproject.contains("openai")
    {
        llm_evidence.push("OpenAI dependency detected".to_string());
    }
    if package_json.contains("anthropic")
        || requirements.contains("anthropic")
        || pyproject.contains("anthropic")
    {
        llm_evidence.push("Anthropic dependency detected".to_string());
    }
    if compose.contains("ollama") || lower_env_keys.iter().any(|k| k.contains("ollama")) {
        llm_evidence.push("local Ollama usage detected".to_string());
    }
    if !llm_evidence.is_empty() {
        push_hint(
            "llm-provider",
            "ai-provider",
            PipeHintConfidence::Medium,
            llm_evidence,
        );
    }

    let mut frontend_api_evidence = Vec::new();
    let looks_like_frontend = detected_app_type == "node"
        && root_files.iter().any(|f| {
            f == "next.config.js"
                || f == "next.config.mjs"
                || f == "vite.config.ts"
                || f == "vite.config.js"
        });
    if looks_like_frontend {
        frontend_api_evidence.push("frontend framework config detected".to_string());
    }
    if lower_env_keys
        .iter()
        .any(|k| k.contains("api_url") || k.contains("api_base") || k.contains("backend_url"))
    {
        frontend_api_evidence.push("env keys reference backend/api URL".to_string());
    }
    if !frontend_api_evidence.is_empty() {
        push_hint(
            "backend-api",
            "http-api",
            PipeHintConfidence::Medium,
            frontend_api_evidence,
        );
    }

    hints
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AI prompt building for stacker.yml generation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// System prompt that instructs the AI how to generate stacker.yml.
const SYSTEM_PROMPT: &str = "\
You are an expert DevOps engineer integrated into the `stacker` CLI tool. \
Your job is to generate a complete, production-ready `stacker.yml` configuration \
based on the project files and context provided.

The `stacker.yml` schema supports these top-level keys:
- name: (string, required) Project name
- version: (string) Version label
- app: Application source config
  - type: static|node|python|rust|go|php|custom
  - path: Source directory (default '.')
  - dockerfile: Path to custom Dockerfile
  - image: Pre-built Docker image
  - build: { context: '.', args: { KEY: VALUE } }
- services: Array of sidecar containers
  - name, image, ports[], environment{}, volumes[], depends_on[]
- proxy: Reverse proxy config
  - type: nginx|nginx-proxy-manager|traefik|none
  - auto_detect: bool
  - domains: [{ domain, ssl: auto|manual|off, upstream }]
- deploy:
  - target: local|cloud|server
  - cloud: { provider: hetzner|digitalocean|aws|linode|vultr, orchestrator: local|remote, region, size, ssh_key }
  - server: { host (REQUIRED), user (default 'root'), port (default 22), ssh_key }
  - registry: { username, password, server } — Docker registry credentials for private images
  - compose_file: path to existing docker-compose (skips generation)
- monitoring: { status_panel: bool, healthcheck: { endpoint, interval }, metrics: { enabled, telegraf } }
- hooks: { pre_build, post_deploy, on_failure } (paths to scripts)
- env_file: Path to .env file
- env: { KEY: VALUE } inline environment variables

Rules:
1. Output ONLY valid YAML — no markdown fences, no explanations, no comments except brief inline ones.
2. Use ${VAR_NAME} syntax for secrets and sensitive values (DB passwords, API keys).
3. Include appropriate services (databases, caches, queues) based on detected dependencies.
4. Set proper port mappings avoiding conflicts.
5. Add volumes for data persistence.
6. Use depends_on for service ordering.
7. Add healthcheck and monitoring when appropriate.
8. If a Dockerfile already exists, set app.type to 'custom' and reference it via app.dockerfile.
9. If a docker-compose already exists, set deploy.compose_file to reference it.
10. Keep the configuration practical and deployable — don't add services that aren't needed.";

/// Expose the system prompt used for AI-based stacker.yml generation.
pub fn generation_system_prompt() -> &'static str {
    SYSTEM_PROMPT
}

/// Build the user prompt from the scan result.
pub fn build_generation_prompt(scan: &ProjectScanResult) -> String {
    let mut sections = Vec::new();

    // Project overview
    sections.push(format!(
        "Project: {}\nDetected type: {}\nRoot files: {}",
        scan.project_name,
        scan.detection.app_type,
        scan.root_files.join(", ")
    ));

    // Existing infrastructure
    if scan.detection.has_dockerfile {
        sections.push("Has existing Dockerfile: yes".to_string());
    }
    if scan.detection.has_compose {
        sections.push("Has existing docker-compose: yes".to_string());
    }
    if scan.detection.has_env_file {
        sections.push(format!(
            "Has .env file with keys: {}",
            scan.env_keys.join(", ")
        ));
    }

    // File contents for context
    for (filename, content) in &scan.file_contents {
        sections.push(format!("--- {} ---\n{}", filename, content));
    }

    // Existing Dockerfile content
    if let Some(ref df) = scan.existing_dockerfile {
        sections.push(format!("--- Existing Dockerfile ---\n{}", df));
    }

    // Existing compose content
    if let Some(ref dc) = scan.existing_compose {
        sections.push(format!("--- Existing docker-compose ---\n{}", dc));
    }

    if !scan.pipe_hints.is_empty() {
        let formatted = scan
            .pipe_hints
            .iter()
            .map(|hint| {
                format!(
                    "- {} -> {} [{}] confidence={} evidence={}",
                    hint.source,
                    hint.target,
                    hint.kind,
                    hint.confidence.as_str(),
                    hint.evidence.join("; ")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        sections.push(format!(
            "Potential local pipe / integration hints (advisory, not runtime-verified):\n{}",
            formatted
        ));
    }

    sections.push(
        "Generate a complete stacker.yml for this project. Output ONLY valid YAML.".to_string(),
    );

    sections.join("\n\n")
}

/// Build the `(system_prompt, user_prompt)` pair for stacker.yml generation.
pub fn build_generation_request(project_dir: &Path) -> (String, String) {
    let fs = RealFileSystem;
    let scan = scan_project(project_dir, &fs);
    (
        generation_system_prompt().to_string(),
        build_generation_prompt(&scan),
    )
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// generate_config_with_ai — core AI generation function
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Scan the project, send context to AI, and return generated stacker.yml content.
///
/// The returned string is raw YAML ready to be written to disk.
/// The caller is responsible for writing the file and validating it.
pub fn generate_config_with_ai(
    project_dir: &Path,
    provider: &dyn AiProvider,
) -> Result<String, CliError> {
    let fs = RealFileSystem;
    generate_config_with_ai_impl(project_dir, provider, &fs)
}

/// Inner implementation taking a `FileSystem` for testability.
pub fn generate_config_with_ai_impl(
    project_dir: &Path,
    provider: &dyn AiProvider,
    fs: &dyn FileSystem,
) -> Result<String, CliError> {
    let scan = scan_project(project_dir, fs);
    let user_prompt = build_generation_prompt(&scan);
    let raw_response = provider.complete(&user_prompt, SYSTEM_PROMPT)?;

    // Strip markdown fences if the model wrapped the YAML in ```yaml ... ```
    let yaml = strip_code_fences(&raw_response);

    // Validate that it's parseable YAML (but don't require it to be a valid StackerConfig
    // yet — the caller will do from_str() and report detailed errors)
    serde_yaml::from_str::<serde_yaml::Value>(&yaml).map_err(|e| CliError::AiProviderError {
        provider: provider.name().to_string(),
        message: format!(
            "AI generated invalid YAML: {}. Raw response:\n{}",
            e, raw_response
        ),
    })?;

    Ok(yaml)
}

/// Strip markdown code fences from AI response.
/// Handles ```yaml\n...\n```, ```yml\n...\n```, and ```\n...\n```.
pub fn strip_code_fences(text: &str) -> String {
    let trimmed = text.trim();

    // Check for opening fence
    let without_open = if trimmed.starts_with("```yaml") || trimmed.starts_with("```yml") {
        // Remove opening fence line
        trimmed.splitn(2, '\n').nth(1).unwrap_or(trimmed)
    } else if trimmed.starts_with("```") {
        trimmed.splitn(2, '\n').nth(1).unwrap_or(trimmed)
    } else {
        return trimmed.to_string();
    };

    // Remove closing fence
    if without_open.trim_end().ends_with("```") {
        let end = without_open.rfind("```").unwrap_or(without_open.len());
        without_open[..end].trim_end().to_string()
    } else {
        without_open.to_string()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::config_parser::{AppType, StackerConfig};
    use crate::cli::detector::FileSystem;

    // ── Mock filesystem ─────────────────────────────

    struct MockFs {
        files: Vec<String>,
    }

    impl MockFs {
        fn with_files(files: &[&str]) -> Self {
            Self {
                files: files.iter().map(|s| s.to_string()).collect(),
            }
        }
    }

    impl FileSystem for MockFs {
        fn exists(&self, path: &Path) -> bool {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            self.files.contains(&name.to_string())
        }

        fn list_dir(&self, _path: &Path) -> Result<Vec<String>, std::io::Error> {
            Ok(self.files.clone())
        }

        fn read_to_string(&self, _path: &Path) -> Result<String, std::io::Error> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "read_to_string not used in ai_scanner tests",
            ))
        }
    }

    // ── Mock AI provider ────────────────────────────

    struct MockAi {
        response: String,
    }

    impl MockAi {
        fn with_yaml(yaml: &str) -> Self {
            Self {
                response: yaml.to_string(),
            }
        }

        fn with_fenced_yaml(yaml: &str) -> Self {
            Self {
                response: format!("```yaml\n{}\n```", yaml),
            }
        }
    }

    impl AiProvider for MockAi {
        fn name(&self) -> &str {
            "mock"
        }

        fn complete(&self, _prompt: &str, _context: &str) -> Result<String, CliError> {
            Ok(self.response.clone())
        }
    }

    struct FailingAi;

    impl AiProvider for FailingAi {
        fn name(&self) -> &str {
            "failing"
        }

        fn complete(&self, _prompt: &str, _context: &str) -> Result<String, CliError> {
            Err(CliError::AiProviderError {
                provider: "failing".to_string(),
                message: "connection refused".to_string(),
            })
        }
    }

    // ── strip_code_fences ───────────────────────────

    #[test]
    fn test_strip_yaml_fences() {
        let input = "```yaml\nname: test\napp:\n  type: node\n```";
        let result = strip_code_fences(input);
        assert_eq!(result, "name: test\napp:\n  type: node");
    }

    #[test]
    fn test_strip_yml_fences() {
        let input = "```yml\nname: test\n```";
        let result = strip_code_fences(input);
        assert_eq!(result, "name: test");
    }

    #[test]
    fn test_strip_generic_fences() {
        let input = "```\nname: test\n```";
        let result = strip_code_fences(input);
        assert_eq!(result, "name: test");
    }

    #[test]
    fn test_strip_no_fences() {
        let input = "name: test\napp:\n  type: node";
        let result = strip_code_fences(input);
        assert_eq!(result, input);
    }

    // ── scan_project ────────────────────────────────

    #[test]
    fn test_scan_project_basic() {
        let fs = MockFs::with_files(&["package.json", "src", "README.md"]);
        let result = scan_project(Path::new("/test-project"), &fs);

        assert_eq!(result.detection.app_type, AppType::Node);
        assert_eq!(result.root_files.len(), 3);
        // Note: file_contents won't have actual data since MockFs doesn't provide file I/O,
        // but root_files and detection should work correctly.
    }

    #[test]
    fn test_scan_project_empty() {
        let fs = MockFs::with_files(&[]);
        let result = scan_project(Path::new("/empty-project"), &fs);

        assert_eq!(result.detection.app_type, AppType::Custom);
        assert!(result.root_files.is_empty());
        assert!(result.file_contents.is_empty());
    }

    #[test]
    fn test_discover_local_pipe_hints_from_env_and_compose() {
        let mut file_contents = HashMap::new();
        file_contents.insert(
            "docker-compose.yml".to_string(),
            "services:\n  postgres:\n    image: postgres:16\n  redis:\n    image: redis:7\n"
                .to_string(),
        );

        let hints = discover_local_pipe_hints(
            "openclaw-app",
            "node".to_string(),
            &["docker-compose.yml".to_string()],
            &file_contents,
            &["DATABASE_URL".to_string(), "REDIS_URL".to_string()],
        );

        assert!(hints
            .iter()
            .any(|h| h.target == "postgres" && h.kind == "database"));
        assert!(hints
            .iter()
            .any(|h| h.target == "redis" && h.kind == "cache-or-queue"));
    }

    #[test]
    fn test_discover_local_pipe_hints_for_frontend_api() {
        let hints = discover_local_pipe_hints(
            "frontend-app",
            "node".to_string(),
            &["next.config.js".to_string()],
            &HashMap::new(),
            &["NEXT_PUBLIC_API_URL".to_string()],
        );

        assert!(hints
            .iter()
            .any(|h| h.target == "backend-api" && h.kind == "http-api"));
    }

    // ── build_generation_prompt ─────────────────────

    #[test]
    fn test_prompt_includes_project_name() {
        let scan = ProjectScanResult {
            project_name: "my-web-app".to_string(),
            detection: ProjectDetection {
                app_type: AppType::Node,
                ..Default::default()
            },
            root_files: vec!["package.json".to_string(), "src".to_string()],
            ..Default::default()
        };

        let prompt = build_generation_prompt(&scan);
        assert!(prompt.contains("my-web-app"));
        assert!(prompt.contains("node"));
        assert!(prompt.contains("package.json"));
        assert!(prompt.contains("Generate a complete stacker.yml"));
    }

    #[test]
    fn test_prompt_includes_env_keys() {
        let scan = ProjectScanResult {
            project_name: "app".to_string(),
            detection: ProjectDetection {
                has_env_file: true,
                ..Default::default()
            },
            env_keys: vec!["DATABASE_URL".to_string(), "SECRET_KEY".to_string()],
            ..Default::default()
        };

        let prompt = build_generation_prompt(&scan);
        assert!(prompt.contains("DATABASE_URL"));
        assert!(prompt.contains("SECRET_KEY"));
    }

    #[test]
    fn test_prompt_includes_existing_dockerfile() {
        let scan = ProjectScanResult {
            project_name: "app".to_string(),
            detection: ProjectDetection {
                has_dockerfile: true,
                ..Default::default()
            },
            existing_dockerfile: Some("FROM node:20\nCOPY . .\nRUN npm install".to_string()),
            ..Default::default()
        };

        let prompt = build_generation_prompt(&scan);
        assert!(prompt.contains("Existing Dockerfile"));
        assert!(prompt.contains("FROM node:20"));
    }

    #[test]
    fn test_prompt_includes_existing_compose() {
        let scan = ProjectScanResult {
            project_name: "app".to_string(),
            detection: ProjectDetection {
                has_compose: true,
                ..Default::default()
            },
            existing_compose: Some("version: '3'\nservices:\n  web:\n    build: .".to_string()),
            ..Default::default()
        };

        let prompt = build_generation_prompt(&scan);
        assert!(prompt.contains("Existing docker-compose"));
        assert!(prompt.contains("services:"));
    }

    #[test]
    fn test_prompt_includes_file_contents() {
        let mut file_contents = HashMap::new();
        file_contents.insert(
            "package.json".to_string(),
            r#"{"name":"test","dependencies":{"express":"^4.18"}}"#.to_string(),
        );

        let scan = ProjectScanResult {
            project_name: "app".to_string(),
            file_contents,
            ..Default::default()
        };

        let prompt = build_generation_prompt(&scan);
        assert!(prompt.contains("package.json"));
        assert!(prompt.contains("express"));
    }

    #[test]
    fn test_prompt_includes_pipe_hints() {
        let scan = ProjectScanResult {
            project_name: "openclaw-app".to_string(),
            pipe_hints: vec![PipeHint {
                source: "openclaw-app".to_string(),
                target: "postgres".to_string(),
                kind: "database".to_string(),
                confidence: PipeHintConfidence::High,
                evidence: vec!["env keys reference postgres/database".to_string()],
            }],
            ..Default::default()
        };

        let prompt = build_generation_prompt(&scan);
        assert!(prompt.contains("Potential local pipe / integration hints"));
        assert!(prompt.contains("openclaw-app -> postgres [database]"));
        assert!(prompt.contains("confidence=high"));
    }

    // ── generate_config_with_ai_impl ────────────────

    #[test]
    fn test_generate_with_ai_valid_yaml() {
        let yaml = "name: ai-app\napp:\n  type: node\n  path: .\ndeploy:\n  target: local\n";
        let provider = MockAi::with_yaml(yaml);
        let fs = MockFs::with_files(&["package.json"]);

        let result = generate_config_with_ai_impl(Path::new("/test"), &provider, &fs);
        assert!(result.is_ok());

        let output = result.unwrap();
        assert!(output.contains("ai-app"));
        assert!(output.contains("node"));

        // Should be parseable as StackerConfig
        let config = StackerConfig::from_str(&output).unwrap();
        assert_eq!(config.name, "ai-app");
        assert_eq!(config.app.app_type, AppType::Node);
    }

    #[test]
    fn test_generate_with_ai_strips_fences() {
        let yaml = "name: fenced-app\napp:\n  type: python\n  path: .\n";
        let provider = MockAi::with_fenced_yaml(yaml);
        let fs = MockFs::with_files(&["requirements.txt"]);

        let result = generate_config_with_ai_impl(Path::new("/test"), &provider, &fs);
        assert!(result.is_ok());

        let output = result.unwrap();
        assert!(!output.contains("```"));
        assert!(output.contains("fenced-app"));
    }

    #[test]
    fn test_generate_with_ai_invalid_yaml_errors() {
        let provider = MockAi::with_yaml("not: valid: yaml: [broken");
        let fs = MockFs::with_files(&["index.html"]);

        let result = generate_config_with_ai_impl(Path::new("/test"), &provider, &fs);
        assert!(result.is_err());

        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("invalid YAML"));
    }

    #[test]
    fn test_generate_with_ai_provider_error() {
        let provider = FailingAi;
        let fs = MockFs::with_files(&["package.json"]);

        let result = generate_config_with_ai_impl(Path::new("/test"), &provider, &fs);
        assert!(result.is_err());

        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("connection refused"));
    }

    #[test]
    fn test_generate_with_ai_full_config() {
        let yaml = r#"name: full-ai-app
version: "1.0"
app:
  type: node
  path: .
  build:
    context: .
    args:
      NODE_ENV: production
services:
  - name: postgres
    image: postgres:16
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: mydb
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
  - name: redis
    image: redis:7-alpine
    ports:
      - "6379:6379"
proxy:
  type: nginx
  domains:
    - domain: app.localhost
      ssl: "off"
      upstream: app:3000
deploy:
  target: local
monitoring:
  status_panel: true
  healthcheck:
    endpoint: /health
    interval: 30s
env:
  NODE_ENV: production
"#;
        let provider = MockAi::with_yaml(yaml);
        let fs = MockFs::with_files(&["package.json", "tsconfig.json"]);

        let result = generate_config_with_ai_impl(Path::new("/test"), &provider, &fs);
        assert!(result.is_ok());

        let output = result.unwrap();

        // Verify it parses as a complete StackerConfig
        // Note: ${DB_PASSWORD} will fail env resolution, so we set it
        std::env::set_var("DB_PASSWORD", "test123");
        let config = StackerConfig::from_str(&output).unwrap();
        std::env::remove_var("DB_PASSWORD");

        assert_eq!(config.name, "full-ai-app");
        assert_eq!(config.app.app_type, AppType::Node);
        assert_eq!(config.services.len(), 2);
        assert_eq!(config.services[0].name, "postgres");
        assert_eq!(config.services[1].name, "redis");
        assert_eq!(
            config.proxy.proxy_type,
            crate::cli::config_parser::ProxyType::Nginx
        );
        assert!(config.monitoring.status_panel);
    }

    // ── System prompt content ───────────────────────

    #[test]
    fn test_system_prompt_covers_schema() {
        assert!(SYSTEM_PROMPT.contains("stacker.yml"));
        assert!(SYSTEM_PROMPT.contains("services"));
        assert!(SYSTEM_PROMPT.contains("proxy"));
        assert!(SYSTEM_PROMPT.contains("deploy"));
        assert!(SYSTEM_PROMPT.contains("monitoring"));
        assert!(SYSTEM_PROMPT.contains("${VAR_NAME}"));
        assert!(SYSTEM_PROMPT.contains("YAML"));
    }
}
