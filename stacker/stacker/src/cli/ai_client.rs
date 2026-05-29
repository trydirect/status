use crate::cli::config_parser::{AiConfig, AiProviderType, AppType};
use crate::cli::error::CliError;
use std::io::{BufRead, BufReader, Write};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Constants
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Default OpenAI-compatible endpoint.
pub const OPENAI_API_URL: &str = "https://api.openai.com/v1/chat/completions";

/// Default Anthropic endpoint.
pub const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";

/// Default Ollama endpoint.
pub const OLLAMA_API_URL: &str = "http://localhost:11434/api/chat";

/// Ollama tags endpoint (for listing available models).
pub const OLLAMA_TAGS_URL: &str = "http://localhost:11434/api/tags";

/// Default model per provider when none is specified in config.
pub fn default_model(provider: AiProviderType) -> &'static str {
    match provider {
        AiProviderType::Openai => "gpt-4o",
        AiProviderType::Anthropic => "claude-sonnet-4-20250514",
        AiProviderType::Ollama => "llama3",
        AiProviderType::Custom => "default",
    }
}

/// Preferred Ollama models for stacker.yml generation, in priority order.
/// The first available model from this list will be used.
const OLLAMA_PREFERRED_MODELS: &[&str] = &[
    "llama3",
    "llama3.1",
    "llama3.2",
    "llama3:latest",
    "codellama",
    "mistral",
    "mixtral",
    "deepseek-r1",
    "deepseek-coder",
    "qwen2.5-coder",
    "qwen2.5",
    "phi3",
    "gemma2",
    "gpt-oss",
];

/// Default request timeout in seconds.
const DEFAULT_AI_TIMEOUT_SECS: u64 = 300;

/// Resolve the AI request timeout in seconds.
///
/// Priority: `STACKER_AI_TIMEOUT` env var > `AiConfig.timeout` value > 300s default.
/// A value of 0 means no timeout (unlimited).
pub fn resolve_timeout(config_timeout: u64) -> u64 {
    if let Ok(val) = std::env::var("STACKER_AI_TIMEOUT") {
        if let Ok(secs) = val.parse::<u64>() {
            return secs;
        }
    }
    if config_timeout > 0 {
        config_timeout
    } else {
        DEFAULT_AI_TIMEOUT_SECS
    }
}

/// Normalise a user-supplied Ollama endpoint.
///
/// If the URL has no `/api/` path component (e.g. `http://host:11434`)
/// the standard chat path `/api/chat` is appended automatically.
pub fn normalize_ollama_endpoint(endpoint: &str) -> String {
    if endpoint.contains("/api/") {
        endpoint.to_string()
    } else {
        format!("{}/api/chat", endpoint.trim_end_matches('/'))
    }
}

/// Query the local Ollama instance for available models.
/// Returns a list of model names, or an empty vec if Ollama is unreachable.
pub fn list_ollama_models(base_url: Option<&str>) -> Vec<String> {
    let tags_url = base_url
        .map(|u| {
            // Normalise base URLs first, then convert chat path → tags path
            let normalised = normalize_ollama_endpoint(u);
            normalised
                .replace("/api/chat", "/api/tags")
                .replace("/api/generate", "/api/tags")
        })
        .unwrap_or_else(|| OLLAMA_TAGS_URL.to_string());

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let response = match client.get(&tags_url).send() {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };

    let json: serde_json::Value = match response.json() {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };

    json["models"]
        .as_array()
        .map(|models| {
            models
                .iter()
                .filter_map(|m| m["name"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Pick the best available Ollama model for config generation.
/// Checks the preferred list first, then falls back to the first available model.
/// Returns None if no models are available.
pub fn pick_ollama_model(base_url: Option<&str>) -> Option<String> {
    let available = list_ollama_models(base_url);
    if available.is_empty() {
        return None;
    }

    // Check preferred models in priority order
    for preferred in OLLAMA_PREFERRED_MODELS {
        for avail in &available {
            // Match base name (e.g. "deepseek-r1" matches "deepseek-r1:latest")
            let avail_base = avail.split(':').next().unwrap_or(avail);
            if avail_base == *preferred || avail == preferred {
                return Some(avail.clone());
            }
        }
    }

    // No preferred model found — use the first non-embedding model
    available
        .into_iter()
        .find(|m| !m.contains("embed"))
        .or_else(|| Some("llama3".to_string()))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AiProvider trait — abstraction over LLM backends (DIP)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tool calling types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A message in a multi-turn chat conversation (used by the agentic loop).
#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
    /// Tool calls requested by the assistant.
    pub tool_calls: Option<Vec<ToolCall>>,
    /// For role="tool": the id of the call this result belongs to.
    pub tool_call_id: Option<String>,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: "system".to_string(),
            content: content.into(),
            tool_calls: None,
            tool_call_id: None,
        }
    }
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".to_string(),
            content: content.into(),
            tool_calls: None,
            tool_call_id: None,
        }
    }
    pub fn tool_result(id: Option<String>, content: impl Into<String>) -> Self {
        Self {
            role: "tool".to_string(),
            content: content.into(),
            tool_calls: None,
            tool_call_id: id,
        }
    }
}

/// Definition of a tool the AI may call.
#[derive(Debug, Clone)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    /// JSON Schema for the parameters object.
    pub parameters: serde_json::Value,
}

/// A tool call requested by the AI.
#[derive(Debug, Clone)]
pub struct ToolCall {
    /// Provider-assigned call id (used when replying with results).
    pub id: Option<String>,
    pub name: String,
    pub arguments: serde_json::Value,
}

/// Response from `complete_with_tools`: either plain text or tool invocations.
#[derive(Debug)]
pub enum AiResponse {
    Text(String),
    /// (assistant narration, tool calls)
    ToolCalls(String, Vec<ToolCall>),
}

/// Built-in tool definitions exposed to the AI in write mode.
pub fn write_file_tool() -> ToolDef {
    ToolDef {
        name: "write_file".to_string(),
        description: "Write content to a file on disk. Creates parent directories as needed."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Relative path to the file" },
                "content": { "type": "string", "description": "Full file content to write" }
            },
            "required": ["path", "content"]
        }),
    }
}

pub fn read_file_tool() -> ToolDef {
    ToolDef {
        name: "read_file".to_string(),
        description: "Read the current content of a file on disk.".to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Relative path to the file" }
            },
            "required": ["path"]
        }),
    }
}

pub fn list_directory_tool() -> ToolDef {
    ToolDef {
        name: "list_directory".to_string(),
        description: "List files and folders in a directory within the project. \
                      Use '.' for the project root."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative directory path (e.g. '.', '.stacker', 'src')"
                }
            },
            "required": ["path"]
        }),
    }
}

pub fn config_validate_tool() -> ToolDef {
    ToolDef {
        name: "config_validate".to_string(),
        description: "Validate the stacker.yml configuration file and report any errors."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
    }
}

pub fn config_show_tool() -> ToolDef {
    ToolDef {
        name: "config_show".to_string(),
        description: "Show the fully-resolved stacker.yml configuration (with env vars expanded)."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
    }
}

pub fn stacker_status_tool() -> ToolDef {
    ToolDef {
        name: "stacker_status".to_string(),
        description: "Show the current deployment status of running containers.".to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
    }
}

pub fn stacker_logs_tool() -> ToolDef {
    ToolDef {
        name: "stacker_logs".to_string(),
        description:
            "Retrieve container logs. Optionally filter by service name and limit line count."
                .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service name to filter logs (omit for all services)"
                },
                "tail": {
                    "type": "integer",
                    "description": "Number of recent lines to show (default 50)"
                }
            },
            "required": []
        }),
    }
}

pub fn stacker_deploy_tool() -> ToolDef {
    ToolDef {
        name: "stacker_deploy".to_string(),
        description: "Build and deploy the stack. Use dry_run=true to preview what would happen \
                      without making changes."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "enum": ["local", "cloud", "server"],
                    "description": "Deployment target (omit to use stacker.yml default)"
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "Preview deployment plan without executing (default: true for safety)"
                },
                "force_rebuild": {
                    "type": "boolean",
                    "description": "Force rebuild of all container images"
                }
            },
            "required": []
        }),
    }
}

pub fn proxy_add_tool() -> ToolDef {
    ToolDef {
        name: "proxy_add".to_string(),
        description: "Add a reverse-proxy entry mapping a domain to an upstream service."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain name (e.g. 'example.com')"
                },
                "upstream": {
                    "type": "string",
                    "description": "Upstream URL (e.g. 'http://app:3000')"
                },
                "ssl": {
                    "type": "string",
                    "enum": ["auto", "manual", "off"],
                    "description": "SSL mode"
                }
            },
            "required": ["domain"]
        }),
    }
}

pub fn proxy_detect_tool() -> ToolDef {
    ToolDef {
        name: "proxy_detect".to_string(),
        description: "Detect running reverse-proxy containers (nginx, Traefik, etc.) on the host."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
    }
}

// ── Agent tools ──────────────────────────────────────

pub fn agent_health_tool() -> ToolDef {
    ToolDef {
        name: "agent_health".to_string(),
        description: "Check container health on the remote deployment via the Status Panel agent. \
                      Returns container states, resource usage, and health metrics."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "app": {
                    "type": "string",
                    "description": "App code to check (e.g. 'postgres', 'nginx'). Omit for all containers."
                },
                "deployment": {
                    "type": "string",
                    "description": "Deployment hash (auto-detected from local config if omitted)"
                }
            },
            "required": []
        }),
    }
}

pub fn agent_status_tool() -> ToolDef {
    ToolDef {
        name: "agent_status".to_string(),
        description: "Get the Status Panel agent status, including agent version, \
                      last heartbeat, container states, and recent command history."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "deployment": {
                    "type": "string",
                    "description": "Deployment hash (auto-detected from local config if omitted)"
                }
            },
            "required": []
        }),
    }
}

pub fn agent_logs_tool() -> ToolDef {
    ToolDef {
        name: "agent_logs".to_string(),
        description: "Fetch container logs from the remote deployment via the Status Panel agent. \
                      Logs are automatically redacted for safety."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "app": {
                    "type": "string",
                    "description": "App code to fetch logs for (e.g. 'postgres', 'nginx')"
                },
                "limit": {
                    "type": "number",
                    "description": "Maximum number of log lines (default: 100)"
                },
                "deployment": {
                    "type": "string",
                    "description": "Deployment hash (auto-detected if omitted)"
                }
            },
            "required": ["app"]
        }),
    }
}

pub fn add_service_tool() -> ToolDef {
    ToolDef {
        name: "add_service".to_string(),
        description: "Add a service from the built-in template catalog to stacker.yml. \
                      Supports common services: postgres, mysql, redis, mongodb, rabbitmq, \
                      elasticsearch, wordpress, traefik, nginx, qdrant, minio, portainer, etc. \
                      Aliases work too: wp→wordpress, pg→postgres, es→elasticsearch."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "service_name": {
                    "type": "string",
                    "description": "Service name or alias (e.g. 'postgres', 'wp', 'redis')"
                },
                "custom_ports": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Override default port mappings (e.g. ['5433:5432'])"
                },
                "custom_env": {
                    "type": "object",
                    "description": "Extra environment variables to merge (e.g. {'POSTGRES_DB': 'mydb'})"
                }
            },
            "required": ["service_name"]
        }),
    }
}

/// Returns all tools available in write mode, ordered from least to most impactful.
pub fn all_write_mode_tools() -> Vec<ToolDef> {
    vec![
        // Read-only
        read_file_tool(),
        list_directory_tool(),
        config_validate_tool(),
        config_show_tool(),
        stacker_status_tool(),
        stacker_logs_tool(),
        proxy_detect_tool(),
        // Agent read-only
        agent_health_tool(),
        agent_status_tool(),
        agent_logs_tool(),
        // Write / action
        write_file_tool(),
        add_service_tool(),
        stacker_deploy_tool(),
        proxy_add_tool(),
    ]
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AiProvider trait
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Abstraction for LLM completion providers.
///
/// Production: `OpenAiProvider`, `AnthropicProvider`, `OllamaProvider`.
/// Tests: `MockAiProvider` returns canned responses.
pub trait AiProvider: Send + Sync {
    /// Provider name for error reporting.
    fn name(&self) -> &str;

    /// Send a completion request and return the response text.
    fn complete(&self, prompt: &str, context: &str) -> Result<String, CliError>;

    /// Whether this provider supports tool calling / function calling.
    fn supports_tools(&self) -> bool {
        false
    }

    /// Send a multi-turn chat request with tool definitions.
    /// The default implementation returns an error; override for providers that
    /// support function / tool calling.
    fn complete_with_tools(
        &self,
        _messages: &[ChatMessage],
        _tools: &[ToolDef],
    ) -> Result<AiResponse, CliError> {
        Err(CliError::AiProviderError {
            provider: self.name().to_string(),
            message: "Tool calling is not supported by this provider. \
                      Use openai or ollama (model with tool support required)."
                .to_string(),
        })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// OpenAiProvider — OpenAI / OpenAI-compatible APIs
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Calls the OpenAI Chat Completions API (or any compatible endpoint).
/// Also works with Azure OpenAI, Together AI, Groq, etc.
pub struct OpenAiProvider {
    pub endpoint: String,
    pub api_key: String,
    pub model: String,
    pub timeout_secs: u64,
}

impl OpenAiProvider {
    pub fn from_config(config: &AiConfig) -> Result<Self, CliError> {
        let api_key = config.api_key.clone().ok_or(CliError::AiProviderError {
            provider: "openai".to_string(),
            message: "api_key is required for OpenAI provider".to_string(),
        })?;

        Ok(Self {
            endpoint: config
                .endpoint
                .clone()
                .unwrap_or_else(|| OPENAI_API_URL.to_string()),
            api_key,
            model: config
                .model
                .clone()
                .unwrap_or_else(|| default_model(AiProviderType::Openai).to_string()),
            timeout_secs: resolve_timeout(config.timeout),
        })
    }
}

impl AiProvider for OpenAiProvider {
    fn name(&self) -> &str {
        "openai"
    }

    fn supports_tools(&self) -> bool {
        true
    }

    fn complete_with_tools(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDef],
    ) -> Result<AiResponse, CliError> {
        let messages_json: Vec<serde_json::Value> = messages
            .iter()
            .map(|m| {
                let mut obj = serde_json::json!({ "role": m.role, "content": m.content });
                if let Some(tcs) = &m.tool_calls {
                    obj["tool_calls"] = serde_json::json!(tcs
                        .iter()
                        .map(|tc| {
                            serde_json::json!({
                                "id": tc.id.as_deref().unwrap_or("call_0"),
                                "type": "function",
                                "function": {
                                    "name": tc.name,
                                    "arguments": tc.arguments.to_string()
                                }
                            })
                        })
                        .collect::<Vec<_>>());
                }
                if let Some(id) = &m.tool_call_id {
                    obj["tool_call_id"] = serde_json::json!(id);
                }
                obj
            })
            .collect();

        let tools_json: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters
                    }
                })
            })
            .collect();

        let body = serde_json::json!({
            "model": self.model,
            "messages": messages_json,
            "tools": tools_json,
            "tool_choice": "auto",
            "temperature": 0.3
        });

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .build()
            .map_err(|e| CliError::AiProviderError {
                provider: "openai".to_string(),
                message: format!("Failed to build HTTP client: {}", e),
            })?;

        let response = client
            .post(&self.endpoint)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| CliError::AiProviderError {
                provider: "openai".to_string(),
                message: format!("Request failed: {}", e),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_default();
            return Err(CliError::AiProviderError {
                provider: "openai".to_string(),
                message: format!("HTTP {} — {}", status, text),
            });
        }

        let json: serde_json::Value = response.json().map_err(|e| CliError::AiProviderError {
            provider: "openai".to_string(),
            message: format!("Failed to parse response: {}", e),
        })?;

        let msg = &json["choices"][0]["message"];
        let content = msg["content"].as_str().unwrap_or("").to_string();

        if let Some(tcs) = msg["tool_calls"].as_array() {
            if !tcs.is_empty() {
                let calls: Vec<ToolCall> = tcs
                    .iter()
                    .filter_map(|tc| {
                        let id = tc["id"].as_str().map(|s| s.to_string());
                        let func = &tc["function"];
                        let name = func["name"].as_str()?.to_string();
                        // OpenAI encodes arguments as a JSON string
                        let arguments: serde_json::Value =
                            serde_json::from_str(func["arguments"].as_str().unwrap_or("{}"))
                                .unwrap_or(serde_json::json!({}));
                        Some(ToolCall {
                            id,
                            name,
                            arguments,
                        })
                    })
                    .collect();
                return Ok(AiResponse::ToolCalls(content, calls));
            }
        }

        Ok(AiResponse::Text(content))
    }

    fn complete(&self, prompt: &str, context: &str) -> Result<String, CliError> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": context },
                { "role": "user", "content": prompt }
            ],
            "temperature": 0.3
        });

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .build()
            .map_err(|e| CliError::AiProviderError {
                provider: "openai".to_string(),
                message: format!("Failed to build HTTP client: {}", e),
            })?;

        let response = client
            .post(&self.endpoint)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| CliError::AiProviderError {
                provider: "openai".to_string(),
                message: format!("Request failed: {}", e),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_default();
            return Err(CliError::AiProviderError {
                provider: "openai".to_string(),
                message: format!("HTTP {} — {}", status, text),
            });
        }

        let json: serde_json::Value = response.json().map_err(|e| CliError::AiProviderError {
            provider: "openai".to_string(),
            message: format!("Failed to parse response: {}", e),
        })?;

        json["choices"][0]["message"]["content"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| CliError::AiProviderError {
                provider: "openai".to_string(),
                message: "No content in response".to_string(),
            })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AnthropicProvider — Claude API
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Calls the Anthropic Messages API.
pub struct AnthropicProvider {
    pub endpoint: String,
    pub api_key: String,
    pub model: String,
    pub timeout_secs: u64,
}

impl AnthropicProvider {
    pub fn from_config(config: &AiConfig) -> Result<Self, CliError> {
        let api_key = config.api_key.clone().ok_or(CliError::AiProviderError {
            provider: "anthropic".to_string(),
            message: "api_key is required for Anthropic provider".to_string(),
        })?;

        Ok(Self {
            endpoint: config
                .endpoint
                .clone()
                .unwrap_or_else(|| ANTHROPIC_API_URL.to_string()),
            api_key,
            model: config
                .model
                .clone()
                .unwrap_or_else(|| default_model(AiProviderType::Anthropic).to_string()),
            timeout_secs: resolve_timeout(config.timeout),
        })
    }
}

impl AiProvider for AnthropicProvider {
    fn name(&self) -> &str {
        "anthropic"
    }

    fn complete(&self, prompt: &str, context: &str) -> Result<String, CliError> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": 4096,
            "system": context,
            "messages": [
                { "role": "user", "content": prompt }
            ]
        });

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .build()
            .map_err(|e| CliError::AiProviderError {
                provider: "anthropic".to_string(),
                message: format!("Failed to build HTTP client: {}", e),
            })?;

        let response = client
            .post(&self.endpoint)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| CliError::AiProviderError {
                provider: "anthropic".to_string(),
                message: format!("Request failed: {}", e),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_default();
            return Err(CliError::AiProviderError {
                provider: "anthropic".to_string(),
                message: format!("HTTP {} — {}", status, text),
            });
        }

        let json: serde_json::Value = response.json().map_err(|e| CliError::AiProviderError {
            provider: "anthropic".to_string(),
            message: format!("Failed to parse response: {}", e),
        })?;

        json["content"][0]["text"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| CliError::AiProviderError {
                provider: "anthropic".to_string(),
                message: "No content in response".to_string(),
            })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// OllamaProvider — local Ollama instance
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Calls a local Ollama chat API. No API key required.
pub struct OllamaProvider {
    pub endpoint: String,
    pub model: String,
    pub timeout_secs: u64,
}

impl OllamaProvider {
    pub fn from_config(config: &AiConfig) -> Self {
        let endpoint = config
            .endpoint
            .as_deref()
            .map(normalize_ollama_endpoint)
            .unwrap_or_else(|| OLLAMA_API_URL.to_string());

        let model = match config.model.clone() {
            Some(m) => {
                // Verify the configured model is actually available
                let available = list_ollama_models(Some(&endpoint));
                if available.is_empty() {
                    // Ollama unreachable — use the configured model as-is
                    m
                } else if available.iter().any(|a| {
                    let base = a.split(':').next().unwrap_or(a);
                    let m_base = m.split(':').next().unwrap_or(&m);
                    a == &m || base == m_base
                }) {
                    m
                } else {
                    // Configured model not found — auto-detect
                    eprintln!("  ⚠ Model '{}' not found in Ollama, auto-detecting...", m);
                    match pick_ollama_model(Some(&endpoint)) {
                        Some(detected) => {
                            eprintln!("  Using Ollama model: {}", detected);
                            detected
                        }
                        None => m, // nothing else available, try anyway
                    }
                }
            }
            None => {
                // No model configured — auto-detect
                match pick_ollama_model(Some(&endpoint)) {
                    Some(m) => {
                        eprintln!("  Using Ollama model: {}", m);
                        m
                    }
                    None => {
                        let default = default_model(AiProviderType::Ollama).to_string();
                        eprintln!("  No models detected, trying default: {}", default);
                        default
                    }
                }
            }
        };

        let timeout_secs = resolve_timeout(config.timeout);

        Self {
            endpoint,
            model,
            timeout_secs,
        }
    }
}

impl AiProvider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    fn supports_tools(&self) -> bool {
        true
    }

    fn complete_with_tools(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDef],
    ) -> Result<AiResponse, CliError> {
        let messages_json: Vec<serde_json::Value> = messages
            .iter()
            .map(|m| {
                let mut obj = serde_json::json!({ "role": m.role, "content": m.content });
                // Include previous assistant tool_calls in history so the model
                // understands its own prior turn.
                if let Some(tcs) = &m.tool_calls {
                    obj["tool_calls"] = serde_json::json!(tcs
                        .iter()
                        .map(|tc| {
                            serde_json::json!({
                                "function": {
                                    "name": tc.name,
                                    "arguments": tc.arguments
                                }
                            })
                        })
                        .collect::<Vec<_>>());
                }
                obj
            })
            .collect();

        let tools_json: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters
                    }
                })
            })
            .collect();

        let body = serde_json::json!({
            "model": self.model,
            "stream": false,
            "messages": messages_json,
            "tools": tools_json
        });

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .build()
            .map_err(|e| CliError::AiProviderError {
                provider: "ollama".to_string(),
                message: format!("Failed to build HTTP client: {}", e),
            })?;

        let response = client
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| CliError::AiProviderError {
                provider: "ollama".to_string(),
                message: format!("Request failed (is Ollama running?): {}", e),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_default();
            return Err(CliError::AiProviderError {
                provider: "ollama".to_string(),
                message: format!("HTTP {} — {}", status, text),
            });
        }

        let json: serde_json::Value = response.json().map_err(|e| CliError::AiProviderError {
            provider: "ollama".to_string(),
            message: format!("Failed to parse response: {}", e),
        })?;

        let msg = &json["message"];
        let content = msg["content"].as_str().unwrap_or("").to_string();

        // Ollama returns tool calls as message.tool_calls (array of objects
        // with a "function" sub-object whose "arguments" is already a JSON
        // object, not a string).
        if let Some(tcs) = msg["tool_calls"].as_array() {
            if !tcs.is_empty() {
                let calls: Vec<ToolCall> = tcs
                    .iter()
                    .filter_map(|tc| {
                        let func = &tc["function"];
                        let name = func["name"].as_str()?.to_string();
                        // arguments may be a JSON object or a JSON string
                        let arguments = if func["arguments"].is_object() {
                            func["arguments"].clone()
                        } else if let Some(s) = func["arguments"].as_str() {
                            serde_json::from_str(s).unwrap_or(serde_json::json!({}))
                        } else {
                            serde_json::json!({})
                        };
                        Some(ToolCall {
                            id: None,
                            name,
                            arguments,
                        })
                    })
                    .collect();
                return Ok(AiResponse::ToolCalls(content, calls));
            }
        }

        Ok(AiResponse::Text(content))
    }

    fn complete(&self, prompt: &str, context: &str) -> Result<String, CliError> {
        let body = serde_json::json!({
            "model": self.model,
            "stream": false,
            "messages": [
                { "role": "system", "content": context },
                { "role": "user", "content": prompt }
            ]
        });

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .build()
            .map_err(|e| CliError::AiProviderError {
                provider: "ollama".to_string(),
                message: format!("Failed to build HTTP client: {}", e),
            })?;

        let response = client
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| CliError::AiProviderError {
                provider: "ollama".to_string(),
                message: format!("Request failed (is Ollama running?): {}", e),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_default();
            return Err(CliError::AiProviderError {
                provider: "ollama".to_string(),
                message: format!("HTTP {} — {}", status, text),
            });
        }

        let json: serde_json::Value = response.json().map_err(|e| CliError::AiProviderError {
            provider: "ollama".to_string(),
            message: format!("Failed to parse response: {}", e),
        })?;

        json["message"]["content"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| CliError::AiProviderError {
                provider: "ollama".to_string(),
                message: "No content in response".to_string(),
            })
    }
}

/// Stream a response from Ollama and print token chunks to stderr as they arrive.
/// Returns the full accumulated response text.
pub fn ollama_complete_streaming(
    config: &AiConfig,
    prompt: &str,
    context: &str,
) -> Result<String, CliError> {
    let provider = OllamaProvider::from_config(config);

    let body = serde_json::json!({
        "model": provider.model,
        "stream": true,
        "messages": [
            { "role": "system", "content": context },
            { "role": "user", "content": prompt }
        ]
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(provider.timeout_secs))
        .build()
        .map_err(|e| CliError::AiProviderError {
            provider: "ollama".to_string(),
            message: format!("Failed to build HTTP client: {}", e),
        })?;

    let response = client
        .post(&provider.endpoint)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| CliError::AiProviderError {
            provider: "ollama".to_string(),
            message: format!("Request failed (is Ollama running?): {}", e),
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().unwrap_or_default();
        return Err(CliError::AiProviderError {
            provider: "ollama".to_string(),
            message: format!("HTTP {} — {}", status, text),
        });
    }

    let mut content = String::new();
    let mut reader = BufReader::new(response);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .map_err(|e| CliError::AiProviderError {
                provider: "ollama".to_string(),
                message: format!("Failed to read stream: {}", e),
            })?;
        if bytes == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let json: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|e| CliError::AiProviderError {
                provider: "ollama".to_string(),
                message: format!("Invalid streaming chunk: {}", e),
            })?;

        if let Some(chunk) = json["message"]["content"].as_str() {
            eprint!("{}", chunk);
            let _ = std::io::stderr().flush();
            content.push_str(chunk);
        }

        if json["done"].as_bool().unwrap_or(false) {
            break;
        }
    }

    Ok(content)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Provider factory
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Create the appropriate provider from an `AiConfig`.
/// Returns `AiNotConfigured` if AI is disabled.
pub fn create_provider(config: &AiConfig) -> Result<Box<dyn AiProvider>, CliError> {
    if !config.enabled {
        return Err(CliError::AiNotConfigured);
    }

    match config.provider {
        AiProviderType::Openai | AiProviderType::Custom => {
            Ok(Box::new(OpenAiProvider::from_config(config)?))
        }
        AiProviderType::Anthropic => Ok(Box::new(AnthropicProvider::from_config(config)?)),
        AiProviderType::Ollama => Ok(Box::new(OllamaProvider::from_config(config))),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Prompt building
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Predefined AI task types that map to `AiConfig.tasks`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiTask {
    Dockerfile,
    Compose,
    Troubleshoot,
    Optimize,
}

impl AiTask {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dockerfile => "dockerfile",
            Self::Compose => "compose",
            Self::Troubleshoot => "troubleshoot",
            Self::Optimize => "optimize",
        }
    }
}

/// Context for building AI prompts.
#[derive(Debug, Clone, Default)]
pub struct PromptContext {
    pub project_type: Option<AppType>,
    pub files: Vec<String>,
    pub error_log: Option<String>,
    pub current_config: Option<String>,
}

/// System message providing context about the stacker CLI.
const SYSTEM_CONTEXT: &str = "\
You are an expert DevOps assistant integrated into the `stacker` CLI tool. \
Stacker helps developers deploy web applications using Docker, docker-compose, \
Terraform, and Ansible. You provide concise, production-ready configurations. \
Always use multi-stage builds when appropriate. Prefer Alpine-based images. \
Include health checks. Follow Docker and security best practices.";

/// Build a prompt for Dockerfile generation.
pub fn build_dockerfile_prompt(ctx: &PromptContext) -> (String, String) {
    let project_type = ctx
        .project_type
        .map(|t| t.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let files_list = if ctx.files.is_empty() {
        "No files detected".to_string()
    } else {
        ctx.files.join(", ")
    };

    let prompt = format!(
        "Generate an optimized Dockerfile for a {} project.\n\
         Detected files: {}\n\
         Requirements:\n\
         - Multi-stage build if applicable\n\
         - Alpine base image preferred\n\
         - Non-root user\n\
         - .dockerignore recommendations\n\
         Return only the Dockerfile content.",
        project_type, files_list
    );

    (SYSTEM_CONTEXT.to_string(), prompt)
}

/// Build a prompt for docker-compose generation/improvement.
pub fn build_compose_prompt(ctx: &PromptContext) -> (String, String) {
    let project_type = ctx
        .project_type
        .map(|t| t.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let current = ctx
        .current_config
        .as_deref()
        .unwrap_or("No existing compose file");

    let prompt = format!(
        "Generate or improve a docker-compose.yml for a {} project.\n\
         Current config:\n```yaml\n{}\n```\n\
         Requirements:\n\
         - Named volumes for persistence\n\
         - Health checks for services\n\
         - Proper networking\n\
         - Resource limits\n\
         Return only the docker-compose.yml content.",
        project_type, current
    );

    (SYSTEM_CONTEXT.to_string(), prompt)
}

/// Build a prompt for troubleshooting deployment issues.
pub fn build_troubleshoot_prompt(ctx: &PromptContext) -> (String, String) {
    let error = ctx.error_log.as_deref().unwrap_or("No error log provided");

    let prompt = format!(
        "Diagnose and fix the following deployment issue.\n\
         Error log:\n```\n{}\n```\n\
         Provide:\n\
         1. Root cause analysis\n\
         2. Step-by-step fix\n\
         3. Prevention recommendations",
        error
    );

    (SYSTEM_CONTEXT.to_string(), prompt)
}

/// Build a prompt based on task type.
pub fn build_prompt(task: AiTask, ctx: &PromptContext) -> (String, String) {
    match task {
        AiTask::Dockerfile => build_dockerfile_prompt(ctx),
        AiTask::Compose => build_compose_prompt(ctx),
        AiTask::Troubleshoot => build_troubleshoot_prompt(ctx),
        AiTask::Optimize => build_dockerfile_prompt(ctx), // reuse dockerfile optimization
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock provider ───────────────────────────────

    struct MockAiProvider {
        response: String,
    }

    impl MockAiProvider {
        fn with_response(response: &str) -> Self {
            Self {
                response: response.to_string(),
            }
        }
    }

    impl AiProvider for MockAiProvider {
        fn name(&self) -> &str {
            "mock"
        }

        fn complete(&self, _prompt: &str, _context: &str) -> Result<String, CliError> {
            Ok(self.response.clone())
        }
    }

    // ── Phase 7 tests ───────────────────────────────

    #[test]
    fn test_ai_provider_from_config_openai() {
        let config = AiConfig {
            enabled: true,
            provider: AiProviderType::Openai,
            model: Some("gpt-4o".to_string()),
            api_key: Some("sk-test-key".to_string()),
            endpoint: None,
            timeout: 300,
            tasks: vec!["dockerfile".to_string()],
        };

        let provider = create_provider(&config).unwrap();
        assert_eq!(provider.name(), "openai");
    }

    #[test]
    fn test_ai_provider_from_config_ollama() {
        let config = AiConfig {
            enabled: true,
            provider: AiProviderType::Ollama,
            model: None,
            api_key: None,
            endpoint: Some("http://localhost:11434/api/chat".to_string()),
            timeout: 300,
            tasks: vec![],
        };

        let provider = create_provider(&config).unwrap();
        assert_eq!(provider.name(), "ollama");
    }

    #[test]
    fn test_ai_provider_from_config_anthropic() {
        let config = AiConfig {
            enabled: true,
            provider: AiProviderType::Anthropic,
            model: Some("claude-sonnet-4-20250514".to_string()),
            api_key: Some("sk-ant-test".to_string()),
            endpoint: None,
            timeout: 300,
            tasks: vec![],
        };

        let provider = create_provider(&config).unwrap();
        assert_eq!(provider.name(), "anthropic");
    }

    #[test]
    fn test_mock_ai_complete() {
        let provider = MockAiProvider::with_response("Use FROM node:lts-alpine");
        let result = provider
            .complete("optimize dockerfile", "system context")
            .unwrap();
        assert!(result.contains("node:lts-alpine"));
    }

    #[test]
    fn test_ai_build_prompt_for_dockerfile() {
        let ctx = PromptContext {
            project_type: Some(AppType::Node),
            files: vec!["package.json".to_string(), "src/index.ts".to_string()],
            error_log: None,
            current_config: None,
        };

        let (system, prompt) = build_dockerfile_prompt(&ctx);
        assert!(system.contains("DevOps"));
        assert!(prompt.contains("node"));
        assert!(prompt.contains("Dockerfile"));
        assert!(prompt.contains("package.json"));
    }

    #[test]
    fn test_ai_build_prompt_for_troubleshoot() {
        let ctx = PromptContext {
            project_type: None,
            files: vec![],
            error_log: Some("connection refused on port 5432".to_string()),
            current_config: None,
        };

        let (_, prompt) = build_troubleshoot_prompt(&ctx);
        assert!(prompt.contains("connection refused"));
        assert!(prompt.contains("Diagnose"));
    }

    #[test]
    fn test_ai_not_configured_returns_error() {
        let config = AiConfig {
            enabled: false,
            ..Default::default()
        };

        let result = create_provider(&config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        match err {
            CliError::AiNotConfigured => {} // expected
            other => panic!("Expected AiNotConfigured, got: {:?}", other),
        }
    }

    // ── Additional tests ────────────────────────────

    #[test]
    fn test_openai_requires_api_key() {
        let config = AiConfig {
            enabled: true,
            provider: AiProviderType::Openai,
            api_key: None,
            ..Default::default()
        };

        let result = create_provider(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_anthropic_requires_api_key() {
        let config = AiConfig {
            enabled: true,
            provider: AiProviderType::Anthropic,
            api_key: None,
            ..Default::default()
        };

        let result = create_provider(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_ollama_no_api_key_needed() {
        let config = AiConfig {
            enabled: true,
            provider: AiProviderType::Ollama,
            api_key: None,
            ..Default::default()
        };

        let provider = create_provider(&config).unwrap();
        assert_eq!(provider.name(), "ollama");
    }

    #[test]
    fn test_custom_provider_uses_openai_compat() {
        let config = AiConfig {
            enabled: true,
            provider: AiProviderType::Custom,
            api_key: Some("custom-key".to_string()),
            endpoint: Some("https://my-llm.local/v1/chat/completions".to_string()),
            model: Some("my-model".to_string()),
            timeout: 300,
            tasks: vec![],
        };

        let provider = create_provider(&config).unwrap();
        // Custom uses OpenAI-compatible protocol
        assert_eq!(provider.name(), "openai");
    }

    #[test]
    fn test_default_models() {
        assert_eq!(default_model(AiProviderType::Openai), "gpt-4o");
        assert_eq!(default_model(AiProviderType::Ollama), "llama3");
        assert!(default_model(AiProviderType::Anthropic).contains("claude"));
    }

    #[test]
    fn test_build_compose_prompt() {
        let ctx = PromptContext {
            project_type: Some(AppType::Python),
            files: vec![],
            error_log: None,
            current_config: Some(
                "version: '3'\nservices:\n  web:\n    image: python:3.11".to_string(),
            ),
        };

        let (_, prompt) = build_compose_prompt(&ctx);
        assert!(prompt.contains("python"));
        assert!(prompt.contains("docker-compose.yml"));
        assert!(prompt.contains("python:3.11"));
    }

    #[test]
    fn test_build_prompt_dispatches_correctly() {
        let ctx = PromptContext {
            project_type: Some(AppType::Rust),
            files: vec!["Cargo.toml".to_string()],
            ..Default::default()
        };

        let (_, dockerfile_prompt) = build_prompt(AiTask::Dockerfile, &ctx);
        assert!(dockerfile_prompt.contains("rust"));

        let (_, compose_prompt) = build_prompt(AiTask::Compose, &ctx);
        assert!(compose_prompt.contains("docker-compose"));

        let troubleshoot_ctx = PromptContext {
            error_log: Some("exit code 1".to_string()),
            ..Default::default()
        };
        let (_, troubleshoot_prompt) = build_prompt(AiTask::Troubleshoot, &troubleshoot_ctx);
        assert!(troubleshoot_prompt.contains("exit code 1"));
    }

    #[test]
    fn test_ai_task_as_str() {
        assert_eq!(AiTask::Dockerfile.as_str(), "dockerfile");
        assert_eq!(AiTask::Compose.as_str(), "compose");
        assert_eq!(AiTask::Troubleshoot.as_str(), "troubleshoot");
        assert_eq!(AiTask::Optimize.as_str(), "optimize");
    }

    #[test]
    fn test_openai_provider_from_config_defaults() {
        let config = AiConfig {
            enabled: true,
            provider: AiProviderType::Openai,
            api_key: Some("sk-test".to_string()),
            model: None,
            endpoint: None,
            timeout: 300,
            tasks: vec![],
        };

        let provider = OpenAiProvider::from_config(&config).unwrap();
        assert_eq!(provider.endpoint, OPENAI_API_URL);
        assert_eq!(provider.model, "gpt-4o");
    }

    #[test]
    fn test_ollama_provider_from_config_defaults() {
        let config = AiConfig {
            enabled: true,
            provider: AiProviderType::Ollama,
            ..Default::default()
        };

        let provider = OllamaProvider::from_config(&config);
        assert_eq!(provider.endpoint, OLLAMA_API_URL);
        // Model is either auto-detected from running Ollama or falls back to default
        assert!(!provider.model.is_empty(), "model must not be empty");
    }

    #[test]
    fn test_ollama_provider_from_config_explicit_model() {
        // Use unreachable endpoint so list_ollama_models returns empty,
        // meaning the configured model is used as-is (no validation possible).
        let config = AiConfig {
            enabled: true,
            provider: AiProviderType::Ollama,
            model: Some("custom-model".to_string()),
            endpoint: Some("http://127.0.0.1:1/api/chat".to_string()),
            ..Default::default()
        };

        let provider = OllamaProvider::from_config(&config);
        assert_eq!(provider.model, "custom-model");
    }

    #[test]
    fn test_ollama_provider_autodetects_when_model_missing() {
        // With Ollama running and a model that doesn't exist, auto-detection
        // should kick in and pick an available model.
        let config = AiConfig {
            enabled: true,
            provider: AiProviderType::Ollama,
            model: Some("nonexistent-model-xyz".to_string()),
            ..Default::default()
        };

        let provider = OllamaProvider::from_config(&config);
        // If Ollama is running, model is auto-detected; if not, original is kept
        assert!(!provider.model.is_empty());
    }

    #[test]
    fn test_prompt_context_default() {
        let ctx = PromptContext::default();
        assert!(ctx.project_type.is_none());
        assert!(ctx.files.is_empty());
        assert!(ctx.error_log.is_none());
        assert!(ctx.current_config.is_none());
    }

    // ── Timeout resolution tests ────────────────
    //
    // These tests mutate the `STACKER_AI_TIMEOUT` env var, which is a
    // process-global resource. They must not run concurrently with each other
    // to avoid flaky results. A single static mutex serialises access.
    static TIMEOUT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_resolve_timeout_uses_config_value() {
        let _guard = TIMEOUT_ENV_LOCK.lock().unwrap();
        std::env::remove_var("STACKER_AI_TIMEOUT");
        assert_eq!(resolve_timeout(600), 600);
        assert_eq!(resolve_timeout(30), 30);
    }

    #[test]
    fn test_resolve_timeout_default_fallback() {
        let _guard = TIMEOUT_ENV_LOCK.lock().unwrap();
        std::env::remove_var("STACKER_AI_TIMEOUT");
        // 0 means "use default"
        assert_eq!(resolve_timeout(0), DEFAULT_AI_TIMEOUT_SECS);
    }

    #[test]
    fn test_resolve_timeout_env_overrides_config() {
        let _guard = TIMEOUT_ENV_LOCK.lock().unwrap();
        std::env::set_var("STACKER_AI_TIMEOUT", "900");
        assert_eq!(resolve_timeout(300), 900);
        std::env::remove_var("STACKER_AI_TIMEOUT");
    }

    #[test]
    fn test_resolve_timeout_env_invalid_ignored() {
        let _guard = TIMEOUT_ENV_LOCK.lock().unwrap();
        std::env::set_var("STACKER_AI_TIMEOUT", "not-a-number");
        assert_eq!(resolve_timeout(120), 120);
        std::env::remove_var("STACKER_AI_TIMEOUT");
    }

    #[test]
    fn test_provider_timeout_from_config() {
        let _guard = TIMEOUT_ENV_LOCK.lock().unwrap();
        std::env::remove_var("STACKER_AI_TIMEOUT");
        let config = AiConfig {
            enabled: true,
            provider: AiProviderType::Ollama,
            timeout: 600,
            ..Default::default()
        };
        let provider = OllamaProvider::from_config(&config);
        assert_eq!(provider.timeout_secs, 600);
    }

    #[test]
    fn test_openai_provider_timeout_from_config() {
        let _guard = TIMEOUT_ENV_LOCK.lock().unwrap();
        std::env::remove_var("STACKER_AI_TIMEOUT");
        let config = AiConfig {
            enabled: true,
            provider: AiProviderType::Openai,
            api_key: Some("sk-test".to_string()),
            timeout: 120,
            ..Default::default()
        };
        let provider = OpenAiProvider::from_config(&config).unwrap();
        assert_eq!(provider.timeout_secs, 120);
    }
}
