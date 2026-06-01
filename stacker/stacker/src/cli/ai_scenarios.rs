use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::cli::config_parser::{AiConfig, AiProviderType, AppType, StackerConfig};
use crate::cli::error::CliError;

pub const WEBSITE_DEPLOY_SCENARIO: &str = "website-deploy";
const SCENARIO_PROVIDER_DIR: &str = "qwen2.5-code";

const WEBSITE_DEPLOY_MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scenarios/qwen2.5-code/website-deploy/scenario.yaml"
));
const WEBSITE_DEPLOY_STEP_INIT_VALIDATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scenarios/qwen2.5-code/website-deploy/steps/01-init-validate.md"
));
const WEBSITE_DEPLOY_STEP_IMAGE_PUBLISH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scenarios/qwen2.5-code/website-deploy/steps/02-image-publish.md"
));
const WEBSITE_DEPLOY_STEP_CLOUD_DEPLOY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scenarios/qwen2.5-code/website-deploy/steps/03-cloud-deploy.md"
));
const WEBSITE_DEPLOY_STEP_AGENT_PROXY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scenarios/qwen2.5-code/website-deploy/steps/04-agent-firewall-dns-proxy.md"
));
const WEBSITE_DEPLOY_STEP_RUNTIME_OPS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scenarios/qwen2.5-code/website-deploy/steps/05-runtime-ops.md"
));

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioSelection {
    pub name: String,
    pub step: Option<String>,
}

impl ScenarioSelection {
    pub fn new(name: impl Into<String>, step: Option<String>) -> Self {
        Self {
            name: name.into(),
            step,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioManifest {
    pub name: String,
    pub description: String,
    pub model_match: ScenarioModelMatch,
    pub trigger_conditions: ScenarioTriggerConditions,
    pub default_step: String,
    pub required_vars: Vec<String>,
    pub transcript_rules: ScenarioTranscriptRules,
    pub safety_rules: Vec<String>,
    pub steps: Vec<ScenarioStep>,
}

impl ScenarioManifest {
    pub fn step(&self, step_id: &str) -> Option<&ScenarioStep> {
        self.steps.iter().find(|step| step.id == step_id)
    }

    pub fn next_step_after(&self, step_id: &str) -> Option<String> {
        let index = self.steps.iter().position(|step| step.id == step_id)?;
        self.steps.get(index + 1).map(|step| step.id.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioModelMatch {
    pub provider: String,
    pub name_contains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioTriggerConditions {
    pub app_types: Vec<String>,
    pub website_kinds: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioTranscriptRules {
    pub default_path: String,
    pub update_existing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioStep {
    pub id: String,
    pub title: String,
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioState {
    pub scenario_name: String,
    pub current_step: String,
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
}

impl ScenarioState {
    pub fn new(scenario_name: impl Into<String>, current_step: impl Into<String>) -> Self {
        Self {
            scenario_name: scenario_name.into(),
            current_step: current_step.into(),
            vars: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebsiteProjectKind {
    Html,
    NextJs,
}

impl WebsiteProjectKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::NextJs => "nextjs",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Html => "HTML/static website",
            Self::NextJs => "Next.js website",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScenarioPromptContext {
    pub manifest: ScenarioManifest,
    pub step_id: String,
    pub step_title: String,
    pub next_step_id: Option<String>,
    pub rendered_prompt: String,
    pub state: Option<ScenarioState>,
}

pub fn is_qwen_website_scenario_model(ai_config: &AiConfig) -> bool {
    if ai_config.provider != AiProviderType::Ollama {
        return false;
    }

    ai_config
        .model
        .as_deref()
        .map(|model| {
            let normalized = model.to_ascii_lowercase();
            normalized.contains("qwen2.5-code") || normalized.contains("qwen2.5-coder")
        })
        .unwrap_or(false)
}

pub fn detect_website_project_kind(
    project_dir: &Path,
    config: &StackerConfig,
) -> Option<WebsiteProjectKind> {
    match config.app.app_type {
        AppType::Static => Some(WebsiteProjectKind::Html),
        AppType::Node => {
            if has_nextjs_markers(project_dir) {
                Some(WebsiteProjectKind::NextJs)
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn load_scenario_manifest(
    project_dir: &Path,
    scenario_name: &str,
) -> Result<ScenarioManifest, CliError> {
    let local_manifest_path = local_scenario_dir(project_dir, scenario_name).join("scenario.yaml");
    let manifest_text = if local_manifest_path.exists() {
        std::fs::read_to_string(&local_manifest_path)?
    } else {
        builtin_manifest_text(scenario_name)?.to_string()
    };

    serde_yaml::from_str(&manifest_text).map_err(|error| {
        CliError::ConfigValidation(format!(
            "Failed to parse AI scenario manifest '{}': {}",
            scenario_name, error
        ))
    })
}

pub fn missing_required_vars(manifest: &ScenarioManifest, state: &ScenarioState) -> Vec<String> {
    manifest
        .required_vars
        .iter()
        .filter(|key| {
            state
                .vars
                .get((*key).as_str())
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
        })
        .cloned()
        .collect()
}

pub fn scenario_state_path(project_dir: &Path, scenario_name: &str) -> PathBuf {
    local_scenario_dir(project_dir, scenario_name).join("state.json")
}

pub fn load_scenario_state(
    project_dir: &Path,
    scenario_name: &str,
) -> Result<Option<ScenarioState>, CliError> {
    let state_path = scenario_state_path(project_dir, scenario_name);
    if !state_path.exists() {
        return Ok(None);
    }

    let contents = std::fs::read_to_string(&state_path)?;
    let state = serde_json::from_str(&contents).map_err(|error| {
        CliError::ConfigValidation(format!(
            "Failed to parse AI scenario state '{}': {}",
            state_path.display(),
            error
        ))
    })?;

    Ok(Some(state))
}

pub fn save_scenario_state(project_dir: &Path, state: &ScenarioState) -> Result<PathBuf, CliError> {
    let state_path = scenario_state_path(project_dir, &state.scenario_name);
    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let content = serde_json::to_string_pretty(state).map_err(|error| {
        CliError::ConfigValidation(format!("Failed to serialize AI scenario state: {}", error))
    })?;
    std::fs::write(&state_path, content)?;

    Ok(state_path)
}

pub fn seed_website_scenario_state(
    project_dir: &Path,
    config_path: &Path,
    config: &StackerConfig,
    ai_config: &AiConfig,
    project_kind: &WebsiteProjectKind,
) -> ScenarioState {
    let mut state = ScenarioState::new(WEBSITE_DEPLOY_SCENARIO, "init-validate");

    insert_var(&mut state.vars, "project_name", Some(config.name.clone()));
    insert_var(
        &mut state.vars,
        "project_identity",
        config.project.identity.clone(),
    );
    insert_var(
        &mut state.vars,
        "project_kind",
        Some(project_kind.display_name().to_string()),
    );
    insert_var(
        &mut state.vars,
        "app_type",
        Some(config.app.app_type.to_string()),
    );
    insert_var(
        &mut state.vars,
        "app_path",
        Some(config.app.path.to_string_lossy().to_string()),
    );
    insert_var(
        &mut state.vars,
        "config_path",
        Some(
            config_path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| "stacker.yml".to_string()),
        ),
    );
    insert_var(
        &mut state.vars,
        "compose_file",
        config
            .deploy
            .compose_file
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
    );
    insert_var(
        &mut state.vars,
        "proxy_type",
        (config.proxy.proxy_type != crate::cli::config_parser::ProxyType::None)
            .then(|| config.proxy.proxy_type.to_string()),
    );
    insert_var(
        &mut state.vars,
        "status_panel_enabled",
        Some(config.monitoring.status_panel.to_string()),
    );
    insert_var(
        &mut state.vars,
        "ai_provider",
        Some(ai_config.provider.to_string()),
    );
    insert_var(&mut state.vars, "ai_model", ai_config.model.clone());
    insert_var(&mut state.vars, "ai_endpoint", ai_config.endpoint.clone());
    insert_var(
        &mut state.vars,
        "repo_url",
        detect_git_remote_url(project_dir),
    );

    if let Some(domain) = primary_public_domain(config) {
        insert_var(&mut state.vars, "public_domain", Some(domain));
    }

    if let Some(image) = &config.app.image {
        let (repository, tag) = split_image_reference(image);
        insert_var(&mut state.vars, "image_repository", Some(repository));
        insert_var(&mut state.vars, "image_tag", tag);
    } else if let Some(repo_url) = state.vars.get("repo_url").cloned() {
        insert_var(
            &mut state.vars,
            "image_repository",
            derive_image_repository_from_repo_url(&repo_url),
        );
    }

    if let Some(cloud) = &config.deploy.cloud {
        insert_var(
            &mut state.vars,
            "cloud_provider",
            Some(cloud.provider.to_string()),
        );
        insert_var(&mut state.vars, "cloud_region", cloud.region.clone());
        insert_var(&mut state.vars, "cloud_size", cloud.size.clone());
    }

    state
}

pub fn load_scenario_prompt_context(
    project_dir: &Path,
    ai_config: &AiConfig,
    selection: &ScenarioSelection,
) -> Result<ScenarioPromptContext, CliError> {
    let manifest = load_scenario_manifest(project_dir, &selection.name)?;
    ensure_model_matches(ai_config, &manifest)?;

    let state = load_scenario_state(project_dir, &selection.name)?;
    let step_id = selection
        .step
        .clone()
        .or_else(|| {
            state
                .as_ref()
                .map(|saved| saved.current_step.clone())
                .filter(|step| !step.trim().is_empty())
        })
        .unwrap_or_else(|| manifest.default_step.clone());
    let step = manifest.step(&step_id).cloned().ok_or_else(|| {
        CliError::ConfigValidation(format!(
            "Unknown AI scenario step '{}' for scenario '{}'",
            step_id, manifest.name
        ))
    })?;
    let step_markdown = load_step_markdown(project_dir, &manifest, &step)?;
    let vars_yaml = state
        .as_ref()
        .map(|saved| scenario_vars_yaml(&saved.vars))
        .unwrap_or_else(|| "(none saved yet)".to_string());
    let next_step_id = manifest.next_step_after(&step_id);
    let safety_rules = manifest
        .safety_rules
        .iter()
        .map(|rule| format!("- {}", rule))
        .collect::<Vec<_>>()
        .join("\n");
    let rendered_prompt = format!(
        "## Active deployment scenario\n\
Scenario: {scenario}\n\
Description: {description}\n\
Current step: {step_id} — {step_title}\n\
Next step hint: {next_step}\n\
Transcript path: {transcript}\n\
\n\
Scenario variables:\n\
```yaml\n\
{vars_yaml}\n\
```\n\
\n\
Safety rules:\n\
{safety_rules}\n\
\n\
Step instructions:\n\
{step_markdown}",
        scenario = manifest.name,
        description = manifest.description,
        step_id = step.id,
        step_title = step.title,
        next_step = next_step_id
            .clone()
            .unwrap_or_else(|| "(this is the final built-in step)".to_string()),
        transcript = manifest.transcript_rules.default_path,
    );

    Ok(ScenarioPromptContext {
        manifest,
        step_id,
        step_title: step.title.clone(),
        next_step_id,
        rendered_prompt,
        state,
    })
}

pub fn next_step_id(
    project_dir: &Path,
    scenario_name: &str,
    current_step: &str,
) -> Result<Option<String>, CliError> {
    let manifest = load_scenario_manifest(project_dir, scenario_name)?;
    Ok(manifest.next_step_after(current_step))
}

fn ensure_model_matches(ai_config: &AiConfig, manifest: &ScenarioManifest) -> Result<(), CliError> {
    let provider_matches = ai_config.provider.to_string() == manifest.model_match.provider;
    let model_matches = ai_config
        .model
        .as_deref()
        .map(|model| {
            let normalized = model.to_ascii_lowercase();
            manifest
                .model_match
                .name_contains
                .iter()
                .any(|needle| normalized.contains(&needle.to_ascii_lowercase()))
        })
        .unwrap_or(false);

    if provider_matches && model_matches {
        Ok(())
    } else {
        Err(CliError::ConfigValidation(format!(
            "Scenario '{}' requires {} models containing one of: {}",
            manifest.name,
            manifest.model_match.provider,
            manifest.model_match.name_contains.join(", ")
        )))
    }
}

fn has_nextjs_markers(project_dir: &Path) -> bool {
    let direct_markers = [
        "next.config.js",
        "next.config.mjs",
        "next.config.ts",
        "src/app/page.tsx",
        "src/app/page.jsx",
        "src/pages/index.tsx",
        "src/pages/index.jsx",
        "pages/index.tsx",
        "pages/index.jsx",
    ];
    if direct_markers
        .iter()
        .any(|path| project_dir.join(path).exists())
    {
        return true;
    }

    let package_json_path = project_dir.join("package.json");
    let package_json = match std::fs::read_to_string(package_json_path) {
        Ok(content) => content,
        Err(_) => return false,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&package_json) {
        Ok(value) => value,
        Err(_) => return false,
    };

    let has_next_dependency = parsed["dependencies"].get("next").is_some()
        || parsed["devDependencies"].get("next").is_some();
    let has_next_script = parsed["scripts"]
        .as_object()
        .map(|scripts| {
            scripts.values().any(|value| {
                value
                    .as_str()
                    .map(|script| script.contains("next "))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    has_next_dependency || has_next_script
}

fn local_scenario_dir(project_dir: &Path, scenario_name: &str) -> PathBuf {
    project_dir
        .join(".stacker")
        .join("scenarios")
        .join(SCENARIO_PROVIDER_DIR)
        .join(scenario_name)
}

fn builtin_manifest_text(scenario_name: &str) -> Result<&'static str, CliError> {
    match scenario_name {
        WEBSITE_DEPLOY_SCENARIO => Ok(WEBSITE_DEPLOY_MANIFEST),
        other => Err(CliError::ConfigValidation(format!(
            "Unknown built-in AI scenario '{}'",
            other
        ))),
    }
}

fn builtin_step_markdown(scenario_name: &str, file: &str) -> Result<&'static str, CliError> {
    match (scenario_name, file) {
        (WEBSITE_DEPLOY_SCENARIO, "steps/01-init-validate.md") => {
            Ok(WEBSITE_DEPLOY_STEP_INIT_VALIDATE)
        }
        (WEBSITE_DEPLOY_SCENARIO, "steps/02-image-publish.md") => {
            Ok(WEBSITE_DEPLOY_STEP_IMAGE_PUBLISH)
        }
        (WEBSITE_DEPLOY_SCENARIO, "steps/03-cloud-deploy.md") => {
            Ok(WEBSITE_DEPLOY_STEP_CLOUD_DEPLOY)
        }
        (WEBSITE_DEPLOY_SCENARIO, "steps/04-agent-firewall-dns-proxy.md") => {
            Ok(WEBSITE_DEPLOY_STEP_AGENT_PROXY)
        }
        (WEBSITE_DEPLOY_SCENARIO, "steps/05-runtime-ops.md") => Ok(WEBSITE_DEPLOY_STEP_RUNTIME_OPS),
        _ => Err(CliError::ConfigValidation(format!(
            "Unknown built-in AI scenario step file '{}'",
            file
        ))),
    }
}

fn load_step_markdown(
    project_dir: &Path,
    manifest: &ScenarioManifest,
    step: &ScenarioStep,
) -> Result<String, CliError> {
    let local_path = local_scenario_dir(project_dir, &manifest.name).join(&step.file);
    if local_path.exists() {
        return Ok(std::fs::read_to_string(local_path)?);
    }

    Ok(builtin_step_markdown(&manifest.name, &step.file)?.to_string())
}

fn insert_var(vars: &mut BTreeMap<String, String>, key: &str, value: Option<String>) {
    if let Some(value) = value.map(|value| value.trim().to_string()) {
        if !value.is_empty() {
            vars.insert(key.to_string(), value);
        }
    }
}

fn scenario_vars_yaml(vars: &BTreeMap<String, String>) -> String {
    if vars.is_empty() {
        return "(none saved yet)".to_string();
    }

    serde_yaml::to_string(vars)
        .unwrap_or_else(|_| "(failed to render variables)".to_string())
        .trim()
        .to_string()
}

fn detect_git_remote_url(project_dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["config", "--get", "remote.origin.url"])
        .current_dir(project_dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let remote = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!remote.is_empty()).then_some(remote)
}

fn primary_public_domain(config: &StackerConfig) -> Option<String> {
    config
        .proxy
        .domains
        .iter()
        .map(|domain| domain.domain.trim())
        .find(|domain| !domain.is_empty() && !is_placeholder_domain(domain))
        .map(ToOwned::to_owned)
}

fn is_placeholder_domain(domain: &str) -> bool {
    domain.ends_with(".localhost") || domain.contains("example.com")
}

fn derive_image_repository_from_repo_url(repo_url: &str) -> Option<String> {
    let remote = repo_url.trim().trim_end_matches(".git");
    let path = if let Some(path) = remote.strip_prefix("git@github.com:") {
        path
    } else if let Some(path) = remote.strip_prefix("https://github.com/") {
        path
    } else if let Some(path) = remote.strip_prefix("ssh://git@github.com/") {
        path
    } else {
        return None;
    };

    let mut segments = path.split('/');
    let owner = segments.next()?.trim();
    let repo = segments.next()?.trim();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }

    Some(format!("ghcr.io/{owner}/{repo}"))
}

fn split_image_reference(image: &str) -> (String, Option<String>) {
    let last_slash = image.rfind('/');
    let last_colon = image.rfind(':');
    if let Some(colon_index) = last_colon {
        if last_slash.map(|slash| colon_index > slash).unwrap_or(true) {
            let repository = image[..colon_index].to_string();
            let tag = image[colon_index + 1..].trim().to_string();
            return (repository, (!tag.is_empty()).then_some(tag));
        }
    }

    (image.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::config_parser::{AiProviderType, ProxyType};

    fn website_ai_config(model: &str) -> AiConfig {
        AiConfig {
            enabled: true,
            provider: AiProviderType::Ollama,
            model: Some(model.to_string()),
            api_key: None,
            endpoint: Some("http://localhost:11434".to_string()),
            timeout: 300,
            tasks: vec![],
        }
    }

    #[test]
    fn test_detect_html_website_candidate() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html></html>").unwrap();

        let mut config = StackerConfig::default();
        config.app.app_type = AppType::Static;

        assert_eq!(
            detect_website_project_kind(dir.path(), &config),
            Some(WebsiteProjectKind::Html)
        );
    }

    #[test]
    fn test_detect_nextjs_website_candidate() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"next":"15.0.0"}}"#,
        )
        .unwrap();

        let mut config = StackerConfig::default();
        config.app.app_type = AppType::Node;

        assert_eq!(
            detect_website_project_kind(dir.path(), &config),
            Some(WebsiteProjectKind::NextJs)
        );
    }

    #[test]
    fn test_seed_website_scenario_state_derives_repo_image_and_cloud_values() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();

        let mut config = StackerConfig::default();
        config.name = "status-web".to_string();
        config.app.app_type = AppType::Static;
        config.proxy.proxy_type = ProxyType::Nginx;
        config
            .proxy
            .domains
            .push(crate::cli::config_parser::DomainConfig {
                domain: "status.try.direct".to_string(),
                ssl: crate::cli::config_parser::SslMode::Auto,
                upstream: "app:80".to_string(),
            });
        config.deploy.cloud = Some(crate::cli::config_parser::CloudConfig {
            provider: crate::cli::config_parser::CloudProvider::Hetzner,
            orchestrator: crate::cli::config_parser::CloudOrchestrator::Remote,
            region: Some("nbg1".to_string()),
            size: Some("cpx11".to_string()),
            install_image: None,
            remote_payload_file: None,
            ssh_key: None,
            key: None,
            server: None,
        });

        // Simulate a git remote through an existing state seed instead of shelling out in tests.
        let ai_config = website_ai_config("qwen2.5-coder:latest");
        let mut state = seed_website_scenario_state(
            dir.path(),
            &dir.path().join("stacker.yml"),
            &config,
            &ai_config,
            &WebsiteProjectKind::Html,
        );
        state.vars.insert(
            "repo_url".to_string(),
            "https://github.com/trydirect/status-web.git".to_string(),
        );
        if !state.vars.contains_key("image_repository") {
            state.vars.insert(
                "image_repository".to_string(),
                derive_image_repository_from_repo_url(state.vars.get("repo_url").unwrap()).unwrap(),
            );
        }

        assert_eq!(
            state.vars.get("project_name").map(String::as_str),
            Some("status-web")
        );
        assert_eq!(
            state.vars.get("public_domain").map(String::as_str),
            Some("status.try.direct")
        );
        assert_eq!(
            state.vars.get("cloud_provider").map(String::as_str),
            Some("hetzner")
        );
        assert_eq!(
            state.vars.get("cloud_region").map(String::as_str),
            Some("nbg1")
        );
        assert_eq!(
            state.vars.get("image_repository").map(String::as_str),
            Some("ghcr.io/trydirect/status-web")
        );
    }

    #[test]
    fn test_load_scenario_prompt_context_uses_local_override_step() {
        let dir = tempfile::TempDir::new().unwrap();
        let scenario_dir = local_scenario_dir(dir.path(), WEBSITE_DEPLOY_SCENARIO);
        std::fs::create_dir_all(scenario_dir.join("steps")).unwrap();
        std::fs::write(
            scenario_dir.join("steps/01-init-validate.md"),
            "Local override step content",
        )
        .unwrap();
        save_scenario_state(
            dir.path(),
            &ScenarioState::new(WEBSITE_DEPLOY_SCENARIO, "init-validate"),
        )
        .unwrap();

        let context = load_scenario_prompt_context(
            dir.path(),
            &website_ai_config("qwen2.5-code:latest"),
            &ScenarioSelection::new(WEBSITE_DEPLOY_SCENARIO, Some("init-validate".to_string())),
        )
        .unwrap();

        assert!(context
            .rendered_prompt
            .contains("Local override step content"));
        assert_eq!(context.step_id, "init-validate");
    }

    #[test]
    fn test_missing_required_vars_reports_absent_values() {
        let manifest = load_scenario_manifest(Path::new("."), WEBSITE_DEPLOY_SCENARIO).unwrap();
        let mut state = ScenarioState::new(WEBSITE_DEPLOY_SCENARIO, "init-validate");
        state
            .vars
            .insert("image_tag".to_string(), "latest".to_string());

        let missing = missing_required_vars(&manifest, &state);
        assert!(missing.contains(&"public_domain".to_string()));
        assert!(!missing.contains(&"image_tag".to_string()));
    }
}
