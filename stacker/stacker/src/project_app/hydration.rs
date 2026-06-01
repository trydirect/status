pub use hydrate::{
    hydrate_project_app, hydrate_single_app, redact_app_environment, HydratedProjectApp,
};

mod hydrate {
    use actix_web::Error;
    use serde_json::{json, Value};
    use sqlx::PgPool;

    use crate::db;
    use crate::helpers::JsonResponse;
    use crate::models::{Project, ProjectApp};
    use crate::services::{AppConfig, ProjectAppService, VaultError, VaultService};

    #[derive(Debug, Clone, serde::Serialize)]
    pub struct ConfigFile {
        pub name: String,
        pub content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub template_path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub destination_path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub file_mode: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub group: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_ansible: Option<bool>,
    }

    #[derive(Debug, Clone, serde::Serialize)]
    pub struct HydratedProjectApp {
        pub id: i32,
        pub project_id: i32,
        pub code: String,
        pub name: String,
        pub image: String,
        pub environment: Value,
        pub ports: Value,
        pub volumes: Value,
        pub domain: Option<String>,
        pub ssl_enabled: bool,
        pub resources: Value,
        pub restart_policy: String,
        pub command: Option<String>,
        pub entrypoint: Option<String>,
        pub networks: Value,
        pub depends_on: Value,
        pub healthcheck: Value,
        pub labels: Value,
        pub config_files: Vec<ConfigFile>,
        pub compose: Option<String>,
        pub template_source: Option<String>,
        pub enabled: bool,
        pub deploy_order: Option<i32>,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
        pub parent_app_code: Option<String>,
    }

    impl HydratedProjectApp {
        fn from_project_app(app: ProjectApp) -> Self {
            Self {
                id: app.id,
                project_id: app.project_id,
                code: app.code,
                name: app.name,
                image: app.image,
                environment: app.environment.unwrap_or(json!({})),
                ports: app.ports.unwrap_or(json!([])),
                volumes: app.volumes.unwrap_or(json!([])),
                domain: app.domain,
                ssl_enabled: app.ssl_enabled.unwrap_or(false),
                resources: app.resources.unwrap_or(json!({})),
                restart_policy: app
                    .restart_policy
                    .unwrap_or_else(|| "unless-stopped".to_string()),
                command: app.command,
                entrypoint: app.entrypoint,
                networks: app.networks.unwrap_or(json!([])),
                depends_on: app.depends_on.unwrap_or(json!([])),
                healthcheck: app.healthcheck.unwrap_or(json!({})),
                labels: app.labels.unwrap_or(json!({})),
                config_files: Vec::new(),
                compose: None,
                template_source: app.template_source,
                enabled: app.enabled.unwrap_or(true),
                deploy_order: app.deploy_order,
                created_at: app.created_at,
                updated_at: app.updated_at,
                parent_app_code: app.parent_app_code,
            }
        }
    }

    pub async fn hydrate_project_app(
        pool: &PgPool,
        project: &Project,
        app: ProjectApp,
    ) -> Result<HydratedProjectApp, Error> {
        hydrate_single_app(pool, project, app).await
    }

    pub async fn hydrate_single_app(
        pool: &PgPool,
        project: &Project,
        app: ProjectApp,
    ) -> Result<HydratedProjectApp, Error> {
        let mut hydrated = HydratedProjectApp::from_project_app(app.clone());
        let mut compose_config: Option<AppConfig> = None;
        let mut env_config: Option<AppConfig> = None;

        if !hydrated.networks.is_array()
            || hydrated
                .networks
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(true)
        {
            hydrated.networks = json!([]);
        }

        if let Some(default_network) = ProjectAppService::default_network_from_project(project) {
            if hydrated
                .networks
                .as_array()
                .map(|arr| arr.is_empty())
                .unwrap_or(true)
            {
                hydrated.networks = json!([default_network]);
            }
        }

        let deployment_hash = project
            .request_json
            .get("report")
            .and_then(|r| r.get("deployment_hash"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if let Some(hash) = deployment_hash {
            if let Ok(vault) = VaultService::from_env() {
                if let Some(vault) = vault {
                    if let Some(compose) = fetch_optional_config(&vault, &hash, &app.code).await? {
                        hydrated.compose = Some(compose.content.clone());
                        compose_config = Some(compose);
                    }

                    if let Some(config) =
                        fetch_optional_config(&vault, &hash, &format!("{}_env", app.code)).await?
                    {
                        hydrated.environment = parse_env_to_json(&config.content);
                        env_config = Some(config);
                    }

                    if let Some(config_bundle) =
                        fetch_optional_config(&vault, &hash, &format!("{}_configs", app.code))
                            .await?
                    {
                        hydrated.config_files = parse_config_bundle(&config_bundle.content);
                    }
                }
            }
        }

        if hydrated.config_files.is_empty() {
            if let Some(config_files) = app.config_files.and_then(|c| c.as_array().cloned()) {
                hydrated.config_files = config_files
                    .into_iter()
                    .filter_map(|file| {
                        let name = file.get("name").and_then(|v| v.as_str())?.to_string();
                        let content = file.get("content").and_then(|v| v.as_str())?.to_string();
                        Some(ConfigFile {
                            name,
                            content,
                            template_path: file
                                .get("template_path")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            destination_path: file
                                .get("destination_path")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            file_mode: file
                                .get("file_mode")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            owner: file
                                .get("owner")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            group: file
                                .get("group")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            is_ansible: file.get("is_ansible").and_then(|v| v.as_bool()),
                        })
                    })
                    .collect();
            }
        }

        if let Some(config) = env_config {
            let env_name = file_name_from_path(&config.destination_path, ".env");
            push_config_file_if_missing(&mut hydrated.config_files, &env_name, &config);
        }

        if let Some(config) = compose_config {
            let compose_name = file_name_from_path(&config.destination_path, "docker-compose.yml");
            push_config_file_if_missing(&mut hydrated.config_files, &compose_name, &config);
        }

        hydrated.environment = redact_app_environment(
            pool,
            &project.user_id,
            project.id,
            &app.code,
            hydrated.environment,
        )
        .await
        .map_err(JsonResponse::internal_server_error)?;

        Ok(hydrated)
    }

    pub async fn redact_app_environment(
        pool: &PgPool,
        user_id: &str,
        project_id: i32,
        app_code: &str,
        env: Value,
    ) -> Result<Value, String> {
        let mut redacted = redact_sensitive_env_vars(env);
        let service_secrets =
            db::remote_secret::list_service_secrets(pool, user_id, project_id, app_code).await?;

        if service_secrets.is_empty() {
            return Ok(redacted);
        }

        if !redacted.is_object() {
            redacted = normalize_environment(redacted);
        }

        let object = redacted
            .as_object_mut()
            .ok_or_else(|| "App environment must be a JSON object".to_string())?;

        for secret in service_secrets {
            object.insert(secret.name, Value::String("[REDACTED]".to_string()));
        }

        Ok(redacted)
    }

    async fn fetch_optional_config(
        vault: &VaultService,
        deployment_hash: &str,
        config_key: &str,
    ) -> Result<Option<AppConfig>, Error> {
        match vault.fetch_app_config(deployment_hash, config_key).await {
            Ok(config) => Ok(Some(config)),
            Err(VaultError::NotFound(_)) => Ok(None),
            Err(error) => Err(JsonResponse::internal_server_error(error.to_string())),
        }
    }

    fn file_name_from_path(path: &str, fallback: &str) -> String {
        path.rsplit('/')
            .find(|part| !part.is_empty())
            .unwrap_or(fallback)
            .to_string()
    }

    fn push_config_file_if_missing(
        config_files: &mut Vec<ConfigFile>,
        name: &str,
        config: &AppConfig,
    ) {
        if config_files.iter().any(|file| file.name == name) {
            return;
        }

        let destination_path = if config.destination_path.is_empty() {
            None
        } else {
            Some(config.destination_path.clone())
        };

        config_files.push(ConfigFile {
            name: name.to_string(),
            content: config.content.clone(),
            template_path: None,
            destination_path,
            file_mode: Some(config.file_mode.clone()),
            owner: config.owner.clone(),
            group: config.group.clone(),
            is_ansible: None,
        });
    }

    fn normalize_environment(env: Value) -> Value {
        match env {
            Value::Object(_) => env,
            Value::Array(items) => {
                let mut normalized = serde_json::Map::new();
                for item in items {
                    if let Some(pair) = item.as_str() {
                        if let Some((key, value)) = pair.split_once('=') {
                            normalized.insert(key.to_string(), Value::String(value.to_string()));
                        }
                    }
                }
                Value::Object(normalized)
            }
            other => other,
        }
    }

    fn redact_sensitive_env_vars(env: Value) -> Value {
        const SENSITIVE_PATTERNS: &[&str] = &[
            "password",
            "passwd",
            "secret",
            "token",
            "key",
            "api_key",
            "apikey",
            "auth",
            "credential",
            "private",
            "cert",
            "ssl",
            "tls",
        ];

        let normalized = normalize_environment(env);
        let Some(obj) = normalized.as_object() else {
            return normalized;
        };

        let redacted = obj
            .iter()
            .map(|(key, value)| {
                let key_lower = key.to_lowercase();
                let is_sensitive = SENSITIVE_PATTERNS
                    .iter()
                    .any(|pattern| key_lower.contains(pattern));
                if is_sensitive {
                    (key.clone(), Value::String("[REDACTED]".to_string()))
                } else {
                    (key.clone(), value.clone())
                }
            })
            .collect();

        Value::Object(redacted)
    }

    fn parse_env_to_json(content: &str) -> Value {
        let mut env_map = serde_json::Map::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                env_map.insert(
                    key.trim().to_string(),
                    Value::String(value.trim().to_string()),
                );
            } else if let Some((key, value)) = line.split_once(':') {
                env_map.insert(
                    key.trim().to_string(),
                    Value::String(value.trim().to_string()),
                );
            }
        }
        Value::Object(env_map)
    }

    fn parse_config_bundle(content: &str) -> Vec<ConfigFile> {
        if let Ok(json) = serde_json::from_str::<Vec<Value>>(content) {
            json.into_iter()
                .filter_map(|file| {
                    let name = file.get("name")?.as_str()?.to_string();
                    let content = file.get("content")?.as_str()?.to_string();
                    Some(ConfigFile {
                        name,
                        content,
                        template_path: file
                            .get("template_path")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        destination_path: file
                            .get("destination_path")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        file_mode: file
                            .get("file_mode")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        owner: file
                            .get("owner")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        group: file
                            .get("group")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        is_ansible: file.get("is_ansible").and_then(|v| v.as_bool()),
                    })
                })
                .collect()
        } else {
            Vec::new()
        }
    }
}
