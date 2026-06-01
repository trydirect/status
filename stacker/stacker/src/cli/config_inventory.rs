use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::cli::config_parser::StackerConfig;
use crate::cli::error::CliError;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConfigInventory {
    pub environment: String,
    pub targets: Vec<TargetConfigInventory>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TargetConfigInventory {
    pub target_code: String,
    pub keys: Vec<ConfigKeyInventory>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConfigKeyInventory {
    pub key: String,
    pub source: String,
    pub present: bool,
    pub secret: bool,
    pub value_hash: Option<String>,
    pub value_preview: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InventoryOptions {
    pub environment: String,
    pub service: Option<String>,
    pub show_values: bool,
}

#[derive(Debug, Clone)]
struct KeyEntry {
    value: String,
    source: String,
}

#[derive(Debug, Default)]
struct InventoryBuilder {
    targets: BTreeMap<String, BTreeMap<String, KeyEntry>>,
    warnings: Vec<String>,
}

impl InventoryBuilder {
    fn add_target(&mut self, target: &str) {
        self.targets.entry(target.to_string()).or_default();
    }

    fn add_env_map(&mut self, target: &str, source: &str, values: BTreeMap<String, String>) {
        let target_keys = self.targets.entry(target.to_string()).or_default();
        for (key, value) in values {
            target_keys.insert(
                key,
                KeyEntry {
                    value,
                    source: source.to_string(),
                },
            );
        }
    }

    fn add_entries(&mut self, target: &str, entries: BTreeMap<String, KeyEntry>) {
        self.targets
            .entry(target.to_string())
            .or_default()
            .extend(entries);
    }

    fn warn(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }
}

pub fn load_inventory(
    config_path: &Path,
    options: &InventoryOptions,
) -> Result<ConfigInventory, CliError> {
    let project_dir = config_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let config = StackerConfig::from_file(config_path)?;
    let (_, env_config) = config
        .resolve_environment_config(Some(&options.environment))?
        .ok_or_else(|| {
            CliError::ConfigValidation("environment could not be resolved".to_string())
        })?;

    let mut builder = InventoryBuilder::default();
    let mut global_entries = BTreeMap::new();

    if let Some(env_file) = env_config.env_file.as_ref() {
        let path = resolve_relative(project_dir, env_file);
        match parse_env_file(&path) {
            Ok(values) => {
                global_entries.extend(values.into_iter().map(|(key, value)| {
                    (
                        key,
                        KeyEntry {
                            value,
                            source: "stacker env_file".to_string(),
                        },
                    )
                }));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                builder.warn(format!("Missing env file: {}", path.display()));
            }
            Err(error) => return Err(error.into()),
        }
    }
    global_entries.extend(config.env.clone().into_iter().map(|(key, value)| {
        (
            key,
            KeyEntry {
                value,
                source: "stacker.yml env".to_string(),
            },
        )
    }));

    let main_target = if config.name.trim().is_empty() {
        "app".to_string()
    } else {
        config.name.clone()
    };
    if target_matches(&main_target, options.service.as_deref()) {
        builder.add_target(&main_target);
        builder.add_entries(&main_target, global_entries.clone());
        builder.add_env_map(
            &main_target,
            "stacker.yml app environment",
            config.app.environment.clone().into_iter().collect(),
        );
    }

    for service in &config.services {
        if !target_matches(&service.name, options.service.as_deref()) {
            continue;
        }
        builder.add_target(&service.name);
        builder.add_entries(&service.name, global_entries.clone());
        builder.add_env_map(
            &service.name,
            "stacker.yml service environment",
            service.environment.clone().into_iter().collect(),
        );
    }

    if let Some(compose_file) = env_config.compose_file.as_ref() {
        let compose_path = resolve_relative(project_dir, compose_file);
        load_compose_file(
            &compose_path,
            "compose",
            &global_entries,
            None,
            options.service.as_deref(),
            &mut builder,
        )?;
    }

    load_app_local_files(
        project_dir,
        &options.environment,
        options.service.as_deref(),
        &mut builder,
    )?;

    let mut targets = Vec::new();
    for (target_code, keys) in builder.targets {
        let key_entries = keys
            .into_iter()
            .map(|(key, entry)| {
                let secret = is_secret_key(&key);
                ConfigKeyInventory {
                    key,
                    source: entry.source,
                    present: true,
                    secret,
                    value_hash: Some(hash_value(&entry.value)),
                    value_preview: if secret || !options.show_values {
                        None
                    } else {
                        Some(entry.value)
                    },
                }
            })
            .collect();

        targets.push(TargetConfigInventory {
            target_code,
            keys: key_entries,
        });
    }

    Ok(ConfigInventory {
        environment: options.environment.clone(),
        targets,
        warnings: builder.warnings,
    })
}

pub fn merge_remote_secret_names(
    inventory: &mut ConfigInventory,
    target_code: &str,
    names: impl IntoIterator<Item = String>,
) {
    if let Some(target) = inventory
        .targets
        .iter_mut()
        .find(|target| target.target_code == target_code)
    {
        for name in names {
            if target.keys.iter().any(|key| key.key == name) {
                continue;
            }
            target.keys.push(ConfigKeyInventory {
                key: name,
                source: "remote secret metadata".to_string(),
                present: true,
                secret: true,
                value_hash: None,
                value_preview: None,
            });
        }
        target.keys.sort_by(|left, right| left.key.cmp(&right.key));
        return;
    }

    let mut keys = names
        .into_iter()
        .map(|name| ConfigKeyInventory {
            key: name,
            source: "remote secret metadata".to_string(),
            present: true,
            secret: true,
            value_hash: None,
            value_preview: None,
        })
        .collect::<Vec<_>>();
    keys.sort_by(|left, right| left.key.cmp(&right.key));

    inventory.targets.push(TargetConfigInventory {
        target_code: target_code.to_string(),
        keys,
    });
    inventory
        .targets
        .sort_by(|left, right| left.target_code.cmp(&right.target_code));
}

fn load_compose_file(
    compose_path: &Path,
    source_prefix: &str,
    global_entries: &BTreeMap<String, KeyEntry>,
    target_override: Option<&str>,
    service_filter: Option<&str>,
    builder: &mut InventoryBuilder,
) -> Result<(), CliError> {
    let content = match std::fs::read_to_string(compose_path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let parsed: serde_yaml::Value = serde_yaml::from_str(&content)?;
    let Some(services) = parsed
        .get("services")
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return Ok(());
    };

    let compose_dir = compose_path.parent().unwrap_or_else(|| Path::new("."));
    for (service_name, service_config) in services {
        let target = if let Some(target_override) = target_override {
            target_override
        } else {
            let Some(target) = service_name.as_str() else {
                continue;
            };
            target
        };
        if !target_matches(target, service_filter) {
            continue;
        }
        builder.add_target(target);
        builder.add_entries(target, global_entries.clone());

        if let Some(env_file) = service_config.get("env_file") {
            for env_path in compose_env_file_paths(env_file) {
                let resolved = resolve_relative(compose_dir, &env_path);
                match parse_env_file(&resolved) {
                    Ok(values) => {
                        builder.add_env_map(target, &format!("{source_prefix} env_file"), values)
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        builder.warn(format!(
                            "Missing env file for {target}: {}",
                            resolved.display()
                        ));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }

        if let Some(environment) = service_config.get("environment") {
            builder.add_env_map(
                target,
                &format!("{source_prefix} environment"),
                compose_environment_values(environment),
            );
        }
    }

    Ok(())
}

fn load_app_local_files(
    project_dir: &Path,
    environment: &str,
    service_filter: Option<&str>,
    builder: &mut InventoryBuilder,
) -> Result<(), CliError> {
    let mut app_dirs = BTreeSet::new();
    discover_app_local_dirs(project_dir, environment, &mut app_dirs)?;

    for app_dir in app_dirs {
        let Some(target) = app_dir.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !target_matches(target, service_filter) {
            continue;
        }
        let env_dir = app_dir.join("docker").join(environment);
        let env_file = env_dir.join(".env");
        if env_file.exists() {
            let values = parse_env_file(&env_file)?;
            builder.add_env_map(target, "app-local .env", values);
        }

        let compose_file = env_dir.join("compose.yml");
        load_compose_file(
            &compose_file,
            "app-local compose",
            &BTreeMap::new(),
            Some(target),
            service_filter,
            builder,
        )?;
    }

    Ok(())
}

fn target_matches(target: &str, service_filter: Option<&str>) -> bool {
    match service_filter {
        Some(service) => service == target,
        None => true,
    }
}

fn discover_app_local_dirs(
    dir: &Path,
    environment: &str,
    app_dirs: &mut BTreeSet<PathBuf>,
) -> Result<(), CliError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with('.') || name == "target" {
            continue;
        }

        let app_env_dir = path.join("docker").join(environment);
        if app_env_dir.join("compose.yml").exists() || app_env_dir.join(".env").exists() {
            app_dirs.insert(path.clone());
        }
    }

    Ok(())
}

fn compose_environment_values(value: &serde_yaml::Value) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();

    match value {
        serde_yaml::Value::Mapping(map) => {
            for (key, value) in map {
                if let Some(key) = key.as_str() {
                    values.insert(key.to_string(), yaml_scalar_to_string(value));
                }
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                let Some(item) = item.as_str() else {
                    continue;
                };
                if let Some((key, value)) = item.split_once('=') {
                    values.insert(key.to_string(), value.to_string());
                }
            }
        }
        _ => {}
    }

    values
}

fn compose_env_file_paths(value: &serde_yaml::Value) -> Vec<PathBuf> {
    match value {
        serde_yaml::Value::String(path) => vec![PathBuf::from(path)],
        serde_yaml::Value::Sequence(items) => items
            .iter()
            .filter_map(|item| match item {
                serde_yaml::Value::String(path) => Some(PathBuf::from(path)),
                serde_yaml::Value::Mapping(map) => map
                    .get("path")
                    .and_then(serde_yaml::Value::as_str)
                    .map(PathBuf::from),
                _ => None,
            })
            .collect(),
        serde_yaml::Value::Mapping(map) => map
            .get("path")
            .and_then(serde_yaml::Value::as_str)
            .map(PathBuf::from)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_env_file(path: &Path) -> Result<BTreeMap<String, String>, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    let mut values = BTreeMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        values.insert(key.to_string(), unquote_env_value(value.trim()).to_string());
    }

    Ok(values)
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn unquote_env_value(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|inner| inner.strip_suffix('\''))
        })
        .unwrap_or(value)
}

fn yaml_scalar_to_string(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::Null => String::new(),
        serde_yaml::Value::Bool(value) => value.to_string(),
        serde_yaml::Value::Number(value) => value.to_string(),
        serde_yaml::Value::String(value) => value.clone(),
        _ => serde_yaml::to_string(value)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

fn is_secret_key(key: &str) -> bool {
    let normalized = key.to_ascii_uppercase();
    [
        "SECRET",
        "PASSWORD",
        "TOKEN",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "DATABASE_URL",
        "DB_URL",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn hash_value(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn inventory(
        root: &Path,
        environment: &str,
        service: Option<&str>,
        show_values: bool,
    ) -> ConfigInventory {
        load_inventory(
            &root.join("stacker.yml"),
            &InventoryOptions {
                environment: environment.to_string(),
                service: service.map(str::to_string),
                show_values,
            },
        )
        .unwrap()
    }

    fn key<'a>(inventory: &'a ConfigInventory, target: &str, name: &str) -> &'a ConfigKeyInventory {
        inventory
            .targets
            .iter()
            .find(|target_inventory| target_inventory.target_code == target)
            .and_then(|target_inventory| target_inventory.keys.iter().find(|key| key.key == name))
            .unwrap()
    }

    #[test]
    fn config_inventory_collects_stackeryml_env_and_service_overrides() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
env:
  RUST_LOG: info
app:
  environment:
    RUST_LOG: debug
services:
  upload:
    image: upload:latest
    environment:
      S3_BUCKET: superbucket
"#,
        );

        let inventory = inventory(temp.path(), "prod", None, true);

        assert_eq!(
            key(&inventory, "device-api", "RUST_LOG")
                .value_preview
                .as_deref(),
            Some("debug")
        );
        assert_eq!(
            key(&inventory, "device-api", "RUST_LOG").source,
            "stacker.yml app environment"
        );
        assert_eq!(
            key(&inventory, "upload", "S3_BUCKET").source,
            "stacker.yml service environment"
        );
    }

    #[test]
    fn config_inventory_attributes_top_level_env_file_keys() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
environments:
  prod:
    env_file: docker/prod/.env
"#,
        );
        write(
            &temp.path().join("docker/prod/.env"),
            "DATABASE_URL=postgres://db\n",
        );

        let inventory = inventory(temp.path(), "prod", None, false);

        assert_eq!(
            key(&inventory, "device-api", "DATABASE_URL").source,
            "stacker env_file"
        );
        assert!(key(&inventory, "device-api", "DATABASE_URL").secret);
        assert_eq!(
            key(&inventory, "device-api", "DATABASE_URL").value_preview,
            None
        );
    }

    #[test]
    fn config_inventory_supports_relative_config_path_in_current_directory() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
env:
  RUST_LOG: debug
"#,
        );

        let previous_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp.path()).unwrap();
        let result = load_inventory(
            Path::new("stacker.yml"),
            &InventoryOptions {
                environment: "prod".to_string(),
                service: None,
                show_values: true,
            },
        );
        std::env::set_current_dir(previous_dir).unwrap();

        let inventory = result.unwrap();
        assert_eq!(
            key(&inventory, "device-api", "RUST_LOG")
                .value_preview
                .as_deref(),
            Some("debug")
        );
    }

    #[test]
    fn config_inventory_collects_compose_environment_and_env_file_by_service() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
environments:
  prod:
    compose_file: docker/prod/compose.yml
"#,
        );
        write(
            &temp.path().join("docker/prod/compose.yml"),
            r#"
services:
  upload:
    image: upload:latest
    env_file:
      - upload.env
    environment:
      UPLOAD_TMP_DIR: /tmp/upload
"#,
        );
        write(
            &temp.path().join("docker/prod/upload.env"),
            "S3_BUCKET=superbucket\n",
        );

        let inventory = inventory(temp.path(), "prod", None, true);

        assert_eq!(
            key(&inventory, "upload", "S3_BUCKET").source,
            "compose env_file"
        );
        assert_eq!(
            key(&inventory, "upload", "UPLOAD_TMP_DIR")
                .value_preview
                .as_deref(),
            Some("/tmp/upload")
        );
    }

    #[test]
    fn config_inventory_collects_app_local_env_files() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: stack
deploy:
  environment: prod
"#,
        );
        write(
            &temp.path().join("device-api/docker/prod/.env"),
            "RUST_LOG=debug\n",
        );

        let inventory = inventory(temp.path(), "prod", None, true);

        assert_eq!(
            key(&inventory, "device-api", "RUST_LOG").source,
            "app-local .env"
        );
        assert_eq!(
            key(&inventory, "device-api", "RUST_LOG")
                .value_preview
                .as_deref(),
            Some("debug")
        );
    }

    #[test]
    fn config_inventory_attributes_app_local_compose_to_app_directory() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: stack
deploy:
  environment: prod
"#,
        );
        write(
            &temp.path().join("device-api/docker/prod/compose.yml"),
            r#"
services:
  app:
    image: device-api:latest
    environment:
      RUST_LOG: debug
"#,
        );

        let inventory = inventory(temp.path(), "prod", None, true);

        assert_eq!(
            key(&inventory, "device-api", "RUST_LOG").source,
            "app-local compose environment"
        );
    }

    #[test]
    fn config_inventory_filters_to_one_service() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
services:
  upload:
    image: upload:latest
    environment:
      S3_BUCKET: superbucket
"#,
        );

        let inventory = inventory(temp.path(), "prod", Some("upload"), true);

        assert_eq!(inventory.targets.len(), 1);
        assert_eq!(inventory.targets[0].target_code, "upload");
    }

    #[test]
    fn config_inventory_redacts_secret_like_values_even_in_json_model() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
env:
  API_TOKEN: supersecret
"#,
        );

        let inventory = inventory(temp.path(), "prod", None, true);
        let token = key(&inventory, "device-api", "API_TOKEN");

        assert!(token.secret);
        assert!(token.value_hash.is_some());
        assert_eq!(token.value_preview, None);
    }

    #[test]
    fn config_inventory_reports_missing_compose_env_file_without_panicking() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
environments:
  prod:
    compose_file: docker/prod/compose.yml
"#,
        );
        write(
            &temp.path().join("docker/prod/compose.yml"),
            r#"
services:
  upload:
    image: upload:latest
    env_file: missing.env
"#,
        );

        let inventory = inventory(temp.path(), "prod", None, true);

        assert!(inventory
            .warnings
            .iter()
            .any(|warning| warning.contains("docker/prod/missing.env")));
    }

    #[test]
    fn config_inventory_service_filter_omits_unrelated_missing_env_file_warnings() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
environments:
  prod:
    compose_file: docker/prod/compose.yml
"#,
        );
        write(
            &temp.path().join("docker/prod/compose.yml"),
            r#"
services:
  device-api:
    image: device-api:latest
    env_file: device-api/.env
  upload:
    image: upload:latest
    env_file: upload/.env
"#,
        );

        let inventory = inventory(temp.path(), "prod", Some("upload"), true);

        assert!(inventory
            .warnings
            .iter()
            .any(|warning| warning.contains("docker/prod/upload/.env")));
        assert!(!inventory
            .warnings
            .iter()
            .any(|warning| warning.contains("docker/prod/device-api/.env")));
    }

    #[test]
    fn config_inventory_merges_remote_secret_metadata_without_plaintext() {
        let mut inventory = ConfigInventory {
            environment: "prod".to_string(),
            targets: vec![TargetConfigInventory {
                target_code: "upload".to_string(),
                keys: Vec::new(),
            }],
            warnings: Vec::new(),
        };

        merge_remote_secret_names(
            &mut inventory,
            "upload",
            vec!["S3_BUCKET".to_string(), "S3_SECRET_KEY".to_string()],
        );

        assert_eq!(inventory.targets[0].keys.len(), 2);
        assert!(inventory.targets[0].keys.iter().all(|key| key.secret));
        assert!(inventory.targets[0]
            .keys
            .iter()
            .all(|key| key.value_preview.is_none() && key.value_hash.is_none()));
        assert_eq!(
            inventory.targets[0].keys[0].source,
            "remote secret metadata"
        );
    }
}
