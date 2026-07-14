use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;

use crate::cli::config_inventory::{load_inventory, ConfigInventory, InventoryOptions};
use crate::cli::config_parser::StackerConfig;
use crate::cli::error::CliError;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConfigCheckResult {
    pub environment: String,
    pub service: Option<String>,
    pub missing_required: Vec<ConfigCheckItem>,
    pub missing_optional: Vec<ConfigCheckItem>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConfigCheckItem {
    pub target: String,
    pub key: String,
    pub secret: bool,
}

pub fn load_check(
    config_path: &Path,
    environment: &str,
    service: Option<String>,
) -> Result<ConfigCheckResult, CliError> {
    let config = StackerConfig::from_file(config_path)?;
    let inventory = load_inventory(
        config_path,
        &InventoryOptions {
            environment: environment.to_string(),
            service: service.clone(),
            show_values: false,
        },
    )?;

    Ok(check_inventory(config, inventory, service))
}

pub fn check_inventory(
    config: StackerConfig,
    inventory: ConfigInventory,
    service: Option<String>,
) -> ConfigCheckResult {
    let mut present_keys = BTreeMap::new();
    for target in &inventory.targets {
        let keys = target
            .keys
            .iter()
            .map(|key| key.key.clone())
            .collect::<BTreeSet<_>>();
        present_keys.insert(target.target_code.clone(), keys);
    }

    let mut missing_required = Vec::new();
    let mut missing_optional = Vec::new();

    for (target, contract) in config.config_contract.services {
        if service.as_deref().is_some_and(|filter| filter != target) {
            continue;
        }

        let present = present_keys.get(&target).cloned().unwrap_or_default();
        let secret_keys = contract.secret.into_iter().collect::<BTreeSet<_>>();

        for key in contract.required {
            if !present.contains(&key) {
                missing_required.push(ConfigCheckItem {
                    secret: secret_keys.contains(&key),
                    target: target.clone(),
                    key,
                });
            }
        }

        for key in contract.optional {
            if !present.contains(&key) {
                missing_optional.push(ConfigCheckItem {
                    secret: secret_keys.contains(&key),
                    target: target.clone(),
                    key,
                });
            }
        }
    }

    ConfigCheckResult {
        environment: inventory.environment,
        service,
        missing_required,
        missing_optional,
        warnings: inventory.warnings,
    }
}

impl ConfigCheckResult {
    pub fn has_required_failures(&self) -> bool {
        !self.missing_required.is_empty()
    }

    pub fn has_warnings(&self) -> bool {
        !self.missing_optional.is_empty() || !self.warnings.is_empty()
    }
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

    fn check(root: &Path, service: Option<&str>) -> ConfigCheckResult {
        load_check(
            &root.join("stacker.yml"),
            "prod",
            service.map(str::to_string),
        )
        .unwrap()
    }

    #[test]
    fn config_check_reports_required_key_missing_from_target() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
environments:
  prod:
    env_file: docker/prod/.env
config_contract:
  services:
    device-api:
      required:
        - DATABASE_URL
"#,
        );
        write(&temp.path().join("docker/prod/.env"), "RUST_LOG=debug\n");

        let result = check(temp.path(), None);

        assert!(result.has_required_failures());
        assert_eq!(result.missing_required[0].target, "device-api");
        assert_eq!(result.missing_required[0].key, "DATABASE_URL");
    }

    #[test]
    fn config_check_treats_optional_key_as_warning_only() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
config_contract:
  services:
    device-api:
      optional:
        - SENTRY_DSN
"#,
        );

        let result = check(temp.path(), None);

        assert!(!result.has_required_failures());
        assert!(result.has_warnings());
        assert_eq!(result.missing_optional[0].key, "SENTRY_DSN");
    }

    #[test]
    fn config_check_secret_contract_redacts_missing_key_marker() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
config_contract:
  services:
    device-api:
      required:
        - CUSTOM_API_KEY
      secret:
        - CUSTOM_API_KEY
"#,
        );

        let result = check(temp.path(), None);

        assert!(result.missing_required[0].secret);
        assert_eq!(result.missing_required[0].key, "CUSTOM_API_KEY");
    }

    #[test]
    fn config_check_passes_when_required_key_exists() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
environments:
  prod:
    env_file: docker/prod/.env
config_contract:
  services:
    device-api:
      required:
        - DATABASE_URL
"#,
        );
        write(
            &temp.path().join("docker/prod/.env"),
            "DATABASE_URL=postgres://db\n",
        );

        let result = check(temp.path(), None);

        assert!(!result.has_required_failures());
        assert!(result.missing_required.is_empty());
    }

    #[test]
    fn config_check_respects_service_filter() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
config_contract:
  services:
    device-api:
      required:
        - DATABASE_URL
    upload:
      required:
        - S3_BUCKET
"#,
        );

        let result = check(temp.path(), Some("upload"));

        assert_eq!(result.missing_required.len(), 1);
        assert_eq!(result.missing_required[0].target, "upload");
        assert_eq!(result.missing_required[0].key, "S3_BUCKET");
    }
}
