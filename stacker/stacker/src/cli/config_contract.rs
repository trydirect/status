use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::cli::config_inventory::{load_inventory, ConfigInventory, InventoryOptions};
use crate::cli::config_parser::{ConfigContract, TargetConfigContract};
use crate::cli::error::CliError;

#[derive(Debug, Clone)]
pub struct ContractSuggestOptions {
    pub environment: String,
    pub service: Option<String>,
}

#[derive(Debug, Serialize)]
struct ContractSuggestion {
    config_contract: ConfigContract,
}

pub fn suggest_contract_yaml(
    config_path: &Path,
    options: &ContractSuggestOptions,
) -> Result<String, CliError> {
    let inventory = load_inventory(
        config_path,
        &InventoryOptions {
            environment: options.environment.clone(),
            service: options.service.clone(),
            show_values: false,
        },
    )?;

    contract_suggestion_yaml(suggest_contract(inventory))
}

pub fn suggest_contract(inventory: ConfigInventory) -> ConfigContract {
    let mut services = BTreeMap::new();

    for target in inventory.targets {
        let mut required = Vec::new();
        let mut secret = Vec::new();

        for key in target.keys {
            required.push(key.key.clone());
            if key.secret {
                secret.push(key.key);
            }
        }

        services.insert(
            target.target_code,
            TargetConfigContract {
                required,
                optional: Vec::new(),
                secret,
            },
        );
    }

    ConfigContract { services }
}

pub fn contract_suggestion_yaml(contract: ConfigContract) -> Result<String, CliError> {
    serde_yaml::to_string(&ContractSuggestion {
        config_contract: contract,
    })
    .map_err(CliError::from)
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

    #[test]
    fn config_contract_suggest_generates_required_keys_from_inventory() {
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
            "DATABASE_URL=postgres://db\nRUST_LOG=debug\n",
        );

        let yaml = suggest_contract_yaml(
            &temp.path().join("stacker.yml"),
            &ContractSuggestOptions {
                environment: "prod".to_string(),
                service: None,
            },
        )
        .unwrap();

        assert!(yaml.contains("config_contract:"));
        assert!(yaml.contains("device-api:"));
        assert!(yaml.contains("- DATABASE_URL"));
        assert!(yaml.contains("- RUST_LOG"));
    }

    #[test]
    fn config_contract_suggest_classifies_secret_like_keys() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
env:
  S3_SECRET_KEY: secret
"#,
        );

        let yaml = suggest_contract_yaml(
            &temp.path().join("stacker.yml"),
            &ContractSuggestOptions {
                environment: "prod".to_string(),
                service: None,
            },
        )
        .unwrap();

        assert!(yaml.contains("secret:"));
        assert!(yaml.contains("- S3_SECRET_KEY"));
    }

    #[test]
    fn config_contract_suggest_respects_service_filter() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
services:
  upload:
    image: upload:latest
    environment:
      S3_BUCKET: bucket
  worker:
    image: worker:latest
    environment:
      QUEUE: default
"#,
        );

        let yaml = suggest_contract_yaml(
            &temp.path().join("stacker.yml"),
            &ContractSuggestOptions {
                environment: "prod".to_string(),
                service: Some("upload".to_string()),
            },
        )
        .unwrap();

        assert!(yaml.contains("upload:"));
        assert!(yaml.contains("- S3_BUCKET"));
        assert!(!yaml.contains("worker:"));
        assert!(!yaml.contains("- QUEUE"));
    }
}
