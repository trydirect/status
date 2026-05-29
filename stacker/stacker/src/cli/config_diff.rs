use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;

use crate::cli::config_inventory::{
    load_inventory, ConfigInventory, ConfigKeyInventory, InventoryOptions,
};
use crate::cli::error::CliError;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConfigDiff {
    pub from_environment: String,
    pub to_environment: String,
    pub service: Option<String>,
    pub missing_in_to: Vec<DiffItem>,
    pub only_in_to: Vec<DiffItem>,
    pub different: Vec<DiffItem>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DiffItem {
    pub target: String,
    pub key: String,
    pub secret: bool,
    pub from_source: Option<String>,
    pub to_source: Option<String>,
    pub from_hash: Option<String>,
    pub to_hash: Option<String>,
}

pub fn load_diff(
    config_path: &Path,
    from_environment: &str,
    to_environment: &str,
    service: Option<String>,
) -> Result<ConfigDiff, CliError> {
    let from_inventory = load_inventory(
        config_path,
        &InventoryOptions {
            environment: from_environment.to_string(),
            service: service.clone(),
            show_values: false,
        },
    )?;
    let to_inventory = load_inventory(
        config_path,
        &InventoryOptions {
            environment: to_environment.to_string(),
            service: service.clone(),
            show_values: false,
        },
    )?;

    Ok(diff_inventories(from_inventory, to_inventory, service))
}

pub fn diff_inventories(
    from_inventory: ConfigInventory,
    to_inventory: ConfigInventory,
    service: Option<String>,
) -> ConfigDiff {
    let from_environment = from_inventory.environment.clone();
    let to_environment = to_inventory.environment.clone();
    let mut warnings = from_inventory.warnings.clone();
    warnings.extend(to_inventory.warnings.clone());

    let from_keys = flatten_inventory(from_inventory);
    let to_keys = flatten_inventory(to_inventory);
    let mut identities = BTreeSet::new();
    identities.extend(from_keys.keys().cloned());
    identities.extend(to_keys.keys().cloned());

    let mut missing_in_to = Vec::new();
    let mut only_in_to = Vec::new();
    let mut different = Vec::new();

    for identity in identities {
        match (from_keys.get(&identity), to_keys.get(&identity)) {
            (Some(from_key), None) => {
                missing_in_to.push(diff_item(&identity, Some(from_key), None))
            }
            (None, Some(to_key)) => only_in_to.push(diff_item(&identity, None, Some(to_key))),
            (Some(from_key), Some(to_key)) if from_key.value_hash != to_key.value_hash => {
                different.push(diff_item(&identity, Some(from_key), Some(to_key)));
            }
            _ => {}
        }
    }

    ConfigDiff {
        from_environment,
        to_environment,
        service,
        missing_in_to,
        only_in_to,
        different,
        warnings,
    }
}

impl ConfigDiff {
    pub fn has_differences(&self) -> bool {
        !self.missing_in_to.is_empty() || !self.only_in_to.is_empty() || !self.different.is_empty()
    }
}

fn flatten_inventory(inventory: ConfigInventory) -> BTreeMap<(String, String), ConfigKeyInventory> {
    let mut flattened = BTreeMap::new();

    for target in inventory.targets {
        for key in target.keys {
            flattened.insert((target.target_code.clone(), key.key.clone()), key);
        }
    }

    flattened
}

fn diff_item(
    identity: &(String, String),
    from_key: Option<&ConfigKeyInventory>,
    to_key: Option<&ConfigKeyInventory>,
) -> DiffItem {
    DiffItem {
        target: identity.0.clone(),
        key: identity.1.clone(),
        secret: from_key
            .map(|key| key.secret)
            .or_else(|| to_key.map(|key| key.secret))
            .unwrap_or(false),
        from_source: from_key.map(|key| key.source.clone()),
        to_source: to_key.map(|key| key.source.clone()),
        from_hash: from_key.and_then(|key| key.value_hash.clone()),
        to_hash: to_key.and_then(|key| key.value_hash.clone()),
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

    fn diff(root: &Path, service: Option<&str>) -> ConfigDiff {
        load_diff(
            &root.join("stacker.yml"),
            "dev",
            "prod",
            service.map(str::to_string),
        )
        .unwrap()
    }

    fn write_env_diff_project(root: &Path, dev_env: &str, prod_env: &str) {
        write(
            &root.join("stacker.yml"),
            r#"
name: device-api
environments:
  dev:
    env_file: docker/dev/.env
  prod:
    env_file: docker/prod/.env
"#,
        );
        write(&root.join("docker/dev/.env"), dev_env);
        write(&root.join("docker/prod/.env"), prod_env);
    }

    #[test]
    fn config_diff_reports_key_missing_in_target_environment() {
        let temp = TempDir::new().unwrap();
        write_env_diff_project(
            temp.path(),
            "RUST_LOG=debug\nS3_BUCKET=dev-bucket\n",
            "RUST_LOG=debug\n",
        );

        let diff = diff(temp.path(), None);

        assert_eq!(diff.missing_in_to.len(), 1);
        assert_eq!(diff.missing_in_to[0].target, "device-api");
        assert_eq!(diff.missing_in_to[0].key, "S3_BUCKET");
    }

    #[test]
    fn config_diff_reports_key_only_in_target_environment() {
        let temp = TempDir::new().unwrap();
        write_env_diff_project(
            temp.path(),
            "RUST_LOG=debug\n",
            "RUST_LOG=debug\nNODE_ENV=production\n",
        );

        let diff = diff(temp.path(), None);

        assert_eq!(diff.only_in_to.len(), 1);
        assert_eq!(diff.only_in_to[0].key, "NODE_ENV");
    }

    #[test]
    fn config_diff_reports_hash_difference_without_plaintext_values() {
        let temp = TempDir::new().unwrap();
        write_env_diff_project(temp.path(), "RUST_LOG=debug\n", "RUST_LOG=info\n");

        let diff = diff(temp.path(), None);

        assert_eq!(diff.different.len(), 1);
        assert_eq!(diff.different[0].key, "RUST_LOG");
        assert_ne!(diff.different[0].from_hash, diff.different[0].to_hash);
    }

    #[test]
    fn config_diff_redacts_secret_like_differences() {
        let temp = TempDir::new().unwrap();
        write_env_diff_project(
            temp.path(),
            "API_TOKEN=dev-secret\n",
            "API_TOKEN=prod-secret\n",
        );

        let diff = diff(temp.path(), None);

        assert_eq!(diff.different.len(), 1);
        assert!(diff.different[0].secret);
        assert_ne!(diff.different[0].from_hash.as_deref(), Some("dev-secret"));
        assert_ne!(diff.different[0].to_hash.as_deref(), Some("prod-secret"));
    }

    #[test]
    fn config_diff_respects_service_filter() {
        let temp = TempDir::new().unwrap();
        write(
            &temp.path().join("stacker.yml"),
            r#"
name: device-api
environments:
  dev:
    compose_file: docker/dev/compose.yml
  prod:
    compose_file: docker/prod/compose.yml
"#,
        );
        write(
            &temp.path().join("docker/dev/compose.yml"),
            r#"
services:
  upload:
    image: upload:latest
    environment:
      S3_BUCKET: dev-bucket
  worker:
    image: worker:latest
    environment:
      QUEUE: dev
"#,
        );
        write(
            &temp.path().join("docker/prod/compose.yml"),
            r#"
services:
  upload:
    image: upload:latest
    environment:
      S3_BUCKET: prod-bucket
"#,
        );

        let diff = diff(temp.path(), Some("upload"));

        assert_eq!(diff.different.len(), 1);
        assert!(diff.missing_in_to.is_empty());
        assert_eq!(diff.different[0].target, "upload");
    }

    #[test]
    fn config_diff_treats_remote_secret_metadata_as_present_in_target() {
        let from_inventory = ConfigInventory {
            environment: "local".to_string(),
            targets: vec![crate::cli::config_inventory::TargetConfigInventory {
                target_code: "upload".to_string(),
                keys: vec![ConfigKeyInventory {
                    key: "S3_SECRET_KEY".to_string(),
                    source: "stacker.yml service environment".to_string(),
                    present: true,
                    secret: true,
                    value_hash: Some("local-hash".to_string()),
                    value_preview: None,
                }],
            }],
            warnings: Vec::new(),
        };
        let mut to_inventory = ConfigInventory {
            environment: "prod".to_string(),
            targets: vec![crate::cli::config_inventory::TargetConfigInventory {
                target_code: "upload".to_string(),
                keys: Vec::new(),
            }],
            warnings: Vec::new(),
        };
        crate::cli::config_inventory::merge_remote_secret_names(
            &mut to_inventory,
            "upload",
            vec!["S3_SECRET_KEY".to_string()],
        );

        let diff = diff_inventories(from_inventory, to_inventory, Some("upload".to_string()));

        assert!(diff.missing_in_to.is_empty());
        assert_eq!(diff.different.len(), 1);
        assert_eq!(diff.different[0].key, "S3_SECRET_KEY");
        assert_eq!(diff.different[0].to_hash, None);
    }
}
