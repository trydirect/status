use std::collections::BTreeSet;
use std::path::Path;

use serde::Serialize;

use crate::cli::config_diff::{load_diff, ConfigDiff, DiffItem};
use crate::cli::error::CliError;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConfigPromotionPlan {
    pub from_environment: String,
    pub to_environment: String,
    pub service: Option<String>,
    pub items: Vec<ConfigPromotionItem>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConfigPromotionItem {
    pub target: String,
    pub key: String,
    pub secret: bool,
    pub from_source: Option<String>,
    pub placeholder: String,
}

pub fn load_promotion_plan(
    config_path: &Path,
    from_environment: &str,
    to_environment: &str,
    service: Option<String>,
    keys: Vec<String>,
) -> Result<ConfigPromotionPlan, CliError> {
    let diff = load_diff(
        config_path,
        from_environment,
        to_environment,
        service.clone(),
    )?;
    Ok(promotion_plan_from_diff(diff, keys))
}

pub fn promotion_plan_from_diff(diff: ConfigDiff, keys: Vec<String>) -> ConfigPromotionPlan {
    let key_filter = keys
        .into_iter()
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty())
        .collect::<BTreeSet<_>>();
    let items = diff
        .missing_in_to
        .iter()
        .filter(|item| key_filter.is_empty() || key_filter.contains(&item.key))
        .map(promotion_item)
        .collect();

    ConfigPromotionPlan {
        from_environment: diff.from_environment,
        to_environment: diff.to_environment,
        service: diff.service,
        items,
        warnings: diff.warnings,
    }
}

impl ConfigPromotionPlan {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

fn promotion_item(item: &DiffItem) -> ConfigPromotionItem {
    ConfigPromotionItem {
        target: item.target.clone(),
        key: item.key.clone(),
        secret: item.secret,
        from_source: item.from_source.clone(),
        placeholder: format!("{}=", item.key),
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

    fn promotion(root: &Path, keys: Vec<String>) -> ConfigPromotionPlan {
        load_promotion_plan(
            &root.join("stacker.yml"),
            "local",
            "prod",
            Some("upload".to_string()),
            keys,
        )
        .unwrap()
    }

    fn write_project(root: &Path) {
        write(
            &root.join("stacker.yml"),
            r#"
name: device-api
environments:
  local:
    compose_file: docker/local/compose.yml
  prod:
    compose_file: docker/prod/compose.yml
"#,
        );
        write(
            &root.join("docker/local/compose.yml"),
            r#"
services:
  upload:
    image: upload:latest
    environment:
      S3_BUCKET: local-bucket
      S3_SECRET_KEY: local-secret
      REDIS_URL: redis://local
"#,
        );
        write(
            &root.join("docker/prod/compose.yml"),
            r#"
services:
  upload:
    image: upload:latest
    environment:
      REDIS_URL: redis://prod
"#,
        );
    }

    #[test]
    fn config_promote_plans_placeholders_for_missing_target_keys() {
        let temp = TempDir::new().unwrap();
        write_project(temp.path());

        let plan = promotion(temp.path(), Vec::new());

        assert_eq!(plan.items.len(), 2);
        assert!(plan.items.iter().any(|item| item.key == "S3_BUCKET"));
        assert!(plan
            .items
            .iter()
            .any(|item| item.placeholder == "S3_SECRET_KEY="));
    }

    #[test]
    fn config_promote_marks_secret_placeholders_without_values() {
        let temp = TempDir::new().unwrap();
        write_project(temp.path());

        let plan = promotion(temp.path(), Vec::new());
        let secret = plan
            .items
            .iter()
            .find(|item| item.key == "S3_SECRET_KEY")
            .unwrap();

        assert!(secret.secret);
        assert_eq!(secret.placeholder, "S3_SECRET_KEY=");
    }

    #[test]
    fn config_promote_respects_key_filter() {
        let temp = TempDir::new().unwrap();
        write_project(temp.path());

        let plan = promotion(temp.path(), vec!["S3_BUCKET".to_string()]);

        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.items[0].key, "S3_BUCKET");
    }
}
