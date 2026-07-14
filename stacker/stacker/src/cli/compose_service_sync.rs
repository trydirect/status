use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::cli::config_parser::{ServiceDefinition, StackerConfig};
use crate::cli::error::CliError;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComposeServiceSyncResult {
    pub compose_path: Option<PathBuf>,
    pub backup_path: Option<PathBuf>,
    pub updated_services: Vec<String>,
}

pub fn sync_configured_compose_services(
    project_dir: &Path,
    config: &StackerConfig,
    service_names: &[String],
) -> Result<ComposeServiceSyncResult, CliError> {
    let Some(compose_file) = config.deploy.compose_file.as_ref() else {
        return Ok(ComposeServiceSyncResult::default());
    };
    if service_names.is_empty() {
        return Ok(ComposeServiceSyncResult {
            compose_path: Some(resolve_path(project_dir, compose_file)),
            ..Default::default()
        });
    }

    let compose_path = resolve_path(project_dir, compose_file);
    if !compose_path.exists() {
        return Err(CliError::ConfigValidation(format!(
            "Configured compose file does not exist: {}",
            compose_path.display()
        )));
    }

    let original = std::fs::read_to_string(&compose_path)?;
    let mut compose_doc: serde_yaml::Value = serde_yaml::from_str(&original)?;
    let project_networks = project_service_networks(&compose_doc);
    let mut updated_services = Vec::new();

    for service_name in service_names {
        let service = config
            .services
            .iter()
            .find(|service| service.name == *service_name)
            .ok_or_else(|| {
                CliError::ConfigValidation(format!(
                    "Service '{}' was not found in stacker.yml",
                    service_name
                ))
            })?;
        upsert_compose_service(&mut compose_doc, service, &project_networks)?;
        updated_services.push(service.name.clone());
    }

    let updated = serde_yaml::to_string(&compose_doc)
        .map_err(|err| CliError::ConfigValidation(format!("failed to serialize compose: {err}")))?;
    if updated == original {
        return Ok(ComposeServiceSyncResult {
            compose_path: Some(compose_path),
            backup_path: None,
            updated_services: Vec::new(),
        });
    }

    let backup_path = backup_path(&compose_path);
    std::fs::copy(&compose_path, &backup_path)?;
    std::fs::write(&compose_path, updated)?;

    Ok(ComposeServiceSyncResult {
        compose_path: Some(compose_path),
        backup_path: Some(backup_path),
        updated_services,
    })
}

fn resolve_path(project_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        project_dir.join(path)
    }
}

fn backup_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.bak", path.to_string_lossy()))
}

fn upsert_compose_service(
    compose_doc: &mut serde_yaml::Value,
    service: &ServiceDefinition,
    project_networks: &[String],
) -> Result<(), CliError> {
    let services_key = serde_yaml::Value::String("services".to_string());
    let root = compose_doc.as_mapping_mut().ok_or_else(|| {
        CliError::ConfigValidation("docker compose file must be a YAML mapping".to_string())
    })?;
    if !root.contains_key(&services_key) {
        root.insert(
            services_key.clone(),
            serde_yaml::Value::Mapping(Default::default()),
        );
    }
    let services = root
        .get_mut(&services_key)
        .and_then(serde_yaml::Value::as_mapping_mut)
        .ok_or_else(|| {
            CliError::ConfigValidation("docker compose file services must be a mapping".to_string())
        })?;

    services.insert(
        serde_yaml::Value::String(service.name.clone()),
        service_to_compose_value(service, project_networks),
    );
    upsert_named_volumes(root, &service.volumes);
    Ok(())
}

fn service_to_compose_value(
    service: &ServiceDefinition,
    project_networks: &[String],
) -> serde_yaml::Value {
    let mut map = serde_yaml::Mapping::new();
    map.insert(
        serde_yaml::Value::String("image".to_string()),
        serde_yaml::Value::String(service.image.clone()),
    );
    insert_string_sequence(&mut map, "ports", &service.ports);
    insert_environment(&mut map, &service.environment);
    insert_string_sequence(&mut map, "volumes", &service.volumes);
    insert_string_sequence(&mut map, "depends_on", &service.depends_on);
    if !project_networks.is_empty() {
        insert_string_sequence(&mut map, "networks", project_networks);
    }
    map.insert(
        serde_yaml::Value::String("restart".to_string()),
        serde_yaml::Value::String("unless-stopped".to_string()),
    );
    serde_yaml::Value::Mapping(map)
}

fn insert_string_sequence(map: &mut serde_yaml::Mapping, key: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    map.insert(
        serde_yaml::Value::String(key.to_string()),
        serde_yaml::Value::Sequence(
            values
                .iter()
                .map(|value| serde_yaml::Value::String(value.clone()))
                .collect(),
        ),
    );
}

fn insert_environment(
    map: &mut serde_yaml::Mapping,
    environment: &std::collections::HashMap<String, String>,
) {
    if environment.is_empty() {
        return;
    }
    let sorted: BTreeMap<_, _> = environment.iter().collect();
    let mut env_map = serde_yaml::Mapping::new();
    for (key, value) in sorted {
        env_map.insert(
            serde_yaml::Value::String(key.clone()),
            serde_yaml::Value::String(value.clone()),
        );
    }
    map.insert(
        serde_yaml::Value::String("environment".to_string()),
        serde_yaml::Value::Mapping(env_map),
    );
}

fn upsert_named_volumes(root: &mut serde_yaml::Mapping, volumes: &[String]) {
    let named_volumes: Vec<String> = volumes
        .iter()
        .filter_map(|volume| named_volume_source(volume))
        .collect();
    if named_volumes.is_empty() {
        return;
    }

    let volumes_key = serde_yaml::Value::String("volumes".to_string());
    if !root.contains_key(&volumes_key) {
        root.insert(
            volumes_key.clone(),
            serde_yaml::Value::Mapping(Default::default()),
        );
    }
    let Some(volume_map) = root
        .get_mut(&volumes_key)
        .and_then(serde_yaml::Value::as_mapping_mut)
    else {
        return;
    };
    for volume in named_volumes {
        let key = serde_yaml::Value::String(volume.clone());
        if volume_map.contains_key(&key) {
            continue;
        }
        let mut value = serde_yaml::Mapping::new();
        value.insert(
            serde_yaml::Value::String("name".to_string()),
            serde_yaml::Value::String(volume),
        );
        volume_map.insert(key, serde_yaml::Value::Mapping(value));
    }
}

fn named_volume_source(volume: &str) -> Option<String> {
    let (source, _) = volume.split_once(':')?;
    if source.starts_with('.') || source.starts_with('/') || source.starts_with('$') {
        return None;
    }
    Some(source.to_string())
}

fn project_service_networks(project_doc: &serde_yaml::Value) -> Vec<String> {
    let Some(project_services) = project_doc
        .as_mapping()
        .and_then(|root| root.get(serde_yaml::Value::String("services".to_string())))
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return Vec::new();
    };

    let mut networks = Vec::new();
    for service in project_services.values() {
        let Some(networks_value) = service
            .as_mapping()
            .and_then(|service| service.get(serde_yaml::Value::String("networks".to_string())))
        else {
            continue;
        };
        collect_network_names(networks_value, &mut networks);
    }
    networks
}

fn collect_network_names(value: &serde_yaml::Value, networks: &mut Vec<String>) {
    match value {
        serde_yaml::Value::String(name) => push_unique_network(networks, name),
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                if let Some(name) = item.as_str() {
                    push_unique_network(networks, name);
                }
            }
        }
        serde_yaml::Value::Mapping(map) => {
            for key in map.keys() {
                if let Some(name) = key.as_str() {
                    push_unique_network(networks, name);
                }
            }
        }
        _ => {}
    }
}

fn push_unique_network(networks: &mut Vec<String>, name: &str) {
    if !networks.iter().any(|existing| existing == name) {
        networks.push(name.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::config_parser::{AppSource, DeployConfig, ProjectConfig};
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[test]
    fn sync_configured_compose_services_upserts_service_networks_and_volumes() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("docker-compose.yml"),
            r#"
version: '3.8'
networks:
  default_network:
    external: true
    name: default_network
services:
  status-panel-web:
    image: trydirect/status-panel-web:latest
    networks:
      - default_network
volumes:
  npm_data:
    name: npm_data
"#,
        )
        .unwrap();

        let config = StackerConfig {
            project: ProjectConfig::default(),
            app: AppSource::default(),
            deploy: DeployConfig {
                compose_file: Some(PathBuf::from("docker-compose.yml")),
                ..Default::default()
            },
            services: vec![ServiceDefinition {
                name: "smtp".to_string(),
                image: "trydirect/smtp".to_string(),
                ports: vec!["1025:25".to_string()],
                environment: HashMap::from([
                    (
                        "RELAY_NETWORKS".to_string(),
                        ":127.0.0.0/8:10.0.0.0/8:172.16.0.0/12:192.168.0.0/16".to_string(),
                    ),
                    ("PORT".to_string(), "25".to_string()),
                ]),
                volumes: vec!["smtp_data:/data".to_string()],
                depends_on: Vec::new(),
            }],
            ..Default::default()
        };

        let result =
            sync_configured_compose_services(dir.path(), &config, &[String::from("smtp")]).unwrap();

        assert_eq!(result.updated_services, vec!["smtp"]);
        assert!(result.backup_path.unwrap().exists());
        let updated = std::fs::read_to_string(dir.path().join("docker-compose.yml")).unwrap();
        assert!(updated.contains("smtp:"));
        assert!(updated.contains("image: trydirect/smtp"));
        assert!(updated.contains("\"1025:25\"") || updated.contains("1025:25"));
        assert!(updated.contains("RELAY_NETWORKS"));
        assert!(updated.contains("default_network"));
        assert!(updated.contains("smtp_data:"));
    }
}
