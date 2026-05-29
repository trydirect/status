use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_yaml::{Mapping, Value};

use crate::cli::config_parser::{ServiceDefinition, StackerConfig};
use crate::cli::error::CliError;

pub fn config_with_compose_secret_target_services(
    config: &StackerConfig,
    compose_path: &Path,
) -> Result<StackerConfig, CliError> {
    let mut config = config.clone();
    let mut existing = config
        .services
        .iter()
        .map(|service| service.name.to_ascii_lowercase())
        .collect::<HashSet<_>>();

    for service in extract_compose_secret_target_services(compose_path, &config)? {
        if existing.insert(service.name.to_ascii_lowercase()) {
            config.services.push(service);
        }
    }

    Ok(config)
}

pub fn extract_compose_secret_target_services(
    compose_path: &Path,
    config: &StackerConfig,
) -> Result<Vec<ServiceDefinition>, CliError> {
    let mut visited = HashSet::new();
    let mut services = Vec::new();
    collect_compose_services(compose_path, config, &mut visited, &mut services)?;
    Ok(services)
}

pub fn compose_defines_nginx_proxy_manager_service(compose_path: &Path) -> Result<bool, CliError> {
    let mut visited = HashSet::new();
    compose_file_defines_nginx_proxy_manager_service(compose_path, &mut visited)
}

fn compose_file_defines_nginx_proxy_manager_service(
    compose_path: &Path,
    visited: &mut HashSet<PathBuf>,
) -> Result<bool, CliError> {
    let canonical = compose_path
        .canonicalize()
        .unwrap_or_else(|_| compose_path.to_path_buf());
    if !visited.insert(canonical) {
        return Ok(false);
    }

    let content = std::fs::read_to_string(compose_path).map_err(|err| {
        CliError::ConfigValidation(format!(
            "Failed to read compose file for proxy discovery '{}': {}",
            compose_path.display(),
            err
        ))
    })?;
    let document: Value = serde_yaml::from_str(&content).map_err(|err| {
        CliError::ConfigValidation(format!(
            "Failed to parse compose file for proxy discovery '{}': {}",
            compose_path.display(),
            err
        ))
    })?;

    if let Some(service_map) = document
        .get(Value::String("services".to_string()))
        .and_then(Value::as_mapping)
    {
        for (name, definition) in service_map {
            let Some(service_name) = name.as_str() else {
                continue;
            };
            let Some(definition) = definition.as_mapping() else {
                continue;
            };
            if is_nginx_proxy_manager_compose_service(service_name, definition) {
                return Ok(true);
            }
        }
    }

    let base_dir = compose_path.parent().unwrap_or_else(|| Path::new("."));
    for include_path in compose_include_paths(&document, base_dir) {
        if compose_file_defines_nginx_proxy_manager_service(&include_path, visited)? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn collect_compose_services(
    compose_path: &Path,
    config: &StackerConfig,
    visited: &mut HashSet<PathBuf>,
    services: &mut Vec<ServiceDefinition>,
) -> Result<(), CliError> {
    let canonical = compose_path
        .canonicalize()
        .unwrap_or_else(|_| compose_path.to_path_buf());
    if !visited.insert(canonical) {
        return Ok(());
    }

    let content = std::fs::read_to_string(compose_path).map_err(|err| {
        CliError::ConfigValidation(format!(
            "Failed to read compose file for service target discovery '{}': {}",
            compose_path.display(),
            err
        ))
    })?;
    let document: Value = serde_yaml::from_str(&content).map_err(|err| {
        CliError::ConfigValidation(format!(
            "Failed to parse compose file for service target discovery '{}': {}",
            compose_path.display(),
            err
        ))
    })?;

    let base_dir = compose_path.parent().unwrap_or_else(|| Path::new("."));
    let existing_config_services = config
        .services
        .iter()
        .map(|service| service.name.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let already_extracted = services
        .iter()
        .map(|service: &ServiceDefinition| service.name.to_ascii_lowercase())
        .collect::<HashSet<_>>();

    if let Some(service_map) = document
        .get(Value::String("services".to_string()))
        .and_then(Value::as_mapping)
    {
        for (name, definition) in service_map {
            let Some(service_name) = name.as_str() else {
                continue;
            };
            let normalized_name = service_name.to_ascii_lowercase();
            if normalized_name == "app"
                || normalized_name == config.name.to_ascii_lowercase()
                || existing_config_services.contains(&normalized_name)
                || already_extracted.contains(&normalized_name)
            {
                continue;
            }

            let Some(definition) = definition.as_mapping() else {
                eprintln!(
                    "  Skipping compose service '{}' as a remote secret target: service definition is not a map.",
                    service_name
                );
                continue;
            };

            if is_platform_managed_compose_service(service_name, definition) {
                eprintln!(
                    "  Skipping compose service '{}' as a remote secret target: service is platform-managed.",
                    service_name
                );
                continue;
            }

            let Some(image) = mapping_string(definition, "image") else {
                eprintln!(
                    "  Skipping compose service '{}' as a remote secret target: image-backed services are required.",
                    service_name
                );
                continue;
            };

            services.push(ServiceDefinition {
                name: service_name.to_string(),
                image,
                ports: mapping_sequence(definition, "ports")
                    .into_iter()
                    .filter_map(compose_port_to_string)
                    .collect(),
                environment: compose_environment(definition),
                volumes: mapping_sequence(definition, "volumes")
                    .into_iter()
                    .filter_map(compose_volume_to_string)
                    .collect(),
                depends_on: compose_depends_on(definition),
            });
        }
    }

    for include_path in compose_include_paths(&document, base_dir) {
        collect_compose_services(&include_path, config, visited, services)?;
    }

    Ok(())
}

fn mapping_string(mapping: &Mapping, key: &str) -> Option<String> {
    mapping
        .get(Value::String(key.to_string()))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn mapping_sequence<'a>(mapping: &'a Mapping, key: &str) -> Vec<&'a Value> {
    mapping
        .get(Value::String(key.to_string()))
        .and_then(Value::as_sequence)
        .map(|values| values.iter().collect())
        .unwrap_or_default()
}

fn compose_environment(mapping: &Mapping) -> std::collections::HashMap<String, String> {
    let mut environment = std::collections::HashMap::new();
    let Some(value) = mapping.get(Value::String("environment".to_string())) else {
        return environment;
    };

    if let Some(map) = value.as_mapping() {
        for (key, value) in map {
            if let Some(key) = key.as_str() {
                environment.insert(key.to_string(), yaml_scalar_to_string(value));
            }
        }
        return environment;
    }

    if let Some(sequence) = value.as_sequence() {
        for item in sequence {
            if let Some(entry) = item.as_str() {
                if let Some((key, value)) = entry.split_once('=') {
                    environment.insert(key.to_string(), value.to_string());
                }
            }
        }
    }

    environment
}

fn compose_depends_on(mapping: &Mapping) -> Vec<String> {
    let Some(value) = mapping.get(Value::String("depends_on".to_string())) else {
        return Vec::new();
    };

    if let Some(sequence) = value.as_sequence() {
        return sequence
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect();
    }

    value
        .as_mapping()
        .map(|depends_on| {
            depends_on
                .keys()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn compose_port_to_string(value: &Value) -> Option<String> {
    if let Some(port) = value.as_str() {
        return Some(port.to_string());
    }

    let map = value.as_mapping()?;
    let target = mapping_scalar(map, "target")?;
    let published = mapping_scalar(map, "published");
    Some(match published {
        Some(published) => format!("{published}:{target}"),
        None => target,
    })
}

fn compose_volume_to_string(value: &Value) -> Option<String> {
    if let Some(volume) = value.as_str() {
        return Some(volume.to_string());
    }

    let map = value.as_mapping()?;
    let target = mapping_scalar(map, "target")?;
    let source = mapping_scalar(map, "source").unwrap_or_default();
    let read_only = map
        .get(Value::String("read_only".to_string()))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Some(if read_only {
        format!("{source}:{target}:ro")
    } else if source.is_empty() {
        target
    } else {
        format!("{source}:{target}")
    })
}

fn mapping_scalar(mapping: &Mapping, key: &str) -> Option<String> {
    mapping
        .get(Value::String(key.to_string()))
        .map(yaml_scalar_to_string)
        .filter(|value| !value.is_empty())
}

fn yaml_scalar_to_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        _ => serde_yaml::to_string(value)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

fn compose_include_paths(document: &Value, base_dir: &Path) -> Vec<PathBuf> {
    let Some(include) = document.get(Value::String("include".to_string())) else {
        return Vec::new();
    };

    let mut paths = Vec::new();
    collect_include_value(include, base_dir, &mut paths);
    paths
}

fn collect_include_value(value: &Value, base_dir: &Path, paths: &mut Vec<PathBuf>) {
    if let Some(path) = value.as_str() {
        paths.push(base_dir.join(path));
        return;
    }

    if let Some(sequence) = value.as_sequence() {
        for item in sequence {
            collect_include_value(item, base_dir, paths);
        }
        return;
    }

    if let Some(mapping) = value.as_mapping() {
        if let Some(path) = mapping_string(mapping, "path") {
            paths.push(base_dir.join(path));
        }
    }
}

fn is_platform_managed_compose_service(service_name: &str, definition: &Mapping) -> bool {
    let image = mapping_string(definition, "image");
    crate::project_app::is_platform_managed_app_identity(service_name, image.as_deref())
}

fn is_nginx_proxy_manager_compose_service(service_name: &str, definition: &Mapping) -> bool {
    let image = mapping_string(definition, "image");
    crate::project_app::is_nginx_proxy_manager_identity(service_name, image.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn detects_nginx_proxy_manager_service_in_compose_file() {
        let dir = TempDir::new().unwrap();
        let compose_path = dir.path().join("compose.yml");
        std::fs::write(
            &compose_path,
            r#"
services:
  proxy:
    image: jc21/nginx-proxy-manager:latest
"#,
        )
        .unwrap();

        assert!(compose_defines_nginx_proxy_manager_service(&compose_path).unwrap());
    }

    #[test]
    fn detects_nginx_proxy_manager_service_from_included_compose_file() {
        let dir = TempDir::new().unwrap();
        let compose_path = dir.path().join("compose.yml");
        let included_path = dir.path().join("proxy.yml");
        std::fs::write(
            &compose_path,
            r#"
include:
  - proxy.yml
"#,
        )
        .unwrap();
        std::fs::write(
            &included_path,
            r#"
services:
  npm:
    image: example/custom-proxy:latest
"#,
        )
        .unwrap();

        assert!(compose_defines_nginx_proxy_manager_service(&compose_path).unwrap());
    }

    #[test]
    fn ignores_compose_files_without_nginx_proxy_manager() {
        let dir = TempDir::new().unwrap();
        let compose_path = dir.path().join("compose.yml");
        std::fs::write(
            &compose_path,
            r#"
services:
  web:
    image: nginx:latest
"#,
        )
        .unwrap();

        assert!(!compose_defines_nginx_proxy_manager_service(&compose_path).unwrap());
    }
}
