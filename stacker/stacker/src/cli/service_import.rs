//! Review-first Docker Compose service import helpers.
//!
//! This module is intentionally pure: it parses Compose YAML and builds a
//! review model plus `ServiceDefinition`s, but never executes Compose content
//! and never mutates `stacker.yml`.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use serde::Serialize;
use serde_yaml::{Mapping, Value};

use crate::cli::config_parser::ServiceDefinition;
use crate::cli::error::CliError;

const SUPPORTED_FIELDS: &[&str] = &["image", "ports", "environment", "volumes", "depends_on"];
const RISK_FIELDS: &[&str] = &[
    "build",
    "cap_add",
    "devices",
    "extra_hosts",
    "ipc",
    "network_mode",
    "pid",
    "privileged",
    "security_opt",
];
const MAIL_PORTS: &[&str] = &["25", "465", "587", "993"];

#[derive(Debug, Clone)]
pub struct ComposeImportRequest {
    pub import_name: String,
    pub selected_service: Option<String>,
    pub renames: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceImportReview {
    pub import_name: String,
    pub services: Vec<ImportedServiceReview>,
    pub risks: Vec<ImportRisk>,
    pub guidance: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportedServiceReview {
    pub source_name: String,
    pub name: String,
    pub image: String,
    pub ports: Vec<String>,
    pub environment_keys: Vec<String>,
    pub environment: HashMap<String, String>,
    pub volumes: Vec<String>,
    pub depends_on: Vec<String>,
    pub unsupported_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImportRisk {
    pub service: String,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct ServiceImportPlan {
    pub review: ServiceImportReview,
    pub services: Vec<ServiceDefinition>,
}

pub fn import_plan_from_compose_file(
    compose_path: &Path,
    request: &ComposeImportRequest,
) -> Result<ServiceImportPlan, CliError> {
    let content = std::fs::read_to_string(compose_path).map_err(|err| {
        CliError::ConfigValidation(format!(
            "Failed to read compose file '{}': {}",
            compose_path.display(),
            err
        ))
    })?;
    import_plan_from_compose_str(&content, request)
}

pub fn import_plan_from_compose_str(
    compose_yaml: &str,
    request: &ComposeImportRequest,
) -> Result<ServiceImportPlan, CliError> {
    let document: Value = serde_yaml::from_str(compose_yaml).map_err(|err| {
        CliError::ConfigValidation(format!("Failed to parse Docker Compose YAML: {err}"))
    })?;
    let service_map = document
        .get(Value::String("services".to_string()))
        .and_then(Value::as_mapping)
        .ok_or_else(|| {
            CliError::ConfigValidation(
                "Docker Compose file must contain a top-level 'services' mapping".to_string(),
            )
        })?;

    let mut services = Vec::new();
    let mut reviews = Vec::new();
    let mut risks = Vec::new();
    let mut has_mail_server_shape = false;
    let rename_map = request
        .renames
        .iter()
        .cloned()
        .collect::<HashMap<String, String>>();

    for (name, definition) in service_map {
        let Some(source_name) = name.as_str() else {
            continue;
        };
        if let Some(selected) = &request.selected_service {
            if selected != source_name {
                continue;
            }
        }

        let definition = definition.as_mapping().ok_or_else(|| {
            CliError::ConfigValidation(format!("Compose service '{source_name}' must be a mapping"))
        })?;
        let image = mapping_string(definition, "image").ok_or_else(|| {
            CliError::ConfigValidation(format!(
                "Compose service '{source_name}' must use an image; build-only imports are not supported yet"
            ))
        })?;
        let destination_name = destination_service_name(source_name, request, &rename_map);
        let ports = mapping_sequence(definition, "ports")
            .into_iter()
            .filter_map(compose_port_to_string)
            .collect::<Vec<_>>();
        let environment = sanitized_compose_environment(definition);
        let mut environment_keys = environment.keys().cloned().collect::<Vec<_>>();
        environment_keys.sort();
        let volumes = mapping_sequence(definition, "volumes")
            .into_iter()
            .filter_map(compose_volume_to_string)
            .collect::<Vec<_>>();
        let depends_on = compose_depends_on(definition)
            .into_iter()
            .map(|dependency| rename_map.get(&dependency).cloned().unwrap_or(dependency))
            .collect::<Vec<_>>();
        let unsupported_fields = unsupported_fields(definition);

        risks.extend(classify_risks(
            source_name,
            definition,
            &ports,
            &volumes,
            &environment_keys,
        ));
        has_mail_server_shape |= looks_like_mail_server(source_name, &image, &ports);

        services.push(ServiceDefinition {
            name: destination_name.clone(),
            image: image.clone(),
            ports: ports.clone(),
            environment: environment.clone(),
            volumes: volumes.clone(),
            depends_on: depends_on.clone(),
        });
        reviews.push(ImportedServiceReview {
            source_name: source_name.to_string(),
            name: destination_name,
            image,
            ports,
            environment_keys,
            environment: redacted_environment(&environment),
            volumes,
            depends_on,
            unsupported_fields,
        });
    }

    if let Some(selected) = &request.selected_service {
        if services.is_empty() {
            return Err(CliError::ConfigValidation(format!(
                "Compose service '{selected}' was not found"
            )));
        }
    } else if services.is_empty() {
        return Err(CliError::ConfigValidation(
            "No importable image-backed Compose services were found".to_string(),
        ));
    }

    let mut guidance = Vec::new();
    if has_mail_server_shape {
        guidance.extend(docker_mailserver_guidance());
    }

    Ok(ServiceImportPlan {
        review: ServiceImportReview {
            import_name: request.import_name.clone(),
            services: reviews,
            risks,
            guidance,
        },
        services,
    })
}

pub fn parse_renames(values: &[String]) -> Result<Vec<(String, String)>, CliError> {
    values
        .iter()
        .map(|value| {
            let (from, to) = value.split_once('=').ok_or_else(|| {
                CliError::ConfigValidation(format!(
                    "Invalid --rename '{value}'. Expected format: old=new"
                ))
            })?;
            if from.trim().is_empty() || to.trim().is_empty() {
                return Err(CliError::ConfigValidation(format!(
                    "Invalid --rename '{value}'. Service names cannot be empty"
                )));
            }
            Ok((from.trim().to_string(), to.trim().to_string()))
        })
        .collect()
}

fn destination_service_name(
    source_name: &str,
    request: &ComposeImportRequest,
    rename_map: &HashMap<String, String>,
) -> String {
    if let Some(renamed) = rename_map.get(source_name) {
        return renamed.clone();
    }

    if request.selected_service.is_some() {
        return request.import_name.clone();
    }

    source_name.to_string()
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

fn sanitized_compose_environment(mapping: &Mapping) -> HashMap<String, String> {
    let mut environment = HashMap::new();
    let Some(value) = mapping.get(Value::String("environment".to_string())) else {
        return environment;
    };

    if let Some(map) = value.as_mapping() {
        for (key, value) in map {
            if let Some(key) = key.as_str() {
                environment.insert(key.to_string(), sanitized_env_value(key, value));
            }
        }
        return environment;
    }

    if let Some(sequence) = value.as_sequence() {
        for item in sequence {
            if let Some(entry) = item.as_str() {
                match entry.split_once('=') {
                    Some((key, value)) => {
                        environment.insert(
                            key.to_string(),
                            sanitized_env_value_from_string(key, value.to_string()),
                        );
                    }
                    None => {
                        environment.insert(entry.to_string(), String::new());
                    }
                }
            }
        }
    }

    environment
}

fn sanitized_env_value(key: &str, value: &Value) -> String {
    sanitized_env_value_from_string(key, yaml_scalar_to_string(value))
}

fn sanitized_env_value_from_string(key: &str, value: String) -> String {
    if is_sensitive_env_key(key) && !is_placeholder_value(&value) && !value.is_empty() {
        format!("${{{key}}}")
    } else {
        value
    }
}

pub fn redacted_environment(environment: &HashMap<String, String>) -> HashMap<String, String> {
    environment
        .iter()
        .map(|(key, value)| {
            let redacted = if is_sensitive_env_key(key) {
                "<redacted>".to_string()
            } else {
                value.clone()
            };
            (key.clone(), redacted)
        })
        .collect()
}

fn is_placeholder_value(value: &str) -> bool {
    value.starts_with("${") && value.ends_with('}')
}

fn is_sensitive_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    upper.contains("PASSWORD")
        || upper.contains("PASS")
        || upper.contains("SECRET")
        || upper.contains("TOKEN")
        || upper.contains("KEY")
        || upper.contains("CREDENTIAL")
        || upper.contains("PRIVATE")
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

fn unsupported_fields(mapping: &Mapping) -> Vec<String> {
    let supported = SUPPORTED_FIELDS
        .iter()
        .copied()
        .collect::<BTreeSet<&'static str>>();
    mapping
        .keys()
        .filter_map(Value::as_str)
        .filter(|key| !supported.contains(key))
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn classify_risks(
    service_name: &str,
    mapping: &Mapping,
    ports: &[String],
    volumes: &[String],
    environment_keys: &[String],
) -> Vec<ImportRisk> {
    let mut risks = Vec::new();

    for field in RISK_FIELDS {
        if mapping.contains_key(Value::String((*field).to_string())) {
            if *field == "privileged"
                && !mapping
                    .get(Value::String("privileged".to_string()))
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            {
                continue;
            }
            if (*field == "network_mode"
                && mapping_string(mapping, "network_mode").as_deref() == Some("host"))
                || *field != "network_mode"
            {
                risks.push(ImportRisk {
                    service: service_name.to_string(),
                    kind: (*field).to_string(),
                    detail: format!("Compose field '{field}' can weaken container isolation"),
                });
            }
        }
    }

    if mapping_string(mapping, "pid").as_deref() == Some("host") {
        risks.push(ImportRisk {
            service: service_name.to_string(),
            kind: "pid_host".to_string(),
            detail: "Service uses host PID namespace".to_string(),
        });
    }
    if mapping_string(mapping, "ipc").as_deref() == Some("host") {
        risks.push(ImportRisk {
            service: service_name.to_string(),
            kind: "ipc_host".to_string(),
            detail: "Service uses host IPC namespace".to_string(),
        });
    }

    for volume in volumes {
        let host_part = volume.split(':').next().unwrap_or_default();
        if host_part == "/var/run/docker.sock" {
            risks.push(ImportRisk {
                service: service_name.to_string(),
                kind: "docker_socket_mount".to_string(),
                detail: "Mounts /var/run/docker.sock, which can grant host-level Docker control"
                    .to_string(),
            });
        } else if host_part.starts_with('/') {
            risks.push(ImportRisk {
                service: service_name.to_string(),
                kind: "absolute_host_path".to_string(),
                detail: format!("Uses absolute host path mount '{host_part}'"),
            });
        }
    }

    for key in environment_keys {
        if is_sensitive_env_key(key) {
            risks.push(ImportRisk {
                service: service_name.to_string(),
                kind: "sensitive_env_name".to_string(),
                detail: format!("Environment key '{key}' looks sensitive; value will be redacted"),
            });
        }
    }

    for port in ports {
        if published_port(port).is_some() {
            risks.push(ImportRisk {
                service: service_name.to_string(),
                kind: "public_port".to_string(),
                detail: format!("Publishes host port '{port}'"),
            });
        }
    }

    risks
}

fn published_port(port: &str) -> Option<&str> {
    let mut parts = port.split(':');
    let first = parts.next()?;
    let second = parts.next();
    second.map(|_| first)
}

fn looks_like_mail_server(service_name: &str, image: &str, ports: &[String]) -> bool {
    let identity = format!("{service_name} {image}").to_ascii_lowercase();
    identity.contains("docker-mailserver")
        || identity.contains("mailserver")
        || ports.iter().any(|port| {
            let public = published_port(port).unwrap_or(port);
            MAIL_PORTS.contains(&public)
        })
}

fn docker_mailserver_guidance() -> Vec<String> {
    vec![
        "Mail server imports require DNS MX, SPF, DKIM, DMARC, PTR/rDNS records before production use.".to_string(),
        "Confirm your provider allows SMTP egress, especially port 25; many clouds block it by default.".to_string(),
        "Open only the required firewall ports (commonly 25, 465, 587, 993) and keep mail data on persistent volumes.".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ComposeImportRequest {
        ComposeImportRequest {
            import_name: "smtp".to_string(),
            selected_service: Some("mailserver".to_string()),
            renames: vec![("mailserver".to_string(), "smtp".to_string())],
        }
    }

    #[test]
    fn parses_compose_service_into_stacker_definition() {
        let plan = import_plan_from_compose_str(
            r#"
services:
  mailserver:
    image: docker.io/mailserver/docker-mailserver:latest
    ports:
      - "25:25"
      - target: 993
        published: 993
    environment:
      OVERRIDE_HOSTNAME: mail.example.com
      ACCOUNT_PASSWORD: super-secret
      DKIM_PRIVATE_KEY: ${DKIM_PRIVATE_KEY}
    volumes:
      - maildata:/var/mail
    depends_on:
      redis:
        condition: service_started
"#,
            &request(),
        )
        .unwrap();

        let service = &plan.services[0];
        assert_eq!(service.name, "smtp");
        assert_eq!(
            service.image,
            "docker.io/mailserver/docker-mailserver:latest"
        );
        assert_eq!(service.ports, vec!["25:25", "993:993"]);
        assert_eq!(
            service.environment.get("ACCOUNT_PASSWORD").unwrap(),
            "${ACCOUNT_PASSWORD}"
        );
        assert_eq!(
            service.environment.get("DKIM_PRIVATE_KEY").unwrap(),
            "${DKIM_PRIVATE_KEY}"
        );
        assert_eq!(service.depends_on, vec!["redis"]);
        assert!(!plan.review.guidance.is_empty());
    }

    #[test]
    fn classifies_risky_compose_fields() {
        let plan = import_plan_from_compose_str(
            r#"
services:
  mailserver:
    image: docker.io/mailserver/docker-mailserver:latest
    privileged: true
    network_mode: host
    pid: host
    ipc: host
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    extra_hosts: ["host.docker.internal:host-gateway"]
    security_opt: ["apparmor:unconfined"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /srv/mail:/var/mail
    environment:
      API_TOKEN: abc
    ports:
      - "587:587"
"#,
            &request(),
        )
        .unwrap();

        let kinds = plan
            .review
            .risks
            .iter()
            .map(|risk| risk.kind.as_str())
            .collect::<BTreeSet<_>>();
        for expected in [
            "privileged",
            "network_mode",
            "pid",
            "ipc",
            "pid_host",
            "ipc_host",
            "cap_add",
            "devices",
            "extra_hosts",
            "security_opt",
            "docker_socket_mount",
            "absolute_host_path",
            "sensitive_env_name",
            "public_port",
        ] {
            assert!(kinds.contains(expected), "missing risk {expected}");
        }
    }

    #[test]
    fn redacts_secret_like_environment_values_in_review() {
        let plan = import_plan_from_compose_str(
            r#"
services:
  mailserver:
    image: mail:latest
    environment:
      PASSWORD: literal
      PUBLIC_NAME: example
"#,
            &request(),
        )
        .unwrap();

        let review_env = &plan.review.services[0].environment;
        assert_eq!(review_env.get("PASSWORD").unwrap(), "<redacted>");
        assert_eq!(review_env.get("PUBLIC_NAME").unwrap(), "example");
    }
}
