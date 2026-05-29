use crate::forms;
use crate::models;
use docker_compose_types as dctypes;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use serde_yaml;
// use crate::helpers::project::*;

/// Extracted service info from a docker-compose file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedService {
    /// Service name (key in services section)
    pub name: String,
    /// Docker image
    pub image: Option<String>,
    /// Port mappings as strings (e.g., "8080:80")
    pub ports: Vec<String>,
    /// Volume mounts as strings
    pub volumes: Vec<String>,
    /// Environment variables as key=value
    pub environment: Vec<String>,
    /// Networks the service connects to
    pub networks: Vec<String>,
    /// Services this depends on
    pub depends_on: Vec<String>,
    /// Restart policy
    pub restart: Option<String>,
    /// Container command
    pub command: Option<String>,
    /// Container entrypoint
    pub entrypoint: Option<String>,
    /// Labels
    pub labels: IndexMap<String, String>,
    /// Healthcheck definition normalized into ProjectApp JSON shape.
    pub healthcheck: Option<JsonValue>,
}

/// Parse a docker-compose.yml string and extract all service definitions
pub fn parse_compose_services(compose_yaml: &str) -> Result<Vec<ExtractedService>, String> {
    let compose: dctypes::Compose = serde_yaml::from_str(compose_yaml)
        .map_err(|e| format!("Failed to parse compose YAML: {}", e))?;

    let mut services = Vec::new();

    for (name, service_opt) in compose.services.0.iter() {
        let Some(service) = service_opt else {
            continue;
        };

        let image = service.image.clone();

        // Extract ports
        let ports = match &service.ports {
            dctypes::Ports::Short(list) => list.clone(),
            dctypes::Ports::Long(list) => list
                .iter()
                .map(|p| {
                    let host = p
                        .host_ip
                        .as_ref()
                        .map(|h| format!("{}:", h))
                        .unwrap_or_default();
                    let published = p
                        .published
                        .as_ref()
                        .map(|pp| match pp {
                            dctypes::PublishedPort::Single(n) => n.to_string(),
                            dctypes::PublishedPort::Range(s) => s.clone(),
                        })
                        .unwrap_or_default();
                    format!("{}{}:{}", host, published, p.target)
                })
                .collect(),
        };

        // Extract volumes
        let volumes: Vec<String> = service
            .volumes
            .iter()
            .filter_map(|v| match v {
                dctypes::Volumes::Simple(s) => Some(s.clone()),
                dctypes::Volumes::Advanced(adv) => Some(format!(
                    "{}:{}",
                    adv.source.as_deref().unwrap_or(""),
                    &adv.target
                )),
            })
            .collect();

        // Extract environment
        let environment: Vec<String> = match &service.environment {
            dctypes::Environment::List(list) => list.clone(),
            dctypes::Environment::KvPair(map) => map
                .iter()
                .map(|(k, v)| {
                    let val = v
                        .as_ref()
                        .map(|sv| match sv {
                            dctypes::SingleValue::String(s) => s.clone(),
                            dctypes::SingleValue::Bool(b) => b.to_string(),
                            dctypes::SingleValue::Unsigned(n) => n.to_string(),
                            dctypes::SingleValue::Signed(n) => n.to_string(),
                            dctypes::SingleValue::Float(f) => f.to_string(),
                        })
                        .unwrap_or_default();
                    format!("{}={}", k, val)
                })
                .collect(),
        };

        // Extract networks
        let networks: Vec<String> = match &service.networks {
            dctypes::Networks::Simple(list) => list.clone(),
            dctypes::Networks::Advanced(adv) => adv.0.keys().cloned().collect(),
        };

        // Extract depends_on
        let depends_on: Vec<String> = match &service.depends_on {
            dctypes::DependsOnOptions::Simple(list) => list.clone(),
            dctypes::DependsOnOptions::Conditional(map) => map.keys().cloned().collect(),
        };

        // Extract restart
        let restart = service.restart.clone();

        // Extract command
        let command = match &service.command {
            Some(dctypes::Command::Simple(s)) => Some(s.clone()),
            Some(dctypes::Command::Args(args)) => Some(args.join(" ")),
            None => None,
        };

        // Extract entrypoint
        let entrypoint = match &service.entrypoint {
            Some(dctypes::Entrypoint::Simple(s)) => Some(s.clone()),
            Some(dctypes::Entrypoint::List(list)) => Some(list.join(" ")),
            None => None,
        };

        // Extract labels
        let labels: IndexMap<String, String> = match &service.labels {
            dctypes::Labels::List(list) => {
                let mut map = IndexMap::new();
                for item in list {
                    if let Some((k, v)) = item.split_once('=') {
                        map.insert(k.to_string(), v.to_string());
                    }
                }
                map
            }
            dctypes::Labels::Map(map) => map.clone(),
        };

        let healthcheck = extract_healthcheck(&service.healthcheck);

        services.push(ExtractedService {
            name: name.clone(),
            image,
            ports,
            volumes,
            environment,
            networks,
            depends_on,
            restart,
            command,
            entrypoint,
            labels,
            healthcheck,
        });
    }

    Ok(services)
}

fn extract_healthcheck(healthcheck: &Option<dctypes::Healthcheck>) -> Option<JsonValue> {
    let healthcheck = healthcheck.as_ref()?;
    if healthcheck.disable {
        return None;
    }

    let test = match &healthcheck.test {
        Some(dctypes::HealthcheckTest::Single(command)) => vec![command.clone()],
        Some(dctypes::HealthcheckTest::Multiple(commands)) => commands.clone(),
        None => Vec::new(),
    };

    if test.is_empty() {
        return None;
    }

    let mut map = serde_json::Map::new();
    map.insert("test".to_string(), json!(test));

    if let Some(interval) = &healthcheck.interval {
        map.insert("interval".to_string(), json!(interval));
    }
    if let Some(timeout) = &healthcheck.timeout {
        map.insert("timeout".to_string(), json!(timeout));
    }
    if healthcheck.retries > 0 {
        map.insert("retries".to_string(), json!(healthcheck.retries));
    }
    if let Some(start_period) = &healthcheck.start_period {
        map.insert("start_period".to_string(), json!(start_period));
    }

    Some(JsonValue::Object(map))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_compose_services_extracts_healthcheck() {
        let compose = r#"
services:
  api:
    image: nginx:latest
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
"#;

        let services = parse_compose_services(compose).expect("compose should parse");
        let service = services.first().expect("service should exist");
        let healthcheck = service
            .healthcheck
            .as_ref()
            .expect("healthcheck should be extracted");

        assert_eq!(
            healthcheck["test"],
            json!(["CMD", "curl", "-f", "http://localhost/health"])
        );
        assert_eq!(healthcheck["interval"], json!("30s"));
        assert_eq!(healthcheck["timeout"], json!("5s"));
        assert_eq!(healthcheck["retries"], json!(3));
        assert_eq!(healthcheck["start_period"], json!("10s"));
    }
}

/// A builder for constructing docker compose.
#[derive(Clone, Debug)]
pub struct DcBuilder {
    // config: Config,
    pub(crate) project: models::Project,
}

impl DcBuilder {
    pub fn new(project: models::Project) -> Self {
        DcBuilder {
            // config: Config::default(),
            project,
        }
    }

    #[tracing::instrument(name = "building project")]
    pub fn build(&self) -> Result<String, String> {
        let mut compose_content = dctypes::Compose {
            version: Some("3.8".to_string()),
            ..Default::default()
        };

        let apps = forms::project::ProjectForm::try_from(&self.project)?;
        tracing::debug!("apps {:?}", &apps);
        let services = apps.custom.services()?;
        tracing::debug!("services {:?}", &services);
        let named_volumes = apps.custom.named_volumes()?;

        tracing::debug!("named volumes {:?}", &named_volumes);
        // let all_networks = &apps.custom.networks.networks.clone().unwrap_or(vec![]);
        let networks = apps.custom.networks.clone();
        compose_content.networks = dctypes::ComposeNetworks(networks.into());

        if !named_volumes.is_empty() {
            compose_content.volumes = dctypes::TopLevelVolumes(named_volumes);
        }

        compose_content.services = dctypes::Services(services);

        let fname = format!("./files/{}.yml", self.project.stack_id);
        tracing::debug!("Saving docker compose to file {:?}", fname);
        let target_file = std::path::Path::new(fname.as_str());
        let serialized = serde_yaml::to_string(&compose_content)
            .map_err(|err| format!("Failed to serialize docker-compose file: {}", err))?;

        if let Some(parent) = target_file.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("Failed to create files directory: {}", err))?;
        }
        std::fs::write(target_file, serialized.clone()).map_err(|err| format!("{}", err))?;

        Ok(serialized)
    }
}

/// Generate a docker-compose.yml for a single app from JSON parameters.
/// Used by deploy_app command when no compose file is provided.
pub fn generate_single_app_compose(
    app_code: &str,
    params: &serde_json::Value,
) -> Result<String, String> {
    // Image is required
    let image = params
        .get("image")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required 'image' parameter".to_string())?;

    let mut service = dctypes::Service {
        image: Some(image.to_string()),
        ..Default::default()
    };

    // Restart policy
    let restart = params
        .get("restart_policy")
        .and_then(|v| v.as_str())
        .unwrap_or("unless-stopped");
    service.restart = Some(restart.to_string());

    // Command
    if let Some(cmd) = params.get("command").and_then(|v| v.as_str()) {
        if !cmd.is_empty() {
            service.command = Some(dctypes::Command::Simple(cmd.to_string()));
        }
    }

    // Entrypoint
    if let Some(entry) = params.get("entrypoint").and_then(|v| v.as_str()) {
        if !entry.is_empty() {
            service.entrypoint = Some(dctypes::Entrypoint::Simple(entry.to_string()));
        }
    }

    // Environment variables
    if let Some(env) = params.get("env") {
        let mut envs = IndexMap::new();
        if let Some(env_obj) = env.as_object() {
            for (key, value) in env_obj {
                let val_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    _ => value.to_string(),
                };
                envs.insert(key.clone(), Some(dctypes::SingleValue::String(val_str)));
            }
        } else if let Some(env_arr) = env.as_array() {
            for item in env_arr {
                if let Some(s) = item.as_str() {
                    if let Some((key, value)) = s.split_once('=') {
                        envs.insert(
                            key.to_string(),
                            Some(dctypes::SingleValue::String(value.to_string())),
                        );
                    }
                }
            }
        }
        if !envs.is_empty() {
            service.environment = dctypes::Environment::KvPair(envs);
        }
    }

    // Ports
    if let Some(ports) = params.get("ports").and_then(|v| v.as_array()) {
        let mut port_list: Vec<String> = vec![];
        for port in ports {
            if let Some(port_str) = port.as_str() {
                // Parse "host:container" or "host:container/protocol"
                port_list.push(port_str.to_string());
            } else if let Some(port_obj) = port.as_object() {
                let host = port_obj.get("host").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let container = port_obj
                    .get("container")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u16;
                if host > 0 && container > 0 {
                    port_list.push(format!("{}:{}", host, container));
                }
            }
        }
        if !port_list.is_empty() {
            service.ports = dctypes::Ports::Short(port_list);
        }
    }

    // Volumes
    if let Some(volumes) = params.get("volumes").and_then(|v| v.as_array()) {
        let mut vol_list = vec![];
        for vol in volumes {
            if let Some(vol_str) = vol.as_str() {
                vol_list.push(dctypes::Volumes::Simple(vol_str.to_string()));
            } else if let Some(vol_obj) = vol.as_object() {
                let source = vol_obj.get("source").and_then(|v| v.as_str()).unwrap_or("");
                let target = vol_obj.get("target").and_then(|v| v.as_str()).unwrap_or("");
                if !source.is_empty() && !target.is_empty() {
                    vol_list.push(dctypes::Volumes::Simple(format!("{}:{}", source, target)));
                }
            }
        }
        if !vol_list.is_empty() {
            service.volumes = vol_list;
        }
    }

    // Networks
    let network_names: Vec<String> = params
        .get("networks")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|n| n.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| vec!["trydirect_network".to_string()]);

    service.networks = dctypes::Networks::Simple(network_names.clone());

    // Depends on
    if let Some(depends_on) = params.get("depends_on").and_then(|v| v.as_array()) {
        let deps: Vec<String> = depends_on
            .iter()
            .filter_map(|d| d.as_str().map(|s| s.to_string()))
            .collect();
        if !deps.is_empty() {
            service.depends_on = dctypes::DependsOnOptions::Simple(deps);
        }
    }

    // Labels
    if let Some(labels) = params.get("labels").and_then(|v| v.as_object()) {
        let mut label_map = IndexMap::new();
        for (key, value) in labels {
            let val_str = match value {
                serde_json::Value::String(s) => s.clone(),
                _ => value.to_string(),
            };
            label_map.insert(key.clone(), val_str);
        }
        if !label_map.is_empty() {
            service.labels = dctypes::Labels::Map(label_map);
        }
    }

    // Build compose structure
    let mut services = IndexMap::new();
    services.insert(app_code.to_string(), Some(service));

    // Build networks section
    let mut networks_map = IndexMap::new();
    for net_name in &network_names {
        networks_map.insert(
            net_name.clone(),
            dctypes::MapOrEmpty::Map(dctypes::NetworkSettings {
                driver: Some("bridge".to_string()),
                ..Default::default()
            }),
        );
    }

    let compose = dctypes::Compose {
        version: Some("3.8".to_string()),
        services: dctypes::Services(services),
        networks: dctypes::ComposeNetworks(networks_map),
        ..Default::default()
    };

    serde_yaml::to_string(&compose)
        .map_err(|err| format!("Failed to serialize docker-compose: {}", err))
}
