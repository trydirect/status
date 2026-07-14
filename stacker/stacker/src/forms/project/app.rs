use crate::forms;
use crate::forms::project::network::Network;
use crate::forms::project::{replace_id_with_name, DockerImage};
use docker_compose_types as dctypes;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_valid::Validate;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct App {
    #[serde(rename = "_etag")]
    #[validate(min_length = 3)]
    #[validate(max_length = 255)]
    pub etag: Option<String>,
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(rename = "_created")]
    pub created: Option<String>,
    #[serde(rename = "_updated")]
    pub updated: Option<String>,
    #[validate(min_length = 3)]
    #[validate(max_length = 50)]
    pub name: String,
    #[validate(min_length = 3)]
    #[validate(max_length = 50)]
    pub code: String,
    #[validate(min_length = 3)]
    #[validate(max_length = 50)]
    #[serde(rename = "type")]
    pub type_field: String,
    #[serde(flatten)]
    pub role: forms::project::Role,
    pub default: Option<bool>,
    pub versions: Option<Vec<forms::project::Version>>,
    #[serde(flatten)]
    #[validate]
    pub docker_image: DockerImage,
    #[serde(flatten)]
    #[validate]
    pub requirements: forms::project::Requirements,
    #[validate(minimum = 1)]
    pub popularity: Option<u32>,
    pub commercial: Option<bool>,
    pub subscription: Option<Value>,
    pub autodeploy: Option<bool>,
    pub suggested: Option<bool>,
    pub dependency: Option<Value>,
    pub avoid_render: Option<bool>,
    pub price: Option<forms::project::Price>,
    pub icon: Option<forms::project::Icon>,
    pub domain: Option<String>,
    pub category_id: Option<u32>,
    pub parent_app_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descr: Option<String>,
    pub full_description: Option<String>,
    pub description: Option<String>,
    pub plan_type: Option<String>,
    pub ansible_var: Option<String>,
    pub repo_dir: Option<String>,
    pub url_app: Option<String>,
    pub url_git: Option<String>,
    #[validate(enumerate("always", "no", "unless-stopped", "on-failure"))]
    pub restart: String,
    pub command: Option<String>,
    pub entrypoint: Option<String>,
    pub volumes: Option<Vec<forms::project::Volume>>,
    #[serde(flatten)]
    pub environment: forms::project::Environment,
    #[serde(flatten)]
    pub network: forms::project::ServiceNetworks,
    #[validate]
    pub shared_ports: Option<Vec<forms::project::Port>>,
}

impl App {
    #[tracing::instrument(name = "named_volumes", skip_all)]
    pub fn named_volumes(&self) -> IndexMap<String, dctypes::MapOrEmpty<dctypes::ComposeVolume>> {
        let mut named_volumes = IndexMap::default();

        if self.volumes.is_none() {
            return named_volumes;
        }

        for volume in self.volumes.as_ref().unwrap() {
            if !volume.is_named_docker_volume() {
                continue;
            }

            let k = volume.host_path.as_ref().unwrap().clone();
            let v = dctypes::MapOrEmpty::Map(volume.into());
            named_volumes.insert(k, v);
        }

        tracing::debug!("Named volumes: {:?}", named_volumes);
        named_volumes
    }

    pub(crate) fn try_into_service(
        &self,
        all_networks: &Vec<Network>,
    ) -> Result<dctypes::Service, String> {
        let mut service = dctypes::Service {
            image: Some(self.docker_image.to_string()),
            ..Default::default()
        };

        let networks = dctypes::Networks::try_from(&self.network).unwrap_or_default();

        let networks = replace_id_with_name(networks, all_networks);
        service.networks = dctypes::Networks::Simple(networks);

        let ports: Vec<dctypes::Port> = match &self.shared_ports {
            Some(ports) => {
                let mut collector = vec![];
                for port in ports {
                    collector.push(port.try_into()?);
                }
                collector
            }
            None => vec![],
        };

        let volumes: Vec<dctypes::Volumes> = match &self.volumes {
            Some(volumes) => {
                let mut collector = vec![];
                for volume in volumes {
                    collector.push(dctypes::Volumes::Advanced(volume.try_into()?));
                }

                collector
            }
            None => vec![],
        };

        let mut envs = IndexMap::new();
        if let Some(item) = self.environment.environment.clone() {
            let items = item
                .into_iter()
                .map(|env_var| {
                    (
                        env_var.key,
                        Some(dctypes::SingleValue::String(env_var.value.clone())),
                    )
                })
                .collect::<IndexMap<_, _>>();

            envs.extend(items);
        }

        service.ports = dctypes::Ports::Long(ports);
        service.restart = Some(self.restart.clone());
        if let Some(cmd) = self.command.as_deref() {
            if !cmd.is_empty() {
                service.command = Some(dctypes::Command::Simple(cmd.to_owned()));
            }
        }

        if let Some(entry) = self.entrypoint.as_deref() {
            if !entry.is_empty() {
                service.entrypoint = Some(dctypes::Entrypoint::Simple(entry.to_owned()));
            }
        }
        service.volumes = volumes;
        service.environment = dctypes::Environment::KvPair(envs);

        Ok(service)
    }
}

impl AsRef<forms::project::DockerImage> for App {
    fn as_ref(&self) -> &forms::project::DockerImage {
        &self.docker_image
    }
}
