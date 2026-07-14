use crate::forms::project::network::Network;
use docker_compose_types as dctypes;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComposeNetworks {
    pub networks: Option<Vec<Network>>,
}

impl Into<IndexMap<String, dctypes::MapOrEmpty<dctypes::NetworkSettings>>> for ComposeNetworks {
    fn into(self) -> IndexMap<String, dctypes::MapOrEmpty<dctypes::NetworkSettings>> {
        // let mut default_networks = vec![Network::default()];
        let mut default_networks = vec![];

        let networks = match self.networks {
            None => default_networks,
            Some(mut nets) => {
                if !nets.is_empty() {
                    nets.append(&mut default_networks);
                }
                nets
            }
        };

        let networks = networks
            .into_iter()
            .map(|net| (net.name.clone(), dctypes::MapOrEmpty::Map(net.into())))
            .collect::<IndexMap<String, _>>();

        tracing::debug!("networks collected {:?}", &networks);

        networks
    }
}
