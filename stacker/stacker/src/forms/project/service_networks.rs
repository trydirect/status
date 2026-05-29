use docker_compose_types as dctypes;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceNetworks {
    pub network: Option<Vec<String>>,
}

impl TryFrom<&ServiceNetworks> for dctypes::Networks {
    type Error = ();

    fn try_from(service_networks: &ServiceNetworks) -> Result<dctypes::Networks, Self::Error> {
        let nets = match service_networks.network.as_ref() {
            Some(_nets) => _nets.clone(),
            None => {
                vec![]
            }
        };
        Ok(dctypes::Networks::Simple(nets.into()))
    }
}

// IndexMap
//
// impl Into<IndexMap<String, MapOrEmpty<NetworkSettings>>> for project::ComposeNetworks {
//     fn into(self) -> IndexMap<String, MapOrEmpty<NetworkSettings>> {
//
//         // let mut default_networks = vec![Network::default()];
//         let mut default_networks = vec![];
//
//         let networks = match self.networks {
//             None => {
//                 default_networks
//             }
//             Some(mut nets) => {
//                 if !nets.is_empty() {
//                     nets.append(&mut default_networks);
//                 }
//                 nets
//             }
//         };
//
//         let networks = networks
//             .into_iter()
//             .map(|net| {
//                 (net.name.clone(), MapOrEmpty::Map(net.into()))
//             }
//             )
//             .collect::<IndexMap<String, _>>();
//
//         tracing::debug!("networks collected {:?}", &networks);
//
//         networks
//     }
// }
