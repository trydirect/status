use crate::forms::project::*;
use serde::{Deserialize, Serialize};
use serde_valid::Validate;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct Feature {
    // #[serde(rename(deserialize = "sharedPorts"))]
    // #[serde(rename(serialize = "shared_ports"))]
    // #[serde(alias = "shared_ports")]
    // pub shared_ports: Option<Vec<Port>>,
    #[serde(flatten)]
    pub app: App,
    pub custom: Option<bool>,
}
