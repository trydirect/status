use docker_compose_types::SingleValue;
use indexmap::IndexMap;
use serde_derive::{Deserialize, Serialize};
use serde_valid::Validate;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct NetworkDriver {
    // not implemented
}

impl Into<IndexMap<String, Option<SingleValue>>> for NetworkDriver {
    fn into(self) -> IndexMap<String, Option<SingleValue>> {
        IndexMap::new()
    }
}
