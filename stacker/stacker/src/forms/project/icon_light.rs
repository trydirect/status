use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IconLight {
    pub width: Option<i64>,
    pub height: Option<i64>,
    pub image: Option<String>,
}
