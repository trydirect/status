use serde::{Deserialize, Serialize};
use serde_valid::Validate;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct Version {
    #[serde(rename = "_etag")]
    pub etag: Option<String>,
    #[serde(rename = "_id")]
    pub id: u32,
    #[serde(rename = "_created")]
    pub created: Option<String>,
    #[serde(rename = "_updated")]
    pub updated: Option<String>,
    pub app_id: Option<u32>,
    pub name: String,
    #[validate(min_length = 3)]
    #[validate(max_length = 20)]
    pub version: String,
    #[serde(rename = "update_status")]
    pub update_status: Option<String>,
    #[validate(min_length = 3)]
    #[validate(max_length = 20)]
    pub tag: String,
}
