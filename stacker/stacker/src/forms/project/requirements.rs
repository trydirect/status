use serde::{Deserialize, Serialize};
use serde_valid::Validate;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct Requirements {
    #[validate(min_length = 1)]
    #[validate(max_length = 10)]
    #[validate(pattern = r"^[0-9]*\.?[0-9]+$")]
    pub cpu: Option<String>,
    #[validate(min_length = 1)]
    #[validate(max_length = 10)]
    #[validate(pattern = r"^[0-9]*\.?[0-9]+Gb?$")]
    #[serde(rename = "disk_size")]
    pub disk_size: Option<String>,
    #[serde(rename = "ram_size")]
    #[validate(min_length = 1)]
    #[validate(max_length = 10)]
    #[validate(pattern = r"^[0-9]*\.?[0-9]+Gb?$")]
    pub ram_size: Option<String>,
}
