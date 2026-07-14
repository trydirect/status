use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IconDark {
    width: Option<i32>,
    height: Option<i32>,
    image: Option<String>,
}
