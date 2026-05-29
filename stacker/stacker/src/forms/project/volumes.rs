use crate::forms::project::*;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Volumes {
    volumes: Vec<Volume>,
}
