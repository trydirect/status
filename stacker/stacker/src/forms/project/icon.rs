use crate::forms::project::*;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Icon {
    pub light: IconLight,
    pub dark: IconDark,
}
