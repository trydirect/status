use crate::models;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_valid::Validate;

#[derive(Serialize, Deserialize, Debug, Validate)]
pub struct UserAddAgreement {
    pub agrt_id: i32,
}

impl Into<models::UserAgreement> for UserAddAgreement {
    fn into(self) -> models::UserAgreement {
        let mut item = models::UserAgreement::default();
        item.agrt_id = self.agrt_id;
        item.created_at = Utc::now();
        item.updated_at = Utc::now();
        item
    }
}
