use crate::models;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_valid::Validate;

#[derive(Serialize, Deserialize, Debug, Validate)]
pub struct Agreement {
    #[validate(max_length = 100)]
    pub name: String,
    #[validate(max_length = 5000)]
    pub text: String,
}

impl Into<models::Agreement> for Agreement {
    fn into(self) -> models::Agreement {
        let mut item = models::Agreement::default();
        item.name = self.name;
        item.text = self.text;
        item.created_at = Utc::now();
        item.updated_at = Utc::now();
        item
    }
}

impl Agreement {
    pub fn update(self, item: &mut models::Agreement) {
        item.name = self.name;
        item.name = self.text;
    }
}
