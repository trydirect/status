use crate::models;
use serde::{Deserialize, Serialize};
use serde_valid::Validate;

#[derive(Serialize, Deserialize, Debug, Validate)]
pub struct UserEditRating {
    #[validate(max_length = 1000)]
    pub comment: Option<String>, // always linked to a product
    #[validate(minimum = 0)]
    #[validate(maximum = 10)]
    pub rate: Option<i32>, //
}

impl UserEditRating {
    pub fn update(self, rating: &mut models::Rating) {
        if let Some(comment) = self.comment {
            rating.comment = Some(comment);
        }

        if let Some(rate) = self.rate {
            rating.rate = Some(rate);
        }
    }
}
