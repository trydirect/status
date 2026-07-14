use crate::models;
use serde::{Deserialize, Serialize};
use serde_valid::Validate;

#[derive(Serialize, Deserialize, Debug, Validate)]
pub struct AddRating {
    pub obj_id: i32,                    // product external id
    pub category: models::RateCategory, // rating of product | rating of service etc
    #[validate(max_length = 1000)]
    pub comment: Option<String>, // always linked to a product
    #[validate(minimum = 0)]
    #[validate(maximum = 10)]
    pub rate: i32, //
}

impl Into<models::Rating> for AddRating {
    fn into(self) -> models::Rating {
        let mut rating = models::Rating::default();
        rating.obj_id = self.obj_id;
        rating.category = self.category.into();
        rating.hidden = Some(false);
        rating.rate = Some(self.rate);
        rating.comment = self.comment;

        rating
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_valid::Validate;

    #[test]
    fn test_add_rating_into_model() {
        let rating = AddRating {
            obj_id: 42,
            category: models::RateCategory::Application,
            comment: Some("Great app!".to_string()),
            rate: 8,
        };
        let model: models::Rating = rating.into();
        assert_eq!(model.obj_id, 42);
        assert_eq!(model.hidden, Some(false));
        assert_eq!(model.rate, Some(8));
        assert_eq!(model.comment, Some("Great app!".to_string()));
    }

    #[test]
    fn test_add_rating_no_comment() {
        let rating = AddRating {
            obj_id: 1,
            category: models::RateCategory::Cloud,
            comment: None,
            rate: 5,
        };
        let model: models::Rating = rating.into();
        assert!(model.comment.is_none());
        assert_eq!(model.rate, Some(5));
    }

    #[test]
    fn test_add_rating_validation_valid() {
        let rating = AddRating {
            obj_id: 1,
            category: models::RateCategory::Price,
            comment: Some("OK".to_string()),
            rate: 5,
        };
        assert!(rating.validate().is_ok());
    }

    #[test]
    fn test_add_rating_validation_rate_too_high() {
        let rating = AddRating {
            obj_id: 1,
            category: models::RateCategory::Design,
            comment: None,
            rate: 11, // max is 10
        };
        assert!(rating.validate().is_err());
    }

    #[test]
    fn test_add_rating_validation_rate_negative() {
        let rating = AddRating {
            obj_id: 1,
            category: models::RateCategory::Design,
            comment: None,
            rate: -1, // min is 0
        };
        assert!(rating.validate().is_err());
    }

    #[test]
    fn test_add_rating_validation_comment_too_long() {
        let rating = AddRating {
            obj_id: 1,
            category: models::RateCategory::TechSupport,
            comment: Some("a".repeat(1001)), // max is 1000
            rate: 5,
        };
        assert!(rating.validate().is_err());
    }
}
