use crate::models;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::convert::From;

#[derive(Debug, Serialize, Default)]
pub struct Admin {
    pub id: i32,
    pub user_id: String, // external user_id, 100, taken using token (middleware?)
    pub obj_id: i32,     // id of the external object
    pub category: models::RateCategory, // rating of product | rating of service etc
    pub comment: Option<String>, // always linked to a product
    pub hidden: Option<bool>, // rating can be hidden for non-adequate user behaviour
    pub rate: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<models::Rating> for Admin {
    fn from(rating: models::Rating) -> Self {
        Self {
            id: rating.id,
            user_id: rating.user_id,
            obj_id: rating.obj_id,
            category: rating.category,
            comment: rating.comment,
            hidden: rating.hidden,
            rate: rating.rate,
            created_at: rating.created_at,
            updated_at: rating.updated_at,
        }
    }
}
