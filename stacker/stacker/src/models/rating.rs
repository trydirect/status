use crate::models;
use chrono::{DateTime, Utc};

#[derive(Debug, Default)]
pub struct Rating {
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
