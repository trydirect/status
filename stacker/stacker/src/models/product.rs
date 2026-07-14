use chrono::{DateTime, Utc};

pub struct Product {
    // Product - is an external object that we want to store in the database,
    // that can be a project or an app in the project. feature, service, web app etc.
    // id - is a unique identifier for the product
    // user_id - is a unique identifier for the user
    // rating - is a rating of the product
    // product type project & app,
    // id is generated based on the product type and external obj_id
    pub id: i32,          //primary key, for better data management
    pub obj_id: i32,      // external product ID db, no autoincrement, example: 100
    pub obj_type: String, // project | app, unique index
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
