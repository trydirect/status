use crate::configuration::get_configuration;
use actix_web::rt;
use actix_web::web;
use sqlx::PgPool;

pub struct NewCommand {
    user_id: i32,
}

impl NewCommand {
    pub fn new(user_id: i32) -> Self {
        Self { user_id }
    }
}

impl crate::console::commands::CallableTrait for NewCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        rt::System::new().block_on(async {
            let settings = get_configuration().expect("Failed to read configuration.");
            let db_pool = PgPool::connect(&settings.database.connection_string())
                .await
                .expect("Failed to connect to database.");

            let settings = web::Data::new(settings);
            let db_pool = web::Data::new(db_pool);

            //todo get user from TryDirect
            let user = crate::models::user::User {
                id: format!("{}", self.user_id),
                first_name: "first_name".to_string(),
                last_name: "last_name".to_string(),
                email: "email".to_string(),
                email_confirmed: true,
                role: "role".to_string(),
                mfa_verified: false,
                access_token: None,
            };
            crate::routes::client::add_handler_inner(&user.id, settings, db_pool).await?;

            Ok(())
        })
    }
}
