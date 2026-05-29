use crate::configuration::get_configuration;
use crate::middleware;
use actix_web::{rt, web, Result};
use casbin::CoreApi;
use sqlx::PgPool;

pub struct CasbinCommand {
    action: String,
    path: String,
    subject: String,
}

impl CasbinCommand {
    pub fn new(action: String, path: String, subject: String) -> Self {
        Self {
            action,
            path,
            subject,
        }
    }
}

impl crate::console::commands::CallableTrait for CasbinCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        rt::System::new().block_on(async {
            let settings = get_configuration().expect("Failed to read configuration.");
            let db_pool = PgPool::connect(&settings.database.connection_string())
                .await
                .expect("Failed to connect to database.");

            let settings = web::Data::new(settings);
            let _db_pool = web::Data::new(db_pool);

            let mut authorization_service =
                middleware::authorization::try_new(settings.database.connection_string()).await?;
            let casbin_enforcer = authorization_service.get_enforcer();

            let mut lock = casbin_enforcer.write().await;
            let policies = lock
                .get_model()
                .get_model()
                .get("p")
                .unwrap()
                .get("p")
                .unwrap()
                .get_policy();
            for (pos, policy) in policies.iter().enumerate() {
                println!("{pos}: {policy:?}");
            }

            #[cfg(feature = "explain")]
            {
                lock.enable_log(true);
            }
            let _ = lock.enforce_mut(vec![
                self.subject.clone(),
                self.path.clone(),
                self.action.clone(),
            ]);

            Ok(())
        })
    }
}
