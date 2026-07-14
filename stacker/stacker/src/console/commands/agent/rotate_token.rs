use crate::configuration::get_configuration;
use crate::services::agent_dispatcher;
use actix_web::rt;
use sqlx::PgPool;

pub struct RotateTokenCommand {
    pub deployment_hash: String,
    pub new_token: String,
}

impl RotateTokenCommand {
    pub fn new(deployment_hash: String, new_token: String) -> Self {
        Self {
            deployment_hash,
            new_token,
        }
    }
}

impl crate::console::commands::CallableTrait for RotateTokenCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let deployment_hash = self.deployment_hash.clone();
        let new_token = self.new_token.clone();

        rt::System::new().block_on(async move {
            let settings = get_configuration().expect("Failed to read configuration.");
            let vault = crate::helpers::VaultClient::new(&settings.vault);

            let db_pool = PgPool::connect(&settings.database.connection_string())
                .await
                .expect("Failed to connect to database.");

            agent_dispatcher::rotate_token(&db_pool, &vault, &deployment_hash, &new_token)
                .await
                .map_err(|e| {
                    eprintln!("Rotate token failed: {}", e);
                    e
                })?;

            println!(
                "Rotated agent token for deployment_hash {} (stored in Vault)",
                deployment_hash
            );

            Ok(())
        })
    }
}
