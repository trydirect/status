mod create;
pub mod dag;
mod delete;
mod deploy;
mod executions;
mod field_match;
mod get;
mod list;
pub mod resilience;
pub mod stream;
mod update;

pub use create::*;
pub use delete::*;
pub use deploy::*;
pub use executions::*;
pub use field_match::*;
pub use get::*;
pub use list::*;
pub use update::*;

use crate::db;
use crate::helpers::JsonResponse;
use crate::models::PipeInstance;
use sqlx::PgPool;

/// Verify that the requesting user owns the pipe instance.
/// For remote pipes (deployment_hash is Some): checks deployment ownership.
/// For local pipes (deployment_hash is None): checks created_by field.
pub(crate) async fn verify_pipe_owner(
    pool: &PgPool,
    instance: &PipeInstance,
    user_id: &str,
) -> Result<(), actix_web::Error> {
    match &instance.deployment_hash {
        Some(hash) => {
            let deployment = db::deployment::fetch_by_deployment_hash(pool, hash)
                .await
                .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;
            match &deployment {
                Some(d) if d.user_id.as_deref() == Some(user_id) => Ok(()),
                _ => Err(JsonResponse::<String>::not_found("Pipe instance not found")),
            }
        }
        None => {
            if instance.created_by == user_id {
                Ok(())
            } else {
                Err(JsonResponse::<String>::not_found("Pipe instance not found"))
            }
        }
    }
}
