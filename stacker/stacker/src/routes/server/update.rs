use crate::db;
use crate::forms;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{put, web, web::Data, Responder, Result};
use serde_valid::Validate;
use sqlx::PgPool;
use std::ops::Deref;
use std::sync::Arc;

#[tracing::instrument(name = "Update server.", skip_all)]
#[put("/{id}")]
pub async fn item(
    path: web::Path<(i32,)>,
    form: web::Json<forms::server::ServerForm>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: Data<PgPool>,
) -> Result<impl Responder> {
    let id = path.0;
    let server_row = db::server::fetch(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<models::Server>::build().internal_server_error(err))
        .and_then(|server| match server {
            Some(server) if server.user_id != user.id => {
                Err(JsonResponse::<models::Project>::build().not_found("Server not found"))
            }
            Some(server) => Ok(server),
            None => Err(JsonResponse::<models::Server>::build().not_found("Server not found")),
        })?;

    if let Err(errors) = form.validate() {
        return Err(JsonResponse::<models::Server>::build().form_error(errors.to_string()));
    }

    let mut server: models::Server = form.deref().into();
    server.id = server_row.id;
    server.project_id = server_row.project_id;
    server.user_id = user.id.clone();

    // Preserve existing values when form fields are not provided (None)
    // This prevents accidental data loss (e.g., IP getting wiped to NULL)
    if server.srv_ip.is_none() {
        server.srv_ip = server_row.srv_ip.clone();
    }
    if server.ssh_port.is_none() {
        server.ssh_port = server_row.ssh_port;
    }
    if server.ssh_user.is_none() {
        server.ssh_user = server_row.ssh_user.clone();
    }
    if server.name.is_none() {
        server.name = server_row.name.clone();
    }
    if server.cloud_id.is_none() {
        server.cloud_id = server_row.cloud_id;
    }
    if server.region.is_none() {
        server.region = server_row.region.clone();
    }
    if server.zone.is_none() {
        server.zone = server_row.zone.clone();
    }
    if server.server.is_none() {
        server.server = server_row.server.clone();
    }
    if server.os.is_none() {
        server.os = server_row.os.clone();
    }
    if server.disk_type.is_none() {
        server.disk_type = server_row.disk_type.clone();
    }
    if server.vault_key_path.is_none() {
        server.vault_key_path = server_row.vault_key_path.clone();
    }
    // Preserve key_status from existing record (not settable via form)
    server.key_status = server_row.key_status.clone();

    tracing::debug!("Updating server {:?}", server);

    db::server::update(pg_pool.get_ref(), server)
        .await
        .map(|server| {
            JsonResponse::<models::Server>::build()
                .set_item(server)
                .ok("success")
        })
        .map_err(|err| {
            tracing::error!("Failed to execute query: {:?}", err);
            JsonResponse::<models::Server>::build().internal_server_error("Could not update server")
        })
}
