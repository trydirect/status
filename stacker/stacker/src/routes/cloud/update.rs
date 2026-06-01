use crate::db;
use crate::forms;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{put, web, web::Data, Responder, Result};
use serde_valid::Validate;
use sqlx::PgPool;
use std::ops::Deref;
use std::sync::Arc;

#[tracing::instrument(name = "Update cloud.", skip_all)]
#[put("/{id}")]
pub async fn item(
    path: web::Path<(i32,)>,
    form: web::Json<forms::cloud::CloudForm>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: Data<PgPool>,
) -> Result<impl Responder> {
    let id = path.0;
    let cloud_row = db::cloud::fetch(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<models::Cloud>::build().internal_server_error(err))
        .and_then(|cloud| match cloud {
            Some(cloud) if cloud.user_id != user.id => {
                Err(JsonResponse::<models::Project>::build().not_found("Cloud not found"))
            }
            Some(cloud) => Ok(cloud),
            None => Err(JsonResponse::<models::Cloud>::build().not_found("Cloud not found")),
        })?;

    if let Err(errors) = form.validate() {
        return Err(JsonResponse::<models::Cloud>::build().form_error(errors.to_string()));
    }

    let mut cloud: models::Cloud = form.deref().into();
    cloud.id = cloud_row.id;
    cloud.user_id = user.id.clone();

    // Validate that encryption succeeded when save_token is enabled.
    if cloud.save_token == Some(true) {
        let has_token = cloud.cloud_token.is_some();
        let has_key_secret = cloud.cloud_key.is_some() && cloud.cloud_secret.is_some();
        if !has_token && !has_key_secret {
            tracing::error!(
                "Cloud credential encryption failed for provider '{}'. \
                 Check that SECURITY_KEY is set and is exactly 32 bytes.",
                cloud.provider
            );
            return Err(JsonResponse::<models::Cloud>::build()
                .bad_request("Failed to encrypt cloud credentials. Please contact support."));
        }
    }

    tracing::debug!("Updating cloud id={} provider={}", cloud.id, cloud.provider);

    db::cloud::update(pg_pool.get_ref(), cloud)
        .await
        .map(|cloud| {
            JsonResponse::<models::Cloud>::build()
                .set_item(cloud)
                .ok("success")
        })
        .map_err(|err| {
            tracing::error!("Failed to execute query: {:?}", err);
            JsonResponse::<models::Cloud>::build().internal_server_error("Could not update")
        })
}
