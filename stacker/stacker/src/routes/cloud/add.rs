use crate::db;
use crate::forms;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{post, web, Responder, Result};
use serde_valid::Validate;
use sqlx::PgPool;
use std::ops::Deref;
use std::sync::Arc;

#[tracing::instrument(name = "Add cloud.", skip_all)]
#[post("")]
pub async fn add(
    user: web::ReqData<Arc<models::User>>,
    mut form: web::Json<forms::cloud::CloudForm>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    if !form.validate().is_ok() {
        let errors = form.validate().unwrap_err().to_string();
        let err_msg = format!("Invalid data received {:?}", &errors);
        tracing::debug!(err_msg);

        return Err(JsonResponse::<models::Project>::build().form_error(errors));
    }

    form.user_id = Some(user.id.clone());
    let cloud: models::Cloud = form.deref().into();

    // Validate that encryption succeeded when save_token is enabled.
    // encrypt_field() returns None on failure, which would silently store NULL credentials.
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

    db::cloud::insert(pg_pool.get_ref(), cloud)
        .await
        .map(|cloud| JsonResponse::build().set_item(cloud).ok("success"))
        .map_err(|_err| {
            JsonResponse::<models::Cloud>::build().internal_server_error("Failed to insert")
        })
}
