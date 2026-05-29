use crate::db;
use crate::forms;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{put, web, Responder, Result};
use serde_valid::Validate;
use sqlx::PgPool;

#[tracing::instrument(name = "Admin update agreement.", skip_all)]
#[put("/{id}")]
pub async fn admin_update_handler(
    path: web::Path<(i32,)>,
    form: web::Json<forms::agreement::AdminAddAgreement>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    if let Err(errors) = form.validate() {
        return Err(JsonResponse::<models::Agreement>::build().form_error(errors.to_string()));
    }

    let id = path.0;
    let mut item = db::agreement::fetch(pg_pool.get_ref(), id)
        .await
        .map_err(|_err| JsonResponse::<models::Agreement>::build().internal_server_error(""))
        .and_then(|item| match item {
            Some(item) => Ok(item),
            _ => Err(JsonResponse::<models::Agreement>::build().not_found("not found")),
        })?;

    form.into_inner().update(&mut item);

    db::agreement::update(pg_pool.get_ref(), item)
        .await
        .map(|item| {
            JsonResponse::<models::Agreement>::build()
                .set_item(Into::<models::Agreement>::into(item))
                .ok("success")
        })
        .map_err(|err| {
            tracing::error!("Failed to execute query: {:?}", err);
            JsonResponse::<models::Agreement>::build()
                .internal_server_error("Agreement not updated")
        })
}
