use crate::db;
use crate::helpers::JsonResponse;
use crate::models;
use crate::models::Cloud;
use actix_web::{delete, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;

#[tracing::instrument(name = "Delete cloud record of a user.", skip_all)]
#[delete("/{id}")]
pub async fn item(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    // Get cloud apps of logged user only
    let (id,) = path.into_inner();

    let cloud = db::cloud::fetch(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<models::Cloud>::build().internal_server_error(err))
        .and_then(|cloud| match cloud {
            Some(cloud) if cloud.user_id != user.id => {
                Err(JsonResponse::<models::Cloud>::build().not_found("not found"))
            }
            Some(cloud) => Ok(cloud),
            None => Err(JsonResponse::<models::Cloud>::build().not_found("not found")),
        })?;

    db::cloud::delete(pg_pool.get_ref(), cloud.id, &user.id)
        .await
        .map_err(|err| JsonResponse::<Cloud>::build().internal_server_error(err))
        .and_then(|result| match result {
            true => Ok(JsonResponse::<Cloud>::build().ok("Deleted")),
            _ => Err(JsonResponse::<Cloud>::build().bad_request("Could not delete")),
        })
}
