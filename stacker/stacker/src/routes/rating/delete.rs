use crate::db;
use crate::helpers::JsonResponse;
use crate::models;
use crate::views;
use actix_web::{delete, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;

#[tracing::instrument(name = "User delete rating.", skip_all)]
#[delete("/{id}")]
pub async fn user_delete_handler(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let rate_id = path.0;
    let mut rating = db::rating::fetch(pg_pool.get_ref(), rate_id)
        .await
        .map_err(|_err| JsonResponse::<views::rating::User>::build().internal_server_error(""))
        .and_then(|rating| match rating {
            Some(rating) if rating.user_id == user.id && rating.hidden == Some(false) => Ok(rating),
            _ => Err(JsonResponse::<views::rating::User>::build().not_found("not found")),
        })?;

    let _ = rating.hidden.insert(true);

    db::rating::update(pg_pool.get_ref(), rating)
        .await
        .map(|_rating| JsonResponse::<views::rating::User>::build().ok("success"))
        .map_err(|err| {
            tracing::error!("Failed to execute query: {:?}", err);
            JsonResponse::<views::rating::User>::build().internal_server_error("Rating not update")
        })
}

#[tracing::instrument(name = "Admin delete rating.", skip_all)]
#[delete("/{id}")]
pub async fn admin_delete_handler(
    _user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let rate_id = path.0;
    let rating = db::rating::fetch(pg_pool.get_ref(), rate_id)
        .await
        .map_err(|_err| JsonResponse::<views::rating::Admin>::build().internal_server_error(""))
        .and_then(|rating| match rating {
            Some(rating) => Ok(rating),
            _ => Err(JsonResponse::<views::rating::Admin>::build().not_found("not found")),
        })?;

    db::rating::delete(pg_pool.get_ref(), rating)
        .await
        .map(|_| JsonResponse::<views::rating::Admin>::build().ok("success"))
        .map_err(|err| {
            tracing::error!("Failed to execute query: {:?}", err);
            JsonResponse::<views::rating::Admin>::build()
                .internal_server_error("Rating not deleted")
        })
}
