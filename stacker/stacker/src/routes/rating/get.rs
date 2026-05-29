use crate::db;
use crate::helpers::JsonResponse;
use crate::views;
use actix_web::{get, web, Responder, Result};
use sqlx::PgPool;
use std::convert::Into;

#[tracing::instrument(name = "Anonymouse get rating.", skip_all)]
#[get("/{id}")]
pub async fn anonymous_get_handler(
    path: web::Path<(i32,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let rate_id = path.0;
    let rating = db::rating::fetch(pg_pool.get_ref(), rate_id)
        .await
        .map_err(|_err| JsonResponse::<views::rating::Anonymous>::build().internal_server_error(""))
        .and_then(|rating| match rating {
            Some(rating) if rating.hidden == Some(false) => Ok(rating),
            _ => Err(JsonResponse::<views::rating::Anonymous>::build().not_found("not found")),
        })?;

    Ok(JsonResponse::build()
        .set_item(Into::<views::rating::Anonymous>::into(rating))
        .ok("OK"))
}

#[tracing::instrument(name = "Anonymous get all ratings.", skip_all)]
#[get("")]
pub async fn anonymous_list_handler(
    _path: web::Path<()>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    db::rating::fetch_all_visible(pg_pool.get_ref())
        .await
        .map(|ratings| {
            let ratings = ratings
                .into_iter()
                .map(Into::into)
                .collect::<Vec<views::rating::Anonymous>>();

            JsonResponse::build().set_list(ratings).ok("OK")
        })
        .map_err(|_err| JsonResponse::<views::rating::Anonymous>::build().internal_server_error(""))
}

#[tracing::instrument(name = "Admin get rating.", skip_all)]
#[get("/{id}")]
pub async fn admin_get_handler(
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

    Ok(JsonResponse::build()
        .set_item(Into::<views::rating::Admin>::into(rating))
        .ok("OK"))
}

#[tracing::instrument(name = "Admin get the list of ratings.", skip_all)]
#[get("")]
pub async fn admin_list_handler(
    _path: web::Path<()>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    db::rating::fetch_all(pg_pool.get_ref())
        .await
        .map(|ratings| {
            let ratings = ratings
                .into_iter()
                .map(Into::into)
                .collect::<Vec<views::rating::Admin>>();

            JsonResponse::build().set_list(ratings).ok("OK")
        })
        .map_err(|_err| JsonResponse::<views::rating::Admin>::build().internal_server_error(""))
}
