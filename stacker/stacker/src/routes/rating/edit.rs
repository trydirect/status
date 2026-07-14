use crate::db;
use crate::forms;
use crate::helpers::JsonResponse;
use crate::models;
use crate::views;
use actix_web::{put, web, Responder, Result};
use serde_valid::Validate;
use sqlx::PgPool;
use std::sync::Arc;

// workflow
// add, update, list, get(user_id), ACL,
// ACL - access to func for a user
// ACL - access to objects for a user

#[tracing::instrument(name = "User edit rating.", skip_all)]
#[put("/{id}")]
pub async fn user_edit_handler(
    path: web::Path<(i32,)>,
    user: web::ReqData<Arc<models::User>>,
    form: web::Json<forms::rating::UserEdit>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    if let Err(errors) = form.validate() {
        return Err(JsonResponse::<views::rating::User>::build().form_error(errors.to_string()));
    }

    let rate_id = path.0;
    let mut rating = db::rating::fetch(pg_pool.get_ref(), rate_id)
        .await
        .map_err(|_err| JsonResponse::<views::rating::User>::build().internal_server_error(""))
        .and_then(|rating| match rating {
            Some(rating) if rating.user_id == user.id && rating.hidden == Some(false) => Ok(rating),
            _ => Err(JsonResponse::<views::rating::User>::build().not_found("not found")),
        })?;

    form.into_inner().update(&mut rating);

    db::rating::update(pg_pool.get_ref(), rating)
        .await
        .map(|rating| {
            JsonResponse::build()
                .set_item(Into::<views::rating::User>::into(rating))
                .ok("success")
        })
        .map_err(|err| {
            tracing::error!("Failed to execute query: {:?}", err);
            JsonResponse::<views::rating::User>::build().internal_server_error("Rating not update")
        })
}

#[tracing::instrument(name = "Admin edit rating.", skip_all)]
#[put("/{id}")]
pub async fn admin_edit_handler(
    path: web::Path<(i32,)>,
    form: web::Json<forms::rating::AdminEdit>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    if let Err(errors) = form.validate() {
        return Err(JsonResponse::<views::rating::Admin>::build().form_error(errors.to_string()));
    }

    let rate_id = path.0;
    let mut rating = db::rating::fetch(pg_pool.get_ref(), rate_id)
        .await
        .map_err(|_err| JsonResponse::<views::rating::Admin>::build().internal_server_error(""))
        .and_then(|rating| match rating {
            Some(rating) => Ok(rating),
            _ => Err(JsonResponse::<views::rating::Admin>::build().not_found("not found")),
        })?;

    form.into_inner().update(&mut rating);

    db::rating::update(pg_pool.get_ref(), rating)
        .await
        .map(|rating| {
            JsonResponse::<views::rating::Admin>::build()
                .set_item(Into::<views::rating::Admin>::into(rating))
                .ok("success")
        })
        .map_err(|err| {
            tracing::error!("Failed to execute query: {:?}", err);
            JsonResponse::<views::rating::Admin>::build().internal_server_error("Rating not update")
        })
}
