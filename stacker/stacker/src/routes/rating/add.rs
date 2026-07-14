use crate::db;
use crate::forms;
use crate::helpers::JsonResponse;
use crate::models;
use crate::views;
use actix_web::{post, web, Responder, Result};
use serde_valid::Validate;
use sqlx::PgPool;
use std::sync::Arc;

#[tracing::instrument(name = "Add rating.", skip_all)]
#[post("")]
pub async fn user_add_handler(
    user: web::ReqData<Arc<models::User>>,
    form: web::Json<forms::rating::Add>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    if let Err(errors) = form.validate() {
        return Err(JsonResponse::<views::rating::User>::build().form_error(errors.to_string()));
    }

    let _product = db::product::fetch_by_obj(pg_pool.get_ref(), form.obj_id)
        .await
        .map_err(|_msg| JsonResponse::<views::rating::User>::build().internal_server_error(_msg))?
        .ok_or_else(|| JsonResponse::<views::rating::User>::build().not_found("not found"))?;

    let rating = db::rating::fetch_by_obj_and_user_and_category(
        pg_pool.get_ref(),
        form.obj_id,
        user.id.clone(),
        form.category,
    )
    .await
    .map_err(|err| JsonResponse::<views::rating::User>::build().internal_server_error(err))?;

    if rating.is_some() {
        return Err(JsonResponse::<views::rating::User>::build().bad_request("already rated"));
    }

    let mut rating: models::Rating = form.into_inner().into();
    rating.user_id = user.id.clone();

    db::rating::insert(pg_pool.get_ref(), rating)
        .await
        .map(|rating| {
            JsonResponse::build()
                .set_item(Into::<views::rating::User>::into(rating))
                .ok("success")
        })
        .map_err(|_err| {
            JsonResponse::<views::rating::User>::build().internal_server_error("Failed to insert")
        })
}
