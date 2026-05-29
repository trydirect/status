use crate::db;
use crate::forms;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{post, web, Responder, Result};
use serde_valid::Validate;
use sqlx::PgPool;
use std::sync::Arc;

#[tracing::instrument(name = "Admin add agreement.", skip_all)]
#[post("")]
pub async fn admin_add_handler(
    form: web::Json<forms::agreement::AdminAddAgreement>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    if let Err(errors) = form.validate() {
        return Err(JsonResponse::<models::Agreement>::build().form_error(errors.to_string()));
    }

    let item: models::Agreement = form.into_inner().into();
    db::agreement::insert(pg_pool.get_ref(), item)
        .await
        .map(|item| {
            JsonResponse::<models::Agreement>::build()
                .set_item(Into::<models::Agreement>::into(item))
                .ok("success")
        })
        .map_err(|err| {
            tracing::error!("Failed to execute query: {:?}", err);
            JsonResponse::<models::Agreement>::build().internal_server_error("Record not added")
        })
}

#[tracing::instrument(name = "Add user agreement.", skip_all)]
#[post("")]
pub async fn user_add_handler(
    user: web::ReqData<Arc<models::User>>,
    form: web::Json<forms::agreement::UserAddAgreement>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    if let Err(errors) = form.validate() {
        return Err(JsonResponse::<models::UserAgreement>::build().form_error(errors.to_string()));
    }

    let agreement = db::agreement::fetch(pg_pool.get_ref(), form.agrt_id)
        .await
        .map_err(|_msg| JsonResponse::<models::UserAgreement>::build().internal_server_error(_msg))?
        .ok_or_else(|| JsonResponse::<models::UserAgreement>::build().not_found("not found"))?;

    let user_id = user.id.as_str();
    let user_agreement =
        db::agreement::fetch_by_user_and_agreement(pg_pool.get_ref(), user_id, agreement.id)
            .await
            .map_err(|err| {
                JsonResponse::<models::UserAgreement>::build().internal_server_error(err)
            })?;

    if user_agreement.is_some() {
        return Err(JsonResponse::<models::UserAgreement>::build().bad_request("already signed"));
    }

    let mut item: models::UserAgreement = form.into_inner().into();
    item.user_id = user.id.clone();

    db::agreement::insert_by_user(pg_pool.get_ref(), item)
        .await
        .map(|item| {
            JsonResponse::build()
                .set_item(Into::<models::UserAgreement>::into(item))
                .ok("success")
        })
        .map_err(|_err| {
            JsonResponse::<models::UserAgreement>::build().internal_server_error("Failed to insert")
        })
}
