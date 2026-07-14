// use crate::forms;
// use crate::helpers::JsonResponse;
// use crate::models;
// use crate::db;
// use actix_web::{post, web, Responder, Result};
// use sqlx::PgPool;
// use tracing::Instrument;
// use std::sync::Arc;
// use serde_valid::Validate;

// workflow
// add, update, list, get(user_id), ACL,
// ACL - access to func for a user
// ACL - access to objects for a user

// #[tracing::instrument(name = "Add server.", skip_all)]
// #[post("")]
// pub async fn add(
//     user: web::ReqData<Arc<models::User>>,
//     form: web::Json<forms::server::Server>,
//     pg_pool: web::Data<PgPool>,
// ) -> Result<impl Responder> {
// //
// //     if !form.validate().is_ok() {
// //         let errors = form.validate().unwrap_err().to_string();
// //         let err_msg = format!("Invalid data received {:?}", &errors);
// //         tracing::debug!(err_msg);
// //
// //         return Err(JsonResponse::<models::Project>::build().form_error(errors));
// //     }
// //
// //
// //     db::cloud::fetch(pg_pool.get_ref(), form.cloud_id)
// //         .await
// //         .map_err(|err| JsonResponse::<models::Cloud>::build().internal_server_error(err))
// //         .and_then(|cloud| {
// //             match cloud {
// //                 Some(cloud) if cloud.user_id != user.id => {
// //                     Err(JsonResponse::<models::Cloud>::build().bad_request("Cloud not found"))
// //                 }
// //                 Some(cloud) => {
// //                     Ok(cloud)
// //                 },
// //                 None => Err(JsonResponse::<models::Cloud>::build().not_found("Cloud not found"))
// //             }
// //         })?;
// //
// //     db::project::fetch(pg_pool.get_ref(), form.project_id)
// //         .await
// //         .map_err(|_err| JsonResponse::<models::Server>::build()
// //             .bad_request("Invalid project"))
// //         .and_then(|project| {
// //             match project {
// //                 Some(project) if project.user_id != user.id => {
// //                     Err(JsonResponse::<models::Project>::build().bad_request("Project not found"))
// //                 }
// //                 Some(project) => { Ok(project) },
// //                 None => Err(JsonResponse::<models::Server>::build().not_found("Project not found"))
// //             }
// //         })?;
// //
// //     let mut server: models::Server = form.into_inner().into();
// //     server.user_id = user.id.clone();
// //
// //     db::server::insert(pg_pool.get_ref(), server)
// //         .await
// //         .map(|server| JsonResponse::build()
// //             .set_item(server)
// //             .ok("success"))
// //         .map_err(|err|
// //             match err {
// //                 _ => {
// //                     return JsonResponse::<models::Server>::build().internal_server_error("Failed to insert");
// //                 }
// //             })
// }
