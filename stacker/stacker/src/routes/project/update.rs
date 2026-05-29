use crate::db;
use crate::forms::project::{DockerImageReadResult, ProjectForm};
use crate::helpers::JsonResponse;
use crate::models;
use crate::project_app;
use actix_web::{put, web, Responder, Result};
use serde_json::Value;
use serde_valid::Validate;
use sqlx::PgPool;
use std::sync::Arc;

#[tracing::instrument(name = "Update project.", skip_all)]
#[put("/{id}")]
pub async fn item(
    path: web::Path<(i32,)>,
    web::Json(request_json): web::Json<serde_json::Value>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let id = path.0;
    let mut project = db::project::fetch(pg_pool.get_ref(), id)
        .await
        .map_err(JsonResponse::internal_server_error)
        .and_then(|project| match project {
            Some(project) if project.user_id != user.id => {
                Err(JsonResponse::not_found("Project not found"))
            }
            Some(project) => Ok(project),
            None => Err(JsonResponse::not_found("Project not found")),
        })?;

    // @todo ACL
    let form: ProjectForm = serde_json::from_value(request_json.clone())
        .map_err(|err| JsonResponse::bad_request(err.to_string()))?;

    if !form.validate().is_ok() {
        let errors = form.validate().unwrap_err();
        return Err(JsonResponse::bad_request(errors.to_string()));
    }

    let project_name = form.custom.custom_stack_code.clone();

    match form.is_readable_docker_image().await {
        Ok(result) => {
            if false == result.readable {
                return Err(JsonResponse::<DockerImageReadResult>::build()
                    .set_item(result)
                    .bad_request("Can not access docker image"));
            }
        }
        Err(e) => {
            return Err(JsonResponse::<DockerImageReadResult>::build().bad_request(e));
        }
    }

    let metadata: Value = serde_json::to_value::<ProjectForm>(form.clone())
        .or(serde_json::to_value::<ProjectForm>(ProjectForm::default()))
        .unwrap();

    project.name = project_name;
    project.metadata = metadata;
    project.request_json = request_json;

    let project = db::project::update(pg_pool.get_ref(), project)
        .await
        .map_err(|err| {
            tracing::error!("Failed to execute query: {:?}", err);
            JsonResponse::internal_server_error("")
        })?;

    project_app::sync_project_level_apps_from_form(pg_pool.get_ref(), project.id, &form)
        .await
        .map_err(|err| {
            tracing::error!("Failed to execute query: {:?}", err);
            tracing::error!(
                "Failed to sync project-level apps for project {} after update: {}",
                project.id,
                err
            );
            JsonResponse::internal_server_error("")
        })?;

    Ok(JsonResponse::<models::Project>::build()
        .set_item(project)
        .ok("success"))
}
