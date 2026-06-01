use crate::db;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{delete, get, post, web, HttpResponse, Responder, Result};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct AddProjectMemberRequest {
    pub user_id: String,
    pub role: String,
}

async fn fetch_owned_project(
    pool: &PgPool,
    project_id: i32,
    user_id: &str,
) -> Result<models::Project, actix_web::Error> {
    let project = db::project::fetch(pool, project_id)
        .await
        .map_err(|err| JsonResponse::<models::ProjectMember>::build().internal_server_error(err))?
        .ok_or_else(|| JsonResponse::<models::ProjectMember>::build().not_found("not found"))?;

    if project.user_id != user_id {
        return Err(JsonResponse::<models::ProjectMember>::build().not_found("not found"));
    }

    Ok(project)
}

#[tracing::instrument(name = "Share project with member", skip_all)]
#[post("/{id}/members")]
pub async fn add(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32,)>,
    payload: web::Json<AddProjectMemberRequest>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let project_id = path.0;

    let _project = fetch_owned_project(pg_pool.get_ref(), project_id, &user.id).await?;

    if payload.role != "viewer" {
        return Err(JsonResponse::<models::ProjectMember>::build()
            .bad_request("Only viewer role is supported"));
    }

    let member = db::project_member::upsert(
        pg_pool.get_ref(),
        project_id,
        &payload.user_id,
        &payload.role,
        &user.id,
    )
    .await
    .map_err(|err| JsonResponse::<models::ProjectMember>::build().internal_server_error(err))?;

    Ok(JsonResponse::build().set_item(member).ok("OK"))
}

#[tracing::instrument(name = "List project members", skip_all)]
#[get("/{id}/members")]
pub async fn list(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let project_id = path.0;

    let _project = fetch_owned_project(pg_pool.get_ref(), project_id, &user.id).await?;

    let members = db::project_member::fetch_by_project(pg_pool.get_ref(), project_id)
        .await
        .map_err(|err| JsonResponse::<models::ProjectMember>::build().internal_server_error(err))?;

    Ok(JsonResponse::build().set_list(members).ok("OK"))
}

#[tracing::instrument(name = "Delete project member", skip_all)]
#[delete("/{id}/members/{member_user_id}")]
pub async fn delete(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32, String)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let (project_id, member_user_id) = path.into_inner();

    let _project = fetch_owned_project(pg_pool.get_ref(), project_id, &user.id).await?;

    let deleted = db::project_member::delete(pg_pool.get_ref(), project_id, &member_user_id)
        .await
        .map_err(|err| JsonResponse::<models::ProjectMember>::build().internal_server_error(err))?;

    if !deleted {
        return Err(JsonResponse::<models::ProjectMember>::build().not_found("not found"));
    }

    Ok(HttpResponse::NoContent().finish())
}
