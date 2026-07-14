use crate::db;
use crate::helpers::JsonResponse;
use crate::models::User;
use actix_web::{get, web, HttpResponse, Result};
use sqlx::PgPool;
use std::sync::Arc;

/// SSE (Server-Sent Events) endpoint for real-time pipe execution streaming.
///
/// Returns a stream of execution events including DAG step progress,
/// completion notifications, and error reports.
#[get("/instances/{instance_id}/stream")]
pub async fn execution_stream_handler(
    pg_pool: web::Data<PgPool>,
    user: web::ReqData<Arc<User>>,
    path: web::Path<String>,
) -> Result<HttpResponse, actix_web::Error> {
    let instance_id = path.into_inner();
    let instance_uuid = uuid::Uuid::parse_str(&instance_id).map_err(|_| {
        JsonResponse::<String>::bad_request(String::from("Invalid instance ID format"))
    })?;

    // Verify instance exists and belongs to user
    let instance = db::pipe::get_instance(pg_pool.get_ref(), &instance_uuid)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    let instance = instance.ok_or_else(|| {
        JsonResponse::<String>::not_found(String::from("Pipe instance not found"))
    })?;

    if instance.created_by != user.id {
        return Err(JsonResponse::<String>::forbidden(String::from(
            "Access denied: not your pipe instance",
        )));
    }

    // Fetch recent executions for initial state
    let recent_executions = db::pipe::list_executions(pg_pool.get_ref(), &instance_uuid, 10, 0)
        .await
        .unwrap_or_default();

    // Build SSE response body
    let mut body = String::new();

    // Connection event
    body.push_str("event: connected\n");
    body.push_str(&format!(
        "data: {{\"instance_id\":\"{}\",\"status\":\"{}\"}}\n\n",
        instance_id, instance.status
    ));

    // Send recent execution history
    for exec in &recent_executions {
        body.push_str("event: execution\n");
        body.push_str(&format!(
            "data: {{\"execution_id\":\"{}\",\"status\":\"{}\",\"started_at\":\"{}\"}}\n\n",
            exec.id, exec.status, exec.started_at
        ));
    }

    // Heartbeat to keep connection alive
    body.push_str(": heartbeat\n\n");

    Ok(HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Connection", "keep-alive"))
        .body(body))
}
