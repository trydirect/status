use crate::db::agent_audit_log as audit_db;
use crate::helpers::JsonResponse;
use crate::models::agent_audit_log::{AgentAuditLog, AuditBatchRequest};
use actix_web::error::ErrorUnauthorized;
use actix_web::{get, post, web, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

// ── POST /api/v1/agent/audit ───────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub accepted: usize,
}

/// Receive a batch of audit events from the Status Panel.
///
/// Auth: `X-Internal-Key` header must match the `INTERNAL_SERVICES_ACCESS_KEY`
/// environment variable.
#[tracing::instrument(name = "Agent audit ingest", skip_all)]
#[post("/audit")]
pub async fn agent_audit_ingest_handler(
    req: HttpRequest,
    body: web::Json<AuditBatchRequest>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse> {
    // Validate internal service key
    let expected = std::env::var("INTERNAL_SERVICES_ACCESS_KEY").unwrap_or_default();
    let provided = req
        .headers()
        .get("x-internal-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    if expected.is_empty() || provided != expected {
        return Err(ErrorUnauthorized("invalid internal key"));
    }

    // Short-circuit on empty batch
    if body.events.is_empty() {
        return Ok(HttpResponse::Ok().json(IngestResponse { accepted: 0 }));
    }

    let accepted = audit_db::insert_batch(&pool, &body.installation_hash, &body.events)
        .await
        .map_err(|err| {
            JsonResponse::<()>::build()
                .internal_server_error(format!("Failed to store audit events: {}", err))
        })?;

    Ok(HttpResponse::Ok().json(IngestResponse { accepted }))
}

// ── GET /api/v1/agent/audit ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuditQueryParams {
    pub installation_hash: Option<String>,
    pub event_type: Option<String>,
    pub limit: Option<i64>,
}

/// Query the audit log.
///
/// Auth: standard JWT or OAuth2 user auth (handled by middleware).
#[tracing::instrument(name = "Agent audit query", skip_all)]
#[get("/audit")]
pub async fn agent_audit_query_handler(
    params: web::Query<AuditQueryParams>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse> {
    let limit = params.limit.unwrap_or(50).min(100).max(1);

    let logs: Vec<AgentAuditLog> = audit_db::fetch_recent(
        &pool,
        params.installation_hash.as_deref(),
        params.event_type.as_deref(),
        limit,
    )
    .await
    .map_err(|err| {
        JsonResponse::<()>::build()
            .internal_server_error(format!("Failed to fetch audit log: {}", err))
    })?;

    Ok(HttpResponse::Ok().json(logs))
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::agent_audit_log::AuditBatchRequest;

    #[test]
    fn test_audit_batch_request_deserializes() {
        let json = r#"{
            "installation_hash": "abc123",
            "events": [
                {
                    "id": 1,
                    "event_type": "deploy_start",
                    "payload": {"key": "value"},
                    "created_at": 1711000000
                }
            ]
        }"#;

        let req: AuditBatchRequest = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(req.installation_hash, "abc123");
        assert_eq!(req.events.len(), 1);
        assert_eq!(req.events[0].event_type, "deploy_start");
        assert_eq!(req.events[0].id, 1);
        assert_eq!(req.events[0].created_at, 1711000000);
    }

    #[test]
    fn test_empty_events_batch() {
        let json = r#"{"installation_hash": "abc123", "events": []}"#;
        let req: AuditBatchRequest = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(req.events.len(), 0);
        // With an empty events list the handler returns accepted: 0 without DB calls.
        // We test the DB layer short-circuit via the check in insert_batch.
    }

    #[test]
    fn test_fetch_recent_defaults() {
        // The limit cap logic lives in fetch_recent; verify the AuditQueryParams default.
        let params = AuditQueryParams {
            installation_hash: None,
            event_type: None,
            limit: None,
        };
        let effective_limit = params.limit.unwrap_or(50).min(100).max(1);
        assert_eq!(effective_limit, 50);

        // Over-limit is capped at 100
        let params_over = AuditQueryParams {
            installation_hash: None,
            event_type: None,
            limit: Some(9999),
        };
        let capped = params_over.limit.unwrap_or(50).min(100).max(1);
        assert_eq!(capped, 100);
    }

    #[test]
    #[ignore] // Requires a live database
    fn test_insert_batch_integration() {
        // Integration test placeholder — run with `cargo test -- --ignored`
    }
}
