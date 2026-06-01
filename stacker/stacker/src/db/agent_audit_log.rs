use crate::models::agent_audit_log::{AgentAuditLog, AuditBatchItem};
use chrono::{TimeZone, Utc};
use sqlx::PgPool;
use tracing::Instrument;

/// Insert a batch of audit events for a given installation.
/// Returns the number of rows successfully inserted.
#[tracing::instrument(name = "Insert agent audit batch", skip(pool, events))]
pub async fn insert_batch(
    pool: &PgPool,
    installation_hash: &str,
    events: &[AuditBatchItem],
) -> Result<usize, sqlx::Error> {
    if events.is_empty() {
        return Ok(0);
    }

    let mut inserted: usize = 0;
    let span = tracing::info_span!("Inserting audit events into database");

    for event in events {
        let created_at = Utc
            .timestamp_opt(event.created_at, 0)
            .single()
            .unwrap_or_else(Utc::now);

        sqlx::query_as::<_, AgentAuditLog>(
            r#"
            INSERT INTO agent_audit_log
                (installation_hash, event_type, payload, status_panel_id, created_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, installation_hash, event_type, payload, status_panel_id,
                      received_at, created_at
            "#,
        )
        .bind(installation_hash)
        .bind(&event.event_type)
        .bind(&event.payload)
        .bind(event.id)
        .bind(created_at)
        .fetch_one(pool)
        .instrument(span.clone())
        .await
        .map_err(|err| {
            tracing::error!("Failed to insert audit event: {:?}", err);
            err
        })?;

        inserted += 1;
    }

    Ok(inserted)
}

/// Fetch recent audit events with optional filters.
/// `limit` is capped at 100.
#[tracing::instrument(name = "Fetch recent audit events", skip(pool))]
pub async fn fetch_recent(
    pool: &PgPool,
    installation_hash: Option<&str>,
    event_type: Option<&str>,
    limit: i64,
) -> Result<Vec<AgentAuditLog>, sqlx::Error> {
    let limit = limit.min(100).max(1);
    let span = tracing::info_span!("Querying agent_audit_log");

    sqlx::query_as::<_, AgentAuditLog>(
        r#"
        SELECT id, installation_hash, event_type, payload, status_panel_id,
               received_at, created_at
        FROM agent_audit_log
        WHERE ($1::TEXT IS NULL OR installation_hash = $1)
          AND ($2::TEXT IS NULL OR event_type = $2)
        ORDER BY received_at DESC
        LIMIT $3
        "#,
    )
    .bind(installation_hash)
    .bind(event_type)
    .bind(limit)
    .fetch_all(pool)
    .instrument(span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch audit log: {:?}", err);
        err
    })
}
