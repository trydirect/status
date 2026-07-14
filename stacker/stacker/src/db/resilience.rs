use crate::models::resilience::{CircuitBreaker, DeadLetterEntry};
use sqlx::PgPool;
use tracing::Instrument;
use uuid::Uuid;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Dead Letter Queue queries
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tracing::instrument(name = "Insert DLQ entry", skip(pool))]
pub async fn insert_dlq_entry(
    pool: &PgPool,
    entry: &DeadLetterEntry,
) -> Result<DeadLetterEntry, String> {
    let span = tracing::info_span!("Saving DLQ entry to database");
    sqlx::query_as::<_, DeadLetterEntry>(
        r#"
        INSERT INTO dead_letter_queue (
            id, pipe_instance_id, pipe_execution_id, dag_step_id,
            payload, error, retry_count, max_retries, next_retry_at,
            status, created_by, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING *
        "#,
    )
    .bind(entry.id)
    .bind(entry.pipe_instance_id)
    .bind(entry.pipe_execution_id)
    .bind(entry.dag_step_id)
    .bind(&entry.payload)
    .bind(&entry.error)
    .bind(entry.retry_count)
    .bind(entry.max_retries)
    .bind(entry.next_retry_at)
    .bind(&entry.status)
    .bind(&entry.created_by)
    .bind(entry.created_at)
    .bind(entry.updated_at)
    .fetch_one(pool)
    .instrument(span)
    .await
    .map_err(|e| format!("Failed to insert DLQ entry: {}", e))
}

#[tracing::instrument(name = "List DLQ entries", skip(pool))]
pub async fn list_dlq_entries(
    pool: &PgPool,
    pipe_instance_id: &Uuid,
) -> Result<Vec<DeadLetterEntry>, String> {
    let span = tracing::info_span!("Listing DLQ entries");
    sqlx::query_as::<_, DeadLetterEntry>(
        r#"
        SELECT * FROM dead_letter_queue
        WHERE pipe_instance_id = $1 AND status NOT IN ('discarded', 'resolved')
        ORDER BY created_at DESC
        "#,
    )
    .bind(pipe_instance_id)
    .fetch_all(pool)
    .instrument(span)
    .await
    .map_err(|e| format!("Failed to list DLQ entries: {}", e))
}

#[tracing::instrument(name = "Get DLQ entry", skip(pool))]
pub async fn get_dlq_entry(
    pool: &PgPool,
    entry_id: &Uuid,
) -> Result<Option<DeadLetterEntry>, String> {
    let span = tracing::info_span!("Fetching DLQ entry");
    sqlx::query_as::<_, DeadLetterEntry>(r#"SELECT * FROM dead_letter_queue WHERE id = $1"#)
        .bind(entry_id)
        .fetch_optional(pool)
        .instrument(span)
        .await
        .map_err(|e| format!("Failed to get DLQ entry: {}", e))
}

#[tracing::instrument(name = "Retry DLQ entry", skip(pool))]
pub async fn retry_dlq_entry(pool: &PgPool, entry_id: &Uuid) -> Result<DeadLetterEntry, String> {
    let span = tracing::info_span!("Retrying DLQ entry");
    // Increment retry_count; if retry_count >= max_retries, set status = 'exhausted'
    sqlx::query_as::<_, DeadLetterEntry>(
        r#"
        UPDATE dead_letter_queue
        SET retry_count = retry_count + 1,
            status = CASE
                WHEN retry_count + 1 >= max_retries THEN 'exhausted'
                ELSE 'retrying'
            END,
            next_retry_at = NOW() + (POWER(2, retry_count) || ' seconds')::INTERVAL,
            updated_at = NOW()
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(entry_id)
    .fetch_one(pool)
    .instrument(span)
    .await
    .map_err(|e| format!("Failed to retry DLQ entry: {}", e))
}

#[tracing::instrument(name = "Discard DLQ entry", skip(pool))]
pub async fn discard_dlq_entry(pool: &PgPool, entry_id: &Uuid) -> Result<(), String> {
    let span = tracing::info_span!("Discarding DLQ entry");
    sqlx::query(
        r#"UPDATE dead_letter_queue SET status = 'discarded', updated_at = NOW() WHERE id = $1"#,
    )
    .bind(entry_id)
    .execute(pool)
    .instrument(span)
    .await
    .map_err(|e| format!("Failed to discard DLQ entry: {}", e))?;
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Circuit Breaker queries
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Get or create circuit breaker for a pipe instance
#[tracing::instrument(name = "Get or create circuit breaker", skip(pool))]
pub async fn get_or_create_circuit_breaker(
    pool: &PgPool,
    pipe_instance_id: &Uuid,
) -> Result<CircuitBreaker, String> {
    let span = tracing::info_span!("Get or create circuit breaker");
    sqlx::query_as::<_, CircuitBreaker>(
        r#"
        INSERT INTO circuit_breakers (id, pipe_instance_id)
        VALUES (gen_random_uuid(), $1)
        ON CONFLICT (pipe_instance_id) DO UPDATE SET updated_at = NOW()
        RETURNING *
        "#,
    )
    .bind(pipe_instance_id)
    .fetch_one(pool)
    .instrument(span)
    .await
    .map_err(|e| format!("Failed to get/create circuit breaker: {}", e))
}

#[tracing::instrument(name = "Update circuit breaker config", skip(pool))]
pub async fn update_circuit_breaker_config(
    pool: &PgPool,
    pipe_instance_id: &Uuid,
    failure_threshold: i32,
    recovery_timeout_seconds: i32,
    half_open_max_requests: i32,
) -> Result<CircuitBreaker, String> {
    let span = tracing::info_span!("Updating circuit breaker config");
    sqlx::query_as::<_, CircuitBreaker>(
        r#"
        INSERT INTO circuit_breakers (id, pipe_instance_id, failure_threshold, recovery_timeout_seconds, half_open_max_requests)
        VALUES (gen_random_uuid(), $1, $2, $3, $4)
        ON CONFLICT (pipe_instance_id) DO UPDATE SET
            failure_threshold = EXCLUDED.failure_threshold,
            recovery_timeout_seconds = EXCLUDED.recovery_timeout_seconds,
            half_open_max_requests = EXCLUDED.half_open_max_requests,
            updated_at = NOW()
        RETURNING *
        "#,
    )
    .bind(pipe_instance_id)
    .bind(failure_threshold)
    .bind(recovery_timeout_seconds)
    .bind(half_open_max_requests)
    .fetch_one(pool)
    .instrument(span)
    .await
    .map_err(|e| format!("Failed to update circuit breaker config: {}", e))
}

/// Record a failure — increment failure_count, open circuit if threshold reached
#[tracing::instrument(name = "Record circuit breaker failure", skip(pool))]
pub async fn record_circuit_breaker_failure(
    pool: &PgPool,
    pipe_instance_id: &Uuid,
) -> Result<CircuitBreaker, String> {
    let span = tracing::info_span!("Recording circuit breaker failure");
    // First ensure circuit breaker exists
    let _cb = get_or_create_circuit_breaker(pool, pipe_instance_id).await?;

    sqlx::query_as::<_, CircuitBreaker>(
        r#"
        UPDATE circuit_breakers
        SET failure_count = failure_count + 1,
            last_failure_at = NOW(),
            state = CASE
                WHEN failure_count + 1 >= failure_threshold THEN 'open'
                ELSE state
            END,
            opened_at = CASE
                WHEN failure_count + 1 >= failure_threshold AND state != 'open' THEN NOW()
                ELSE opened_at
            END,
            updated_at = NOW()
        WHERE pipe_instance_id = $1
        RETURNING *
        "#,
    )
    .bind(pipe_instance_id)
    .fetch_one(pool)
    .instrument(span)
    .await
    .map_err(|e| format!("Failed to record circuit breaker failure: {}", e))
}

/// Record a success — reset failure_count in closed/half_open states
#[tracing::instrument(name = "Record circuit breaker success", skip(pool))]
pub async fn record_circuit_breaker_success(
    pool: &PgPool,
    pipe_instance_id: &Uuid,
) -> Result<CircuitBreaker, String> {
    let span = tracing::info_span!("Recording circuit breaker success");
    let _cb = get_or_create_circuit_breaker(pool, pipe_instance_id).await?;

    sqlx::query_as::<_, CircuitBreaker>(
        r#"
        UPDATE circuit_breakers
        SET failure_count = 0,
            success_count = success_count + 1,
            state = CASE
                WHEN state = 'half_open' THEN 'closed'
                ELSE state
            END,
            opened_at = CASE
                WHEN state = 'half_open' THEN NULL
                ELSE opened_at
            END,
            updated_at = NOW()
        WHERE pipe_instance_id = $1
        RETURNING *
        "#,
    )
    .bind(pipe_instance_id)
    .fetch_one(pool)
    .instrument(span)
    .await
    .map_err(|e| format!("Failed to record circuit breaker success: {}", e))
}

/// Reset circuit breaker to closed state
#[tracing::instrument(name = "Reset circuit breaker", skip(pool))]
pub async fn reset_circuit_breaker(
    pool: &PgPool,
    pipe_instance_id: &Uuid,
) -> Result<CircuitBreaker, String> {
    let span = tracing::info_span!("Resetting circuit breaker");
    let _cb = get_or_create_circuit_breaker(pool, pipe_instance_id).await?;

    sqlx::query_as::<_, CircuitBreaker>(
        r#"
        UPDATE circuit_breakers
        SET state = 'closed',
            failure_count = 0,
            success_count = 0,
            opened_at = NULL,
            last_failure_at = NULL,
            updated_at = NOW()
        WHERE pipe_instance_id = $1
        RETURNING *
        "#,
    )
    .bind(pipe_instance_id)
    .fetch_one(pool)
    .instrument(span)
    .await
    .map_err(|e| format!("Failed to reset circuit breaker: {}", e))
}
