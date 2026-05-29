use crate::models;
use sqlx::PgPool;
use tracing::Instrument;

pub async fn fetch(pool: &PgPool, id: i32) -> Result<Option<models::Agreement>, String> {
    tracing::info!("Fetch agreement {}", id);
    sqlx::query_as!(
        models::Agreement,
        r#"
        SELECT
            *
        FROM agreement
        WHERE id=$1
        LIMIT 1
        "#,
        id
    )
    .fetch_one(pool)
    .await
    .map(|agreement| Some(agreement))
    .or_else(|err| match err {
        sqlx::Error::RowNotFound => Ok(None),
        e => {
            tracing::error!("Failed to fetch agreement, error: {:?}", e);
            Err("Could not fetch data".to_string())
        }
    })
}

#[allow(dead_code)]
pub async fn fetch_by_user(
    pool: &PgPool,
    user_id: &str,
) -> Result<Vec<models::UserAgreement>, String> {
    let query_span = tracing::info_span!("Fetch agreements by user id.");
    sqlx::query_as!(
        models::UserAgreement,
        r#"
        SELECT
            *
        FROM user_agreement
        WHERE user_id=$1
        "#,
        user_id
    )
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch agreement, error: {:?}", err);
        "".to_string()
    })
}

pub async fn fetch_by_user_and_agreement(
    pool: &PgPool,
    user_id: &str,
    agreement_id: i32,
) -> Result<Option<models::UserAgreement>, String> {
    let query_span = tracing::info_span!("Fetch agreements by user id.");
    sqlx::query_as!(
        models::UserAgreement,
        r#"
        SELECT
            *
        FROM user_agreement
        WHERE user_id=$1
        AND agrt_id=$2
        LIMIT 1
        "#,
        user_id,
        agreement_id
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map(|agreement| Some(agreement))
    .or_else(|err| match err {
        sqlx::Error::RowNotFound => Ok(None),
        err => {
            tracing::error!("Failed to fetch one agreement by name, error: {:?}", err);
            Err("".to_string())
        }
    })
}
#[allow(dead_code)]
pub async fn fetch_one_by_name(
    pool: &PgPool,
    name: &str,
) -> Result<Option<models::Agreement>, String> {
    let query_span = tracing::info_span!("Fetch one agreement by name.");
    sqlx::query_as!(
        models::Agreement,
        r#"
        SELECT
            *
        FROM agreement
        WHERE name=$1
        LIMIT 1
        "#,
        name
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map(|agreement| Some(agreement))
    .or_else(|err| match err {
        sqlx::Error::RowNotFound => Ok(None),
        err => {
            tracing::error!("Failed to fetch one agreement by name, error: {:?}", err);
            Err("".to_string())
        }
    })
}

pub async fn insert(
    pool: &PgPool,
    mut agreement: models::Agreement,
) -> Result<models::Agreement, String> {
    let query_span = tracing::info_span!("Saving new agreement into the database");
    sqlx::query!(
        r#"
        INSERT INTO agreement (name, text, created_at, updated_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id;
        "#,
        agreement.name,
        agreement.text,
        agreement.created_at,
        agreement.updated_at,
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map(move |result| {
        agreement.id = result.id;
        agreement
    })
    .map_err(|e| {
        tracing::error!("Failed to execute query: {:?}", e);
        "Failed to insert".to_string()
    })
}

pub async fn insert_by_user(
    pool: &PgPool,
    mut item: models::UserAgreement,
) -> Result<models::UserAgreement, String> {
    let query_span = tracing::info_span!("Saving new agreement into the database");
    sqlx::query!(
        r#"
        INSERT INTO user_agreement (agrt_id, user_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id;
        "#,
        item.agrt_id,
        item.user_id,
        item.created_at,
        item.updated_at,
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map(move |result| {
        item.id = result.id;
        item
    })
    .map_err(|e| {
        tracing::error!("Failed to execute query: {:?}", e);
        "Failed to insert".to_string()
    })
}
pub async fn update(
    pool: &PgPool,
    mut agreement: models::Agreement,
) -> Result<models::Agreement, String> {
    let query_span = tracing::info_span!("Updating agreement");
    sqlx::query_as!(
        models::Agreement,
        r#"
        UPDATE agreement
        SET
            name=$2,
            text=$3,
            updated_at=NOW() at time zone 'utc'
        WHERE id = $1
        RETURNING *
        "#,
        agreement.id,
        agreement.name,
        agreement.text,
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map(|result| {
        tracing::info!("Agreement {} has been saved to database", agreement.id);
        agreement.updated_at = result.updated_at;
        agreement
    })
    .map_err(|err| {
        tracing::error!("Failed to execute query: {:?}", err);
        "".to_string()
    })
}

#[tracing::instrument(name = "Delete user's agreement.")]
#[allow(dead_code)]
pub async fn delete(pool: &PgPool, id: i32) -> Result<bool, String> {
    tracing::info!("Delete agreement {}", id);
    sqlx::query::<sqlx::Postgres>("DELETE FROM agreement WHERE id = $1;")
        .bind(id)
        .execute(pool)
        .await
        .map(|_| true)
        .map_err(|err| {
            tracing::error!("Failed to delete agreement: {:?}", err);
            "Failed to delete agreement".to_string()
        })
}
