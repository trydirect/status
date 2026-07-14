use crate::models;
use sqlx::PgPool;
use tracing::Instrument;

pub async fn update(pool: &PgPool, client: models::Client) -> Result<models::Client, String> {
    let query_span = tracing::info_span!("Updating client into the database");
    sqlx::query!(
        r#"
        UPDATE client
        SET 
            secret=$1,
            updated_at=NOW() at time zone 'utc'
        WHERE id = $2
        "#,
        client.secret,
        client.id
    )
    .execute(pool)
    .instrument(query_span)
    .await
    .map(|_| {
        tracing::info!("Client {} has been saved to the database", client.id);
        client
    })
    .map_err(|err| {
        tracing::error!("Failed to execute query: {:?}", err);
        "".to_string()
    })
}

pub async fn fetch(pool: &PgPool, id: i32) -> Result<Option<models::Client>, String> {
    let query_span = tracing::info_span!("Fetching the client by ID");
    sqlx::query_as!(
        models::Client,
        r#"
        SELECT
           id,
           user_id,
           secret 
        FROM client c
        WHERE c.id = $1
        LIMIT 1
        "#,
        id,
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map(|client| Some(client))
    .or_else(|e| match e {
        sqlx::Error::RowNotFound => Ok(None),
        s => {
            tracing::error!("Failed to execute fetch query: {:?}", s);
            Err("".to_string())
        }
    })
}

pub async fn count_by_user(pool: &PgPool, user_id: &String) -> Result<i64, String> {
    let query_span = tracing::info_span!("Counting the user's clients");

    sqlx::query!(
        r#"
        SELECT
            count(*) as client_count
        FROM client c 
        WHERE c.user_id = $1
        "#,
        user_id.clone(),
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map(|result| result.client_count.unwrap())
    .map_err(|err| {
        tracing::error!("Failed to execute query: {:?}", err);
        "Internal Server Error".to_string()
    })
}

pub async fn insert(pool: &PgPool, mut client: models::Client) -> Result<models::Client, String> {
    let query_span = tracing::info_span!("Saving new client into the database");
    sqlx::query!(
        r#"
        INSERT INTO client (user_id, secret, created_at, updated_at)
        VALUES ($1, $2, NOW() at time zone 'utc', NOW() at time zone 'utc')
        RETURNING id
        "#,
        client.user_id.clone(),
        client.secret,
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map(move |result| {
        client.id = result.id;
        client
    })
    .map_err(|e| {
        tracing::error!("Failed to execute query: {:?}", e);
        "Failed to insert".to_string()
    })
}
