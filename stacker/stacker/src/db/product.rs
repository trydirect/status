use crate::models;
use sqlx::PgPool;
use tracing::Instrument;

pub async fn fetch_by_obj(
    pg_pool: &PgPool,
    obj_id: i32,
) -> Result<Option<models::Product>, String> {
    let query_span = tracing::info_span!("Check product existence by id.");
    sqlx::query_as!(
        models::Product,
        r#"SELECT
            *
         FROM product
         WHERE obj_id = $1
         LIMIT 1
         "#,
        obj_id
    )
    .fetch_one(pg_pool)
    .instrument(query_span)
    .await
    .map(|product| Some(product))
    .or_else(|e| match e {
        sqlx::Error::RowNotFound => Ok(None),
        s => {
            tracing::error!("Failed to execute fetch query: {:?}", s);
            Err("".to_string())
        }
    })
}
