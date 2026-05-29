use sqlx::PgPool;
use tracing::Instrument;

#[tracing::instrument(name = "Check if secret is unique.")]
pub async fn is_secret_unique(pool_ref: &PgPool, secret: &String) -> Result<bool, String> {
    let query_span = tracing::info_span!("Looking for the secret in the client's table.");
    match sqlx::query!(
        r#"
        SELECT
            count(*) as found
        FROM client c 
        WHERE c.secret = $1
        LIMIT 1
        "#,
        secret,
    )
    .fetch_one(pool_ref)
    .instrument(query_span)
    .await
    {
        Ok(result) => {
            return Ok(result.found < Some(1));
        }
        Err(e) => {
            return Err(format!("{e:?}"));
        }
    };
}
