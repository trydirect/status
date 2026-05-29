use crate::models;
use sqlx::PgPool;
use tracing::Instrument;

pub async fn fetch(pool: &PgPool, id: i32) -> Result<Option<models::Cloud>, String> {
    tracing::info!("Fetch cloud {}", id);
    sqlx::query_as!(
        models::Cloud,
        r#"SELECT * FROM cloud WHERE id=$1 LIMIT 1 "#,
        id
    )
    .fetch_one(pool)
    .await
    .map(|cloud| Some(cloud))
    .or_else(|err| match err {
        sqlx::Error::RowNotFound => Ok(None),
        e => {
            tracing::error!("Failed to fetch cloud, error: {:?}", e);
            Err("Could not fetch data".to_string())
        }
    })
}

pub async fn fetch_by_user(pool: &PgPool, user_id: &str) -> Result<Vec<models::Cloud>, String> {
    let query_span = tracing::info_span!("Fetch clouds by user id.");
    sqlx::query_as!(
        models::Cloud,
        r#"
        SELECT
            *
        FROM cloud
        WHERE user_id=$1
        "#,
        user_id
    )
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch cloud, error: {:?}", err);
        "".to_string()
    })
}

pub async fn insert(pool: &PgPool, mut cloud: models::Cloud) -> Result<models::Cloud, String> {
    let query_span = tracing::info_span!("Saving user's cloud data into the database");

    // If no name provided, generate a unique default using a UUID suffix to
    // avoid collisions on the (user_id, name) unique constraint.
    let has_name = !cloud.name.is_empty();
    let insert_name = if has_name {
        cloud.name.clone()
    } else {
        let suffix = uuid::Uuid::new_v4().to_string();
        format!("{}-{}", cloud.provider, &suffix[..8])
    };

    let result = sqlx::query!(
        r#"
        INSERT INTO cloud (
        user_id,
        name,
        provider,
        cloud_token,
        cloud_key,
        cloud_secret,
        save_token,
        created_at,
        updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW() at time zone 'utc', NOW() at time zone 'utc')
        RETURNING id;
        "#,
        cloud.user_id,
        insert_name,
        cloud.provider,
        cloud.cloud_token,
        cloud.cloud_key,
        cloud.cloud_secret,
        cloud.save_token
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("Failed to execute query: {:?}", e);
        "Failed to insert".to_string()
    })?;

    cloud.id = result.id;

    // Set the final name: "{provider}-{id}" for auto-generated names
    let final_name = if has_name {
        insert_name
    } else {
        format!("{}-{}", cloud.provider, cloud.id)
    };
    cloud.name = final_name.clone();

    // Persist the final name to the database
    let update_span = tracing::info_span!("Updating cloud name after insert");
    sqlx::query!(
        r#"UPDATE cloud SET name = $1 WHERE id = $2"#,
        final_name,
        cloud.id
    )
    .execute(pool)
    .instrument(update_span)
    .await
    .map_err(|e| {
        tracing::warn!("Failed to update cloud name after insert: {:?}", e);
        // Non-fatal: the row was inserted, name is just the temp placeholder
        "Failed to update name".to_string()
    })?;

    Ok(cloud)
}

pub async fn update(pool: &PgPool, mut cloud: models::Cloud) -> Result<models::Cloud, String> {
    let query_span = tracing::info_span!("Updating user cloud");
    sqlx::query_as!(
        models::Cloud,
        r#"
        UPDATE cloud
        SET
            user_id=$2,
            name=$3,
            provider=$4,
            cloud_token=$5,
            cloud_key=$6,
            cloud_secret=$7,
            save_token=$8,
            updated_at=NOW() at time zone 'utc'
        WHERE id = $1
        RETURNING *
        "#,
        cloud.id,
        cloud.user_id,
        cloud.name,
        cloud.provider,
        cloud.cloud_token,
        cloud.cloud_key,
        cloud.cloud_secret,
        cloud.save_token
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map(|result| {
        tracing::info!("Cloud info {} have been saved", cloud.id);
        cloud.updated_at = result.updated_at;
        cloud
    })
    .map_err(|err| {
        tracing::error!("Failed to execute query: {:?}", err);
        "".to_string()
    })
}

#[tracing::instrument(name = "Delete cloud of a user.")]
pub async fn delete(pool: &PgPool, id: i32, user_id: &str) -> Result<bool, String> {
    tracing::info!("Delete cloud {}", id);
    sqlx::query::<sqlx::Postgres>("DELETE FROM cloud WHERE id = $1 AND user_id = $2;")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await
        .map(|r| r.rows_affected() > 0)
        .map_err(|err| {
            tracing::error!("Failed to delete cloud: {:?}", err);
            "Failed to delete cloud".to_string()
        })
}
