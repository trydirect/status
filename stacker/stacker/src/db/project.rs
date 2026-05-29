use crate::models;
use sqlx::PgPool;
use sqlx::Row;
use tracing::Instrument;

pub async fn fetch(pool: &PgPool, id: i32) -> Result<Option<models::Project>, String> {
    tracing::info!("Fetch project {}", id);
    sqlx::query_as!(
        models::Project,
        r#"
        SELECT
            *
        FROM project
        WHERE id=$1
        LIMIT 1
        "#,
        id
    )
    .fetch_one(pool)
    .await
    .map(|project| Some(project))
    .or_else(|err| match err {
        sqlx::Error::RowNotFound => Ok(None),
        e => {
            tracing::error!("Failed to fetch project, error: {:?}", e);
            Err("Could not fetch data".to_string())
        }
    })
}

pub async fn fetch_by_user(pool: &PgPool, user_id: &str) -> Result<Vec<models::Project>, String> {
    let query_span = tracing::info_span!("Fetch projects by user id.");
    sqlx::query_as!(
        models::Project,
        r#"
        SELECT
            *
        FROM project
        WHERE user_id=$1
        "#,
        user_id
    )
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch project, error: {:?}", err);
        "".to_string()
    })
}

pub async fn fetch_shared_by_user(
    pool: &PgPool,
    user_id: &str,
) -> Result<Vec<models::SharedProjectSummary>, String> {
    let query_span = tracing::info_span!("Fetch shared projects by user id.");
    sqlx::query_as::<_, models::SharedProjectSummary>(
        r#"
        SELECT
            p.id,
            p.name,
            pm.role,
            pm.created_at AS shared_at
        FROM project_member pm
        JOIN project p ON p.id = pm.project_id
        WHERE pm.user_id = $1
        ORDER BY pm.created_at DESC, p.id DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch shared projects, error: {:?}", err);
        "".to_string()
    })
}

pub async fn fetch_one_by_name(
    pool: &PgPool,
    name: &str,
    user_id: &str,
) -> Result<Option<models::Project>, String> {
    let query_span = tracing::info_span!("Fetch one project by name.");
    sqlx::query_as!(
        models::Project,
        r#"
        SELECT
            *
        FROM project
        WHERE name=$1 AND user_id=$2
        LIMIT 1
        "#,
        name,
        user_id
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map(|project| Some(project))
    .or_else(|err| match err {
        sqlx::Error::RowNotFound => Ok(None),
        err => {
            tracing::error!("Failed to fetch one project by name, error: {:?}", err);
            Err("".to_string())
        }
    })
}

pub async fn insert(
    pool: &PgPool,
    mut project: models::Project,
) -> Result<models::Project, String> {
    let query_span = tracing::info_span!("Saving new project into the database");
    sqlx::query(
        r#"
        INSERT INTO project (
            stack_id,
            user_id,
            name,
            metadata,
            created_at,
            updated_at,
            request_json,
            source_template_id,
            template_version
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id;
        "#,
    )
    .bind(project.stack_id)
    .bind(project.user_id.clone())
    .bind(project.name.clone())
    .bind(project.metadata.clone())
    .bind(project.created_at)
    .bind(project.updated_at)
    .bind(project.request_json.clone())
    .bind(project.source_template_id)
    .bind(project.template_version.clone())
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map(move |result| {
        project.id = result.get("id");
        project
    })
    .map_err(|e| {
        tracing::error!("Failed to execute query: {:?}", e);
        "Failed to insert".to_string()
    })
}

pub async fn update(
    pool: &PgPool,
    mut project: models::Project,
) -> Result<models::Project, String> {
    let query_span = tracing::info_span!("Updating project");
    sqlx::query(
        r#"
        UPDATE project
        SET 
            stack_id=$2,
            user_id=$3,
            name=$4,
            metadata=$5,
            request_json=$6,
            source_template_id=$7,
            template_version=$8,
            updated_at=NOW() at time zone 'utc'
        WHERE id = $1
        "#,
    )
    .bind(project.id)
    .bind(project.stack_id)
    .bind(project.user_id.clone())
    .bind(project.name.clone())
    .bind(project.metadata.clone())
    .bind(project.request_json.clone())
    .bind(project.source_template_id)
    .bind(project.template_version.clone())
    .execute(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to execute query: {:?}", err);
        "".to_string()
    })?;

    fetch(pool, project.id)
        .await
        .and_then(|result| result.ok_or_else(|| "Project not found after update".to_string()))
        .map(|saved| {
            tracing::info!("Project {} has been saved to database", project.id);
            project.updated_at = saved.updated_at;
            project
        })
}

#[tracing::instrument(name = "Delete user's project.")]
pub async fn delete(pool: &PgPool, id: i32, user_id: &str) -> Result<bool, String> {
    tracing::info!("Delete project {}", id);
    sqlx::query::<sqlx::Postgres>("DELETE FROM project WHERE id = $1 AND user_id = $2;")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await
        .map(|r| r.rows_affected() > 0)
        .map_err(|err| {
            tracing::error!("Failed to delete project: {:?}", err);
            "Failed to delete project".to_string()
        })
}
