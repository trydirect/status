use crate::models::{
    AnalyticsPeriod, AnalyticsSummary, CloudBreakdown, MarketplaceVendorProfile, SeriesBucket,
    StackCategory, StackTemplate, StackTemplateReview, StackTemplateVersion, TemplateAnalytics,
    TemplatePerformance, VendorAnalytics,
};
use chrono::{Duration, Utc};
use serde_json::{Map, Value};
use sqlx::{PgPool, Row};
use tracing::Instrument;

pub const SLUG_UNIQUE_CONSTRAINT: &str = "stack_template_slug_key";

#[derive(Debug)]
pub enum CreateDraftError {
    DuplicateSlug { slug: String },
    Internal,
}

pub async fn list_approved(
    pool: &PgPool,
    category: Option<&str>,
    tag: Option<&str>,
    sort: Option<&str>,
) -> Result<Vec<StackTemplate>, String> {
    let mut base = String::from(
        r#"SELECT 
            t.id,
            t.creator_user_id,
            t.creator_name,
            t.name,
            t.slug,
            t.short_description,
            t.long_description,
            c.name AS category_code,
            t.product_id,
            t.tags,
            t.tech_stack,
            t.status,
            t.is_configurable,
            t.view_count,
            t.deploy_count,
            t.required_plan_name,
            t.price,
            t.billing_cycle,
            t.currency,
            t.created_at,
            t.updated_at,
            t.approved_at,
            t.verifications,
            t.infrastructure_requirements,
            t.public_ports,
            t.vendor_url
        FROM stack_template t
        LEFT JOIN stack_category c ON t.category_id = c.id
        WHERE t.status = 'approved'"#,
    );

    match (category.is_some(), tag.is_some()) {
        (true, true) => base.push_str(" AND c.name = $1 AND t.tags ? $2"),
        (true, false) => base.push_str(" AND c.name = $1"),
        (false, true) => base.push_str(" AND t.tags ? $1"),
        (false, false) => {}
    }

    match sort.unwrap_or("recent") {
        // Hardened images always float to the top of each sort bucket
        "popular" => base.push_str(
            " ORDER BY (t.verifications @> '{\"hardened_images\":true}') DESC, t.deploy_count DESC, t.view_count DESC",
        ),
        "rating" => base.push_str(
            " ORDER BY (t.verifications @> '{\"hardened_images\":true}') DESC, (SELECT AVG(rate) FROM rating WHERE rating.product_id = t.product_id) DESC NULLS LAST",
        ),
        _ => base.push_str(
            " ORDER BY (t.verifications @> '{\"hardened_images\":true}') DESC, t.approved_at DESC NULLS LAST, t.created_at DESC",
        ),
    }

    let query_span = tracing::info_span!("marketplace_list_approved");

    let res = if category.is_some() && tag.is_some() {
        sqlx::query_as::<_, StackTemplate>(&base)
            .bind(category.unwrap())
            .bind(tag.unwrap())
            .fetch_all(pool)
            .instrument(query_span)
            .await
    } else if category.is_some() {
        sqlx::query_as::<_, StackTemplate>(&base)
            .bind(category.unwrap())
            .fetch_all(pool)
            .instrument(query_span)
            .await
    } else if tag.is_some() {
        sqlx::query_as::<_, StackTemplate>(&base)
            .bind(tag.unwrap())
            .fetch_all(pool)
            .instrument(query_span)
            .await
    } else {
        sqlx::query_as::<_, StackTemplate>(&base)
            .fetch_all(pool)
            .instrument(query_span)
            .await
    };

    res.map_err(|e| {
        tracing::error!("list_approved error: {:?}", e);
        "Internal Server Error".to_string()
    })
}

pub async fn get_by_slug_and_user(
    pool: &PgPool,
    slug: &str,
    user_id: &str,
) -> Result<Option<StackTemplate>, String> {
    let query_span =
        tracing::info_span!("marketplace_get_by_slug_and_user", slug = %slug, user_id = %user_id);

    sqlx::query_as::<_, StackTemplate>(
        r#"SELECT 
            t.id,
            t.creator_user_id,
            t.creator_name,
            t.name,
            t.slug,
            t.short_description,
            t.long_description,
            c.name AS category_code,
            t.product_id,
            t.tags,
            t.tech_stack,
            t.status,
            t.is_configurable,
            t.view_count,
            t.deploy_count,
            t.required_plan_name,
            t.price,
            t.billing_cycle,
            t.currency,
            t.created_at,
            t.updated_at,
            t.approved_at,
            t.verifications,
            t.infrastructure_requirements,
            t.public_ports,
            t.vendor_url
        FROM stack_template t
        LEFT JOIN stack_category c ON t.category_id = c.id
        WHERE t.slug = $1 AND t.creator_user_id = $2"#,
    )
    .bind(slug)
    .bind(user_id)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("get_by_slug_and_user error: {:?}", e);
        "Internal Server Error".to_string()
    })
}

pub async fn get_by_slug_with_latest(
    pool: &PgPool,
    slug: &str,
) -> Result<(StackTemplate, Option<StackTemplateVersion>), String> {
    let query_span = tracing::info_span!("marketplace_get_by_slug_with_latest", slug = %slug);

    let template = sqlx::query_as::<_, StackTemplate>(
        r#"SELECT 
            t.id,
            t.creator_user_id,
            t.creator_name,
            t.name,
            t.slug,
            t.short_description,
            t.long_description,
            c.name AS "category_code",
            t.product_id,
            t.tags,
            t.tech_stack,
            t.status,
            t.is_configurable,
            t.view_count,
            t.deploy_count,
            t.required_plan_name,
            t.price,
            t.billing_cycle,
            t.currency,
            t.created_at,
            t.updated_at,
            t.approved_at,
            t.verifications,
            t.infrastructure_requirements,
            t.public_ports,
            t.vendor_url
        FROM stack_template t
        LEFT JOIN stack_category c ON t.category_id = c.id
        WHERE t.slug = $1 AND t.status = 'approved'"#,
    )
    .bind(slug)
    .fetch_one(pool)
    .instrument(query_span.clone())
    .await
    .map_err(|e| {
        tracing::error!("get_by_slug template error: {:?}", e);
        "Not Found".to_string()
    })?;

    let version = sqlx::query_as::<_, StackTemplateVersion>(
        r#"SELECT 
            id,
            template_id,
            version,
            stack_definition,
            config_files,
            assets,
            seed_jobs,
            post_deploy_hooks,
            update_mode_capabilities,
            definition_format,
            changelog,
            is_latest,
            created_at
        FROM stack_template_version WHERE template_id = $1 AND is_latest = true LIMIT 1"#,
    )
    .bind(template.id)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("get_by_slug version error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok((template, version))
}

pub async fn get_by_id(
    pool: &PgPool,
    template_id: uuid::Uuid,
) -> Result<Option<StackTemplate>, String> {
    let query_span = tracing::info_span!("marketplace_get_by_id", id = %template_id);

    let template = sqlx::query_as::<_, StackTemplate>(
        r#"SELECT 
            t.id,
            t.creator_user_id,
            t.creator_name,
            t.name,
            t.slug,
            t.short_description,
            t.long_description,
            c.name AS "category_code",
            t.product_id,
            t.tags,
            t.tech_stack,
            t.status,
            t.is_configurable,
            t.view_count,
            t.deploy_count,
            t.created_at,
            t.updated_at,
            t.approved_at,
            t.required_plan_name,
            t.price,
            t.billing_cycle,
            t.currency,
            t.verifications,
            t.infrastructure_requirements,
            t.public_ports,
            t.vendor_url
        FROM stack_template t
        LEFT JOIN stack_category c ON t.category_id = c.id
        WHERE t.id = $1"#,
    )
    .bind(template_id)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("get_by_id error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok(template)
}

pub async fn create_draft(
    pool: &PgPool,
    creator_user_id: &str,
    creator_name: Option<&str>,
    name: &str,
    slug: &str,
    short_description: Option<&str>,
    long_description: Option<&str>,
    category_code: Option<&str>,
    tags: serde_json::Value,
    tech_stack: serde_json::Value,
    infrastructure_requirements: serde_json::Value,
    price: f64,
    billing_cycle: &str,
    required_plan_name: Option<&str>,
    currency: &str,
    public_ports: Option<serde_json::Value>,
    vendor_url: Option<&str>,
) -> Result<StackTemplate, CreateDraftError> {
    let query_span = tracing::info_span!("marketplace_create_draft", slug = %slug);

    let price_f64 = price;

    if let Some(category_code) = category_code {
        sqlx::query(r#"INSERT INTO stack_category (name) VALUES ($1) ON CONFLICT DO NOTHING"#)
            .bind(category_code)
            .execute(pool)
            .instrument(query_span.clone())
            .await
            .map_err(|e| {
                tracing::error!("create_draft category upsert error: {:?}", e);
                CreateDraftError::Internal
            })?;
    }

    let rec = sqlx::query_as::<_, StackTemplate>(
        r#"INSERT INTO stack_template (
            creator_user_id, creator_name, name, slug,
            short_description, long_description, category_id,
            tags, tech_stack, infrastructure_requirements, status, price, billing_cycle, required_plan_name, currency,
            public_ports, vendor_url
        ) VALUES ($1,$2,$3,$4,$5,$6,(SELECT id FROM stack_category WHERE name = $7),$8,$9,$10,'draft',$11,$12,$13,$14,$15,$16)
        RETURNING 
            id,
            creator_user_id,
            creator_name,
            name,
            slug,
            short_description,
            long_description,
            (SELECT name FROM stack_category WHERE id = category_id) AS "category_code",
            product_id,
            tags,
            tech_stack,
            status,
            is_configurable,
            view_count,
            deploy_count,
            required_plan_name,
            price,
            billing_cycle,
            currency,
            created_at,
            updated_at,
            approved_at,
            verifications,
            infrastructure_requirements,
            public_ports,
            vendor_url
        "#,
    )
    .bind(creator_user_id)
    .bind(creator_name)
    .bind(name)
    .bind(slug)
    .bind(short_description)
    .bind(long_description)
    .bind(category_code)
    .bind(tags)
    .bind(tech_stack)
    .bind(infrastructure_requirements)
    .bind(price_f64)
    .bind(billing_cycle)
    .bind(required_plan_name)
    .bind(currency)
    .bind(public_ports)
    .bind(vendor_url)
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("create_draft error: {:?}", e);

        if let sqlx::Error::Database(db_err) = &e {
            if db_err.code().as_deref() == Some("23505")
                && db_err.constraint() == Some(SLUG_UNIQUE_CONSTRAINT)
            {
                return CreateDraftError::DuplicateSlug {
                    slug: slug.to_string(),
                };
            }
        }

        CreateDraftError::Internal
    })?;

    Ok(rec)
}

pub async fn set_latest_version(
    pool: &PgPool,
    template_id: &uuid::Uuid,
    version: &str,
    stack_definition: serde_json::Value,
    definition_format: Option<&str>,
    changelog: Option<&str>,
    config_files: serde_json::Value,
    assets: serde_json::Value,
    seed_jobs: serde_json::Value,
    post_deploy_hooks: serde_json::Value,
    update_mode_capabilities: Option<serde_json::Value>,
) -> Result<StackTemplateVersion, String> {
    let query_span =
        tracing::info_span!("marketplace_set_latest_version", template_id = %template_id);

    // Clear previous latest
    sqlx::query!(
        r#"UPDATE stack_template_version SET is_latest = false WHERE template_id = $1 AND is_latest = true"#,
        template_id
    )
    .execute(pool)
    .instrument(query_span.clone())
    .await
    .map_err(|e| {
        tracing::error!("clear_latest error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    let rec = sqlx::query_as::<_, StackTemplateVersion>(
        r#"INSERT INTO stack_template_version (
            template_id,
            version,
            stack_definition,
            config_files,
            assets,
            seed_jobs,
            post_deploy_hooks,
            update_mode_capabilities,
            definition_format,
            changelog,
            is_latest
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true)
        RETURNING
            id,
            template_id,
            version,
            stack_definition,
            config_files,
            assets,
            seed_jobs,
            post_deploy_hooks,
            update_mode_capabilities,
            definition_format,
            changelog,
            is_latest,
            created_at"#,
    )
    .bind(template_id)
    .bind(version)
    .bind(stack_definition)
    .bind(config_files)
    .bind(assets)
    .bind(seed_jobs)
    .bind(post_deploy_hooks)
    .bind(update_mode_capabilities)
    .bind(definition_format)
    .bind(changelog)
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("set_latest_version error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok(rec)
}

pub async fn upsert_latest_version(
    pool: &PgPool,
    template_id: &uuid::Uuid,
    version: &str,
    stack_definition: serde_json::Value,
    definition_format: Option<&str>,
    changelog: Option<&str>,
    config_files: serde_json::Value,
    assets: serde_json::Value,
    seed_jobs: serde_json::Value,
    post_deploy_hooks: serde_json::Value,
    update_mode_capabilities: Option<serde_json::Value>,
) -> Result<StackTemplateVersion, String> {
    let query_span =
        tracing::info_span!("marketplace_upsert_latest_version", template_id = %template_id);

    let updated = sqlx::query_as::<_, StackTemplateVersion>(
        r#"UPDATE stack_template_version
           SET version = $2,
               stack_definition = $3,
               config_files = $4,
               assets = $5,
               seed_jobs = $6,
               post_deploy_hooks = $7,
               update_mode_capabilities = $8,
               definition_format = $9,
               changelog = $10
           WHERE template_id = $1 AND is_latest = true
           RETURNING
               id,
               template_id,
               version,
               stack_definition,
               config_files,
               assets,
               seed_jobs,
               post_deploy_hooks,
               update_mode_capabilities,
               definition_format,
               changelog,
               is_latest,
               created_at"#,
    )
    .bind(template_id)
    .bind(version)
    .bind(stack_definition.clone())
    .bind(config_files.clone())
    .bind(assets.clone())
    .bind(seed_jobs.clone())
    .bind(post_deploy_hooks.clone())
    .bind(update_mode_capabilities.clone())
    .bind(definition_format)
    .bind(changelog)
    .fetch_optional(pool)
    .instrument(query_span.clone())
    .await
    .map_err(|e| {
        tracing::error!("upsert_latest_version update error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    if let Some(version_row) = updated {
        return Ok(version_row);
    }

    set_latest_version(
        pool,
        template_id,
        version,
        stack_definition,
        definition_format,
        changelog,
        config_files,
        assets,
        seed_jobs,
        post_deploy_hooks,
        update_mode_capabilities,
    )
    .await
}

pub async fn update_metadata(
    pool: &PgPool,
    template_id: &uuid::Uuid,
    name: Option<&str>,
    short_description: Option<&str>,
    long_description: Option<&str>,
    category_code: Option<&str>,
    tags: Option<serde_json::Value>,
    tech_stack: Option<serde_json::Value>,
    infrastructure_requirements: Option<serde_json::Value>,
    price: Option<f64>,
    billing_cycle: Option<&str>,
    required_plan_name: Option<&str>,
    currency: Option<&str>,
    public_ports: Option<serde_json::Value>,
    vendor_url: Option<&str>,
) -> Result<bool, String> {
    let query_span = tracing::info_span!("marketplace_update_metadata", template_id = %template_id);

    // Update only allowed statuses
    let status = sqlx::query_scalar!(
        r#"SELECT status FROM stack_template WHERE id = $1::uuid"#,
        template_id
    )
    .fetch_one(pool)
    .instrument(query_span.clone())
    .await
    .map_err(|e| {
        tracing::error!("get status error: {:?}", e);
        "Not Found".to_string()
    })?;

    if status != "draft" && status != "rejected" && status != "needs_changes" {
        return Err("Template not editable in current status".to_string());
    }

    if let Some(category_code) = category_code {
        sqlx::query(r#"INSERT INTO stack_category (name) VALUES ($1) ON CONFLICT DO NOTHING"#)
            .bind(category_code)
            .execute(pool)
            .instrument(query_span.clone())
            .await
            .map_err(|e| {
                tracing::error!("update_metadata category upsert error: {:?}", e);
                "Internal Server Error".to_string()
            })?;
    }

    let res = sqlx::query(
        r#"UPDATE stack_template SET 
            name = COALESCE($2, name),
            short_description = COALESCE($3, short_description),
            long_description = COALESCE($4, long_description),
            category_id = COALESCE((SELECT id FROM stack_category WHERE name = $5), category_id),
            tags = COALESCE($6, tags),
            tech_stack = COALESCE($7, tech_stack),
            infrastructure_requirements = COALESCE($8, infrastructure_requirements),
            price = COALESCE($9, price),
            billing_cycle = COALESCE($10, billing_cycle),
            required_plan_name = COALESCE($11, required_plan_name),
            currency = COALESCE($12, currency),
            public_ports = COALESCE($13, public_ports),
            vendor_url = COALESCE($14, vendor_url)
        WHERE id = $1::uuid"#,
    )
    .bind(template_id)
    .bind(name)
    .bind(short_description)
    .bind(long_description)
    .bind(category_code)
    .bind(tags)
    .bind(tech_stack)
    .bind(infrastructure_requirements)
    .bind(price)
    .bind(billing_cycle)
    .bind(required_plan_name)
    .bind(currency)
    .bind(public_ports)
    .bind(vendor_url)
    .execute(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("update_metadata error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok(res.rows_affected() > 0)
}

pub async fn update_metadata_for_resubmit(
    pool: &PgPool,
    template_id: &uuid::Uuid,
    name: Option<&str>,
    short_description: Option<&str>,
    long_description: Option<&str>,
    category_code: Option<&str>,
    tags: Option<serde_json::Value>,
    tech_stack: Option<serde_json::Value>,
    infrastructure_requirements: Option<serde_json::Value>,
    price: Option<f64>,
    billing_cycle: Option<&str>,
    required_plan_name: Option<&str>,
    currency: Option<&str>,
    public_ports: Option<serde_json::Value>,
    vendor_url: Option<&str>,
) -> Result<bool, String> {
    let query_span =
        tracing::info_span!("marketplace_update_metadata_for_resubmit", template_id = %template_id);

    let status = sqlx::query_scalar!(
        r#"SELECT status FROM stack_template WHERE id = $1::uuid"#,
        template_id
    )
    .fetch_one(pool)
    .instrument(query_span.clone())
    .await
    .map_err(|e| {
        tracing::error!("get status for resubmit error: {:?}", e);
        "Not Found".to_string()
    })?;

    if status != "rejected" && status != "needs_changes" && status != "approved" {
        return Err("Template metadata is not editable in current status".to_string());
    }

    if let Some(category_code) = category_code {
        sqlx::query(r#"INSERT INTO stack_category (name) VALUES ($1) ON CONFLICT DO NOTHING"#)
            .bind(category_code)
            .execute(pool)
            .instrument(query_span.clone())
            .await
            .map_err(|e| {
                tracing::error!(
                    "update_metadata_for_resubmit category upsert error: {:?}",
                    e
                );
                "Internal Server Error".to_string()
            })?;
    }

    let res = sqlx::query(
        r#"UPDATE stack_template SET
            name = COALESCE($2, name),
            short_description = COALESCE($3, short_description),
            long_description = COALESCE($4, long_description),
            category_id = COALESCE((SELECT id FROM stack_category WHERE name = $5), category_id),
            tags = COALESCE($6, tags),
            tech_stack = COALESCE($7, tech_stack),
            infrastructure_requirements = COALESCE($8, infrastructure_requirements),
            price = COALESCE($9, price),
            billing_cycle = COALESCE($10, billing_cycle),
            required_plan_name = COALESCE($11, required_plan_name),
            currency = COALESCE($12, currency),
            public_ports = COALESCE($13, public_ports),
            vendor_url = COALESCE($14, vendor_url)
        WHERE id = $1::uuid"#,
    )
    .bind(template_id)
    .bind(name)
    .bind(short_description)
    .bind(long_description)
    .bind(category_code)
    .bind(tags)
    .bind(tech_stack)
    .bind(infrastructure_requirements)
    .bind(price)
    .bind(billing_cycle)
    .bind(required_plan_name)
    .bind(currency)
    .bind(public_ports)
    .bind(vendor_url)
    .execute(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("update_metadata_for_resubmit error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok(res.rows_affected() > 0)
}

pub async fn submit_for_review(pool: &PgPool, template_id: &uuid::Uuid) -> Result<bool, String> {
    let query_span =
        tracing::info_span!("marketplace_submit_for_review", template_id = %template_id);

    let res = sqlx::query!(
        r#"UPDATE stack_template SET status = 'submitted' WHERE id = $1::uuid AND status IN ('draft','rejected','needs_changes')"#,
        template_id
    )
    .execute(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("submit_for_review error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok(res.rows_affected() > 0)
}

/// Resubmit a template for review with a new version.
/// Allowed from statuses: rejected, needs_changes, approved (for version updates).
/// Creates a new version, resets status to 'submitted'.
pub async fn resubmit_with_new_version(
    pool: &PgPool,
    template_id: &uuid::Uuid,
    name: Option<&str>,
    short_description: Option<&str>,
    long_description: Option<&str>,
    category_code: Option<&str>,
    tags: Option<serde_json::Value>,
    tech_stack: Option<serde_json::Value>,
    infrastructure_requirements: Option<serde_json::Value>,
    price: Option<f64>,
    billing_cycle: Option<&str>,
    required_plan_name: Option<&str>,
    currency: Option<&str>,
    public_ports: Option<serde_json::Value>,
    vendor_url: Option<&str>,
    version: &str,
    stack_definition: serde_json::Value,
    definition_format: Option<&str>,
    changelog: Option<&str>,
    config_files: serde_json::Value,
    assets: serde_json::Value,
    seed_jobs: serde_json::Value,
    post_deploy_hooks: serde_json::Value,
    update_mode_capabilities: Option<serde_json::Value>,
) -> Result<StackTemplateVersion, String> {
    let query_span =
        tracing::info_span!("marketplace_resubmit_with_new_version", template_id = %template_id);

    let mut tx = pool.begin().await.map_err(|e| {
        tracing::error!("tx begin error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    // Update status to submitted (allowed from rejected, needs_changes, approved)
    let res = sqlx::query!(
        r#"UPDATE stack_template SET status = 'submitted', updated_at = now()
           WHERE id = $1::uuid AND status IN ('rejected', 'needs_changes', 'approved')"#,
        template_id
    )
    .execute(&mut *tx)
    .instrument(query_span.clone())
    .await
    .map_err(|e| {
        tracing::error!("resubmit status update error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    if res.rows_affected() == 0 {
        return Err("Template cannot be resubmitted from its current status".to_string());
    }

    if let Some(category_code) = category_code {
        sqlx::query(r#"INSERT INTO stack_category (name) VALUES ($1) ON CONFLICT DO NOTHING"#)
            .bind(category_code)
            .execute(&mut *tx)
            .instrument(query_span.clone())
            .await
            .map_err(|e| {
                tracing::error!("resubmit category upsert error: {:?}", e);
                "Internal Server Error".to_string()
            })?;
    }

    sqlx::query(
        r#"UPDATE stack_template SET
            name = COALESCE($2, name),
            short_description = COALESCE($3, short_description),
            long_description = COALESCE($4, long_description),
            category_id = COALESCE((SELECT id FROM stack_category WHERE name = $5), category_id),
            tags = COALESCE($6, tags),
            tech_stack = COALESCE($7, tech_stack),
            infrastructure_requirements = COALESCE($8, infrastructure_requirements),
            price = COALESCE($9, price),
            billing_cycle = COALESCE($10, billing_cycle),
            required_plan_name = COALESCE($11, required_plan_name),
            currency = COALESCE($12, currency),
            public_ports = COALESCE($13, public_ports),
            vendor_url = COALESCE($14, vendor_url)
         WHERE id = $1::uuid"#,
    )
    .bind(template_id)
    .bind(name)
    .bind(short_description)
    .bind(long_description)
    .bind(category_code)
    .bind(tags.clone())
    .bind(tech_stack.clone())
    .bind(infrastructure_requirements.clone())
    .bind(price)
    .bind(billing_cycle)
    .bind(required_plan_name)
    .bind(currency)
    .bind(public_ports.clone())
    .bind(vendor_url)
    .execute(&mut *tx)
    .instrument(query_span.clone())
    .await
    .map_err(|e| {
        tracing::error!("resubmit metadata update error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    let current_latest = sqlx::query_as::<_, StackTemplateVersion>(
        r#"SELECT
                id,
                template_id,
                version,
                stack_definition,
                config_files,
                assets,
                seed_jobs,
                post_deploy_hooks,
                update_mode_capabilities,
                definition_format,
                changelog,
                is_latest,
                created_at
           FROM stack_template_version
           WHERE template_id = $1 AND is_latest = true
           LIMIT 1"#,
    )
    .bind(template_id)
    .fetch_optional(&mut *tx)
    .instrument(query_span.clone())
    .await
    .map_err(|e| {
        tracing::error!("load current latest version error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    if let Some(current_latest) = current_latest {
        if current_latest.version == version {
            let ver = sqlx::query_as::<_, StackTemplateVersion>(
                r#"UPDATE stack_template_version
                   SET stack_definition = $2,
                       config_files = $3,
                       assets = $4,
                       seed_jobs = $5,
                       post_deploy_hooks = $6,
                       update_mode_capabilities = $7,
                       definition_format = $8,
                       changelog = $9,
                       is_latest = true
                   WHERE id = $1
                   RETURNING
                       id,
                       template_id,
                       version,
                       stack_definition,
                       config_files,
                       assets,
                       seed_jobs,
                       post_deploy_hooks,
                       update_mode_capabilities,
                       definition_format,
                       changelog,
                       is_latest,
                       created_at"#,
            )
            .bind(current_latest.id)
            .bind(stack_definition.clone())
            .bind(config_files.clone())
            .bind(assets.clone())
            .bind(seed_jobs.clone())
            .bind(post_deploy_hooks.clone())
            .bind(update_mode_capabilities.clone())
            .bind(definition_format)
            .bind(changelog)
            .fetch_one(&mut *tx)
            .instrument(query_span.clone())
            .await
            .map_err(|e| {
                tracing::error!("update same-version resubmit error: {:?}", e);
                "Internal Server Error".to_string()
            })?;

            tx.commit().await.map_err(|e| {
                tracing::error!("tx commit error: {:?}", e);
                "Internal Server Error".to_string()
            })?;

            return Ok(ver);
        }
    }

    // Clear previous latest version
    sqlx::query!(
        r#"UPDATE stack_template_version SET is_latest = false WHERE template_id = $1 AND is_latest = true"#,
        template_id
    )
    .execute(&mut *tx)
    .instrument(query_span.clone())
    .await
    .map_err(|e| {
        tracing::error!("clear latest version error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    // Insert new version
    let ver = sqlx::query_as::<_, StackTemplateVersion>(
        r#"INSERT INTO stack_template_version (
            template_id,
            version,
            stack_definition,
            config_files,
            assets,
            seed_jobs,
            post_deploy_hooks,
            update_mode_capabilities,
            definition_format,
            changelog,
            is_latest
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true)
        RETURNING
            id,
            template_id,
            version,
            stack_definition,
            config_files,
            assets,
            seed_jobs,
            post_deploy_hooks,
            update_mode_capabilities,
            definition_format,
            changelog,
            is_latest,
            created_at"#,
    )
    .bind(template_id)
    .bind(version)
    .bind(stack_definition)
    .bind(config_files)
    .bind(assets)
    .bind(seed_jobs)
    .bind(post_deploy_hooks)
    .bind(update_mode_capabilities)
    .bind(definition_format)
    .bind(changelog)
    .fetch_one(&mut *tx)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("insert new version error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    tx.commit().await.map_err(|e| {
        tracing::error!("tx commit error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok(ver)
}

pub async fn list_mine(pool: &PgPool, user_id: &str) -> Result<Vec<StackTemplate>, String> {
    let query_span = tracing::info_span!("marketplace_list_mine", user = %user_id);

    sqlx::query_as::<_, StackTemplate>(
        r#"SELECT 
            t.id,
            t.creator_user_id,
            t.creator_name,
            t.name,
            t.slug,
            t.short_description,
            t.long_description,
            c.name AS "category_code",
            t.product_id,
            t.tags,
            t.tech_stack,
            t.status,
            t.is_configurable,
            t.view_count,
            t.deploy_count,
            t.required_plan_name,
            t.price,
            t.billing_cycle,
            t.currency,
            t.created_at,
            t.updated_at,
            t.approved_at,
            t.verifications,
            t.infrastructure_requirements,
            t.public_ports,
            t.vendor_url,
            v.version,
            v.changelog,
            COALESCE(v.config_files, '[]'::jsonb) AS config_files,
            COALESCE(v.assets, '[]'::jsonb) AS assets,
            COALESCE(v.seed_jobs, '[]'::jsonb) AS seed_jobs,
            COALESCE(v.post_deploy_hooks, '[]'::jsonb) AS post_deploy_hooks,
            v.update_mode_capabilities
        FROM stack_template t
        LEFT JOIN stack_template_version v ON v.template_id = t.id AND v.is_latest = true
        LEFT JOIN stack_category c ON t.category_id = c.id
        WHERE t.creator_user_id = $1
        ORDER BY t.created_at DESC"#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("list_mine error: {:?}", e);
        "Internal Server Error".to_string()
    })
}

pub async fn admin_list_submitted(pool: &PgPool) -> Result<Vec<StackTemplate>, String> {
    let query_span = tracing::info_span!("marketplace_admin_list_submitted");

    sqlx::query_as::<_, StackTemplate>(
        r#"SELECT 
            t.id,
            t.creator_user_id,
            t.creator_name,
            t.name,
            t.slug,
            t.short_description,
            t.long_description,
            c.name AS "category_code",
            t.product_id,
            t.tags,
            t.tech_stack,
            t.status,
            t.is_configurable,
            t.view_count,
            t.deploy_count,
            t.required_plan_name,
            t.price,
            t.billing_cycle,
            t.currency,
            t.created_at,
            t.updated_at,
            t.approved_at,
            t.verifications,
            t.infrastructure_requirements,
            t.public_ports,
            t.vendor_url
        FROM stack_template t
        LEFT JOIN stack_category c ON t.category_id = c.id
        WHERE t.status IN ('submitted', 'approved')
        ORDER BY 
            CASE t.status
                WHEN 'submitted' THEN 0
                WHEN 'approved' THEN 1
            END,
            t.created_at ASC"#,
    )
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("admin_list_submitted error: {:?}", e);
        "Internal Server Error".to_string()
    })
}

pub async fn admin_decide(
    pool: &PgPool,
    template_id: &uuid::Uuid,
    reviewer_user_id: &str,
    decision: &str,
    review_reason: Option<&str>,
    verifications: Option<&serde_json::Value>,
) -> Result<bool, String> {
    let _query_span = tracing::info_span!("marketplace_admin_decide", template_id = %template_id, decision = %decision);

    let valid = ["approved", "rejected", "needs_changes"];
    if !valid.contains(&decision) {
        return Err("Invalid decision".to_string());
    }

    let mut tx = pool.begin().await.map_err(|e| {
        tracing::error!("tx begin error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    sqlx::query!(
        r#"INSERT INTO stack_template_review (template_id, reviewer_user_id, decision, review_reason, reviewed_at) VALUES ($1::uuid, $2, $3, $4, now())"#,
        template_id,
        reviewer_user_id,
        decision,
        review_reason
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("insert review error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    let status_sql = if decision == "approved" {
        "approved"
    } else if decision == "rejected" {
        "rejected"
    } else {
        "needs_changes"
    };
    let should_set_approved = decision == "approved";

    sqlx::query!(
        r#"UPDATE stack_template SET status = $2, approved_at = CASE WHEN $3 THEN now() ELSE approved_at END WHERE id = $1::uuid"#,
        template_id,
        status_sql,
        should_set_approved
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("update template status error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    // Merge admin verifications into template.verifications if provided
    if let Some(v) = verifications {
        sqlx::query(
            r#"UPDATE stack_template SET verifications = verifications || $2::jsonb WHERE id = $1::uuid"#,
        )
        .bind(template_id)
        .bind(v)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("update verifications error: {:?}", e);
            "Internal Server Error".to_string()
        })?;
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("tx commit error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok(true)
}

/// Unapprove a template: set status back to 'submitted' and clear approved_at.
/// This hides the template from the marketplace until re-approved.
pub async fn admin_unapprove(
    pool: &PgPool,
    template_id: &uuid::Uuid,
    reviewer_user_id: &str,
    reason: Option<&str>,
) -> Result<bool, String> {
    let _query_span =
        tracing::info_span!("marketplace_admin_unapprove", template_id = %template_id);

    let mut tx = pool.begin().await.map_err(|e| {
        tracing::error!("tx begin error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    // Insert a review record documenting the unapproval
    sqlx::query!(
        r#"INSERT INTO stack_template_review (template_id, reviewer_user_id, decision, review_reason, reviewed_at) VALUES ($1::uuid, $2, 'rejected', $3, now())"#,
        template_id,
        reviewer_user_id,
        reason
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("insert unapproval review error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    // Set status back to 'submitted' and clear approved_at
    let result = sqlx::query!(
        r#"UPDATE stack_template SET status = 'submitted', approved_at = NULL WHERE id = $1::uuid AND status = 'approved'"#,
        template_id,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("unapprove template error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    tx.commit().await.map_err(|e| {
        tracing::error!("tx commit error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok(result.rows_affected() > 0)
}

/// Sync categories from User Service to local mirror
/// Upserts category data (id, name, title, metadata)
pub async fn sync_categories(
    pool: &PgPool,
    categories: Vec<crate::connectors::CategoryInfo>,
) -> Result<usize, String> {
    let query_span = tracing::info_span!("sync_categories", count = categories.len());
    let _enter = query_span.enter();

    if categories.is_empty() {
        tracing::info!("No categories to sync");
        return Ok(0);
    }

    let mut synced_count = 0;
    let mut error_count = 0;

    for category in categories {
        // Use INSERT ... ON CONFLICT DO UPDATE to upsert
        // Handle conflicts on both id and name (both have unique constraints)
        let result = sqlx::query(
            r#"
            INSERT INTO stack_category (id, name, title, metadata)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (id) DO UPDATE
            SET name = EXCLUDED.name,
                title = EXCLUDED.title,
                metadata = EXCLUDED.metadata
            "#,
        )
        .bind(category.id)
        .bind(&category.name)
        .bind(&category.title)
        .bind(serde_json::json!({"priority": category.priority}))
        .execute(pool)
        .await;

        // If conflict on id fails, try conflict on name
        let result = match result {
            Ok(r) => Ok(r),
            Err(e) if e.to_string().contains("stack_category_name_key") => {
                sqlx::query(
                    r#"
                    INSERT INTO stack_category (id, name, title, metadata)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (name) DO UPDATE
                    SET id = EXCLUDED.id,
                        title = EXCLUDED.title,
                        metadata = EXCLUDED.metadata
                    "#,
                )
                .bind(category.id)
                .bind(&category.name)
                .bind(&category.title)
                .bind(serde_json::json!({"priority": category.priority}))
                .execute(pool)
                .await
            }
            Err(e) => Err(e),
        };

        match result {
            Ok(res) if res.rows_affected() > 0 => {
                synced_count += 1;
            }
            Ok(_) => {
                tracing::debug!("Category {} already up to date", category.name);
            }
            Err(e) => {
                tracing::error!("Failed to sync category {}: {:?}", category.name, e);
                error_count += 1;
            }
        }
    }

    if error_count > 0 {
        tracing::warn!(
            "Synced {} categories with {} errors",
            synced_count,
            error_count
        );
    } else {
        tracing::info!("Synced {} categories from User Service", synced_count);
    }

    Ok(synced_count)
}

/// Get all categories from local mirror
pub async fn get_categories(pool: &PgPool) -> Result<Vec<StackCategory>, String> {
    let query_span = tracing::info_span!("get_categories");

    sqlx::query_as::<_, StackCategory>(
        r#"
        SELECT id, name, title, metadata
        FROM stack_category
        ORDER BY id
        "#,
    )
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch categories: {:?}", e);
        "Internal Server Error".to_string()
    })
}

/// List all versions for a template, ordered by creation date descending
pub async fn list_versions_by_template(
    pool: &PgPool,
    template_id: uuid::Uuid,
) -> Result<Vec<StackTemplateVersion>, String> {
    let query_span = tracing::info_span!("list_versions_by_template", template_id = %template_id);

    sqlx::query_as::<_, StackTemplateVersion>(
        r#"
        SELECT id, template_id, version, stack_definition, config_files, assets, seed_jobs,
               post_deploy_hooks, update_mode_capabilities, definition_format, changelog,
               is_latest, created_at
        FROM stack_template_version
        WHERE template_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(template_id)
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("list_versions_by_template error: {:?}", e);
        "Internal Server Error".to_string()
    })
}

pub async fn get_latest_version_by_template(
    pool: &PgPool,
    template_id: uuid::Uuid,
) -> Result<Option<StackTemplateVersion>, String> {
    let query_span =
        tracing::info_span!("get_latest_version_by_template", template_id = %template_id);

    sqlx::query_as::<_, StackTemplateVersion>(
        r#"
        SELECT id, template_id, version, stack_definition, config_files, assets, seed_jobs,
               post_deploy_hooks, update_mode_capabilities, definition_format, changelog,
               is_latest, created_at
        FROM stack_template_version
        WHERE template_id = $1 AND is_latest = true
        LIMIT 1
        "#,
    )
    .bind(template_id)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("get_latest_version_by_template error: {:?}", e);
        "Internal Server Error".to_string()
    })
}

pub async fn upsert_latest_version_asset(
    pool: &PgPool,
    template_id: uuid::Uuid,
    asset: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let query_span = tracing::info_span!("upsert_latest_version_asset", template_id = %template_id);

    let existing_assets: serde_json::Value = sqlx::query_scalar(
        r#"
        SELECT assets
        FROM stack_template_version
        WHERE template_id = $1 AND is_latest = true
        LIMIT 1
        "#,
    )
    .bind(template_id)
    .fetch_optional(pool)
    .instrument(query_span.clone())
    .await
    .map_err(|e| {
        tracing::error!("load_latest_version_assets error: {:?}", e);
        "Internal Server Error".to_string()
    })?
    .ok_or_else(|| "Latest template version not found".to_string())?;

    let asset_key = asset
        .get("key")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "Asset key is required".to_string())?;

    let mut assets = existing_assets.as_array().cloned().unwrap_or_default();
    if let Some(index) = assets.iter().position(|item| {
        item.get("key")
            .and_then(|value| value.as_str())
            .map(|key| key == asset_key)
            .unwrap_or(false)
    }) {
        assets[index] = asset.clone();
    } else {
        assets.push(asset.clone());
    }

    let updated_assets = serde_json::Value::Array(assets);

    sqlx::query(
        r#"
        UPDATE stack_template_version
        SET assets = $2
        WHERE template_id = $1 AND is_latest = true
        "#,
    )
    .bind(template_id)
    .bind(&updated_assets)
    .execute(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("upsert_latest_version_asset error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok(updated_assets)
}

pub async fn get_latest_version_asset_by_key(
    pool: &PgPool,
    template_id: uuid::Uuid,
    asset_key: &str,
) -> Result<Option<serde_json::Value>, String> {
    let query_span = tracing::info_span!(
        "get_latest_version_asset_by_key",
        template_id = %template_id,
        asset_key = %asset_key
    );

    let assets: serde_json::Value = sqlx::query_scalar(
        r#"
        SELECT assets
        FROM stack_template_version
        WHERE template_id = $1 AND is_latest = true
        LIMIT 1
        "#,
    )
    .bind(template_id)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("get_latest_version_asset_by_key error: {:?}", e);
        "Internal Server Error".to_string()
    })?
    .unwrap_or_else(|| serde_json::Value::Array(vec![]));

    Ok(assets.as_array().and_then(|items| {
        items
            .iter()
            .find(|item| {
                item.get("key")
                    .and_then(|value| value.as_str())
                    .map(|key| key == asset_key)
                    .unwrap_or(false)
            })
            .cloned()
    }))
}

/// List all reviews for a template, ordered by submission date descending
pub async fn list_reviews_by_template(
    pool: &PgPool,
    template_id: uuid::Uuid,
) -> Result<Vec<StackTemplateReview>, String> {
    let query_span = tracing::info_span!("list_reviews_by_template", template_id = %template_id);

    sqlx::query_as::<_, StackTemplateReview>(
        r#"
        SELECT id, template_id, reviewer_user_id, decision, review_reason,
               security_checklist, submitted_at, reviewed_at
        FROM stack_template_review
        WHERE template_id = $1
        ORDER BY submitted_at DESC
        "#,
    )
    .bind(template_id)
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("list_reviews_by_template error: {:?}", e);
        "Internal Server Error".to_string()
    })
}

pub async fn get_vendor_profile_by_creator(
    pool: &PgPool,
    creator_user_id: &str,
) -> Result<Option<MarketplaceVendorProfile>, String> {
    let query_span =
        tracing::info_span!("get_vendor_profile_by_creator", creator_user_id = %creator_user_id);

    sqlx::query_as::<_, MarketplaceVendorProfile>(
        r#"SELECT
            creator_user_id,
            verification_status,
            onboarding_status,
            payouts_enabled,
            payout_provider,
            payout_account_ref,
            metadata,
            created_at,
            updated_at
        FROM marketplace_vendor_profile
        WHERE creator_user_id = $1"#,
    )
    .bind(creator_user_id)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("get_vendor_profile_by_creator error: {:?}", e);
        "Internal Server Error".to_string()
    })
}

pub async fn upsert_vendor_profile(
    pool: &PgPool,
    creator_user_id: &str,
    verification_status: Option<&str>,
    onboarding_status: Option<&str>,
    payouts_enabled: Option<bool>,
    payout_provider: Option<&str>,
    payout_account_ref: Option<&str>,
    metadata: Option<serde_json::Value>,
) -> Result<MarketplaceVendorProfile, String> {
    let query_span =
        tracing::info_span!("upsert_vendor_profile", creator_user_id = %creator_user_id);

    sqlx::query_as::<_, MarketplaceVendorProfile>(
        r#"INSERT INTO marketplace_vendor_profile (
            creator_user_id,
            verification_status,
            onboarding_status,
            payouts_enabled,
            payout_provider,
            payout_account_ref,
            metadata
        )
        VALUES (
            $1,
            COALESCE($2, 'unverified'),
            COALESCE($3, 'not_started'),
            COALESCE($4, false),
            $5,
            $6,
            COALESCE($7, '{}'::jsonb)
        )
        ON CONFLICT (creator_user_id) DO UPDATE SET
            verification_status = COALESCE($2, marketplace_vendor_profile.verification_status),
            onboarding_status = COALESCE($3, marketplace_vendor_profile.onboarding_status),
            payouts_enabled = COALESCE($4, marketplace_vendor_profile.payouts_enabled),
            payout_provider = COALESCE($5, marketplace_vendor_profile.payout_provider),
            payout_account_ref = COALESCE($6, marketplace_vendor_profile.payout_account_ref),
            metadata = COALESCE($7, marketplace_vendor_profile.metadata),
            updated_at = NOW()
        RETURNING
            creator_user_id,
            verification_status,
            onboarding_status,
            payouts_enabled,
            payout_provider,
            payout_account_ref,
            metadata,
            created_at,
            updated_at"#,
    )
    .bind(creator_user_id)
    .bind(verification_status)
    .bind(onboarding_status)
    .bind(payouts_enabled)
    .bind(payout_provider)
    .bind(payout_account_ref)
    .bind(metadata)
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("upsert_vendor_profile error: {:?}", e);
        "Internal Server Error".to_string()
    })
}

fn metadata_object(metadata: &Value) -> Map<String, Value> {
    match metadata {
        Value::Object(map) => map.clone(),
        _ => Map::new(),
    }
}

fn onboarding_object(metadata: &Value) -> Map<String, Value> {
    metadata
        .get("onboarding")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn merge_onboarding_link_metadata(metadata: &Value) -> Value {
    let now = Utc::now().to_rfc3339();
    let mut root = metadata_object(metadata);
    let mut onboarding = onboarding_object(metadata);

    if !onboarding.contains_key("started_at") {
        onboarding.insert("started_at".to_string(), Value::String(now.clone()));
    }

    let request_count = onboarding
        .get("link_request_count")
        .and_then(Value::as_i64)
        .unwrap_or(0)
        + 1;

    onboarding.insert(
        "last_link_requested_at".to_string(),
        Value::String(now.clone()),
    );
    onboarding.insert(
        "link_request_count".to_string(),
        Value::Number(request_count.into()),
    );

    root.insert("onboarding".to_string(), Value::Object(onboarding));
    Value::Object(root)
}

fn merge_onboarding_completion_metadata(metadata: &Value, source: &str) -> Value {
    let now = Utc::now().to_rfc3339();
    let mut root = metadata_object(metadata);
    let mut onboarding = onboarding_object(metadata);

    onboarding.insert("completed_at".to_string(), Value::String(now));
    onboarding.insert(
        "completion_source".to_string(),
        Value::String(source.to_string()),
    );

    root.insert("onboarding".to_string(), Value::Object(onboarding));
    Value::Object(root)
}

pub async fn ensure_vendor_onboarding_link(
    pool: &PgPool,
    creator_user_id: &str,
    payout_provider: &str,
    generated_account_ref: &str,
) -> Result<(MarketplaceVendorProfile, bool), String> {
    let existing = get_vendor_profile_by_creator(pool, creator_user_id).await?;
    let linkage_created = existing
        .as_ref()
        .map(|profile| profile.payout_provider.is_none() || profile.payout_account_ref.is_none())
        .unwrap_or(true);

    let verification_status = existing
        .as_ref()
        .map(|profile| profile.verification_status.as_str())
        .unwrap_or("unverified");
    let onboarding_status = match existing
        .as_ref()
        .map(|profile| profile.onboarding_status.as_str())
    {
        Some("not_started") | None => "in_progress",
        Some(status) => status,
    };
    let payouts_enabled = existing
        .as_ref()
        .map(|profile| profile.payouts_enabled)
        .unwrap_or(false);
    let payout_provider = existing
        .as_ref()
        .and_then(|profile| profile.payout_provider.as_deref())
        .unwrap_or(payout_provider);
    let payout_account_ref = existing
        .as_ref()
        .and_then(|profile| profile.payout_account_ref.as_deref())
        .unwrap_or(generated_account_ref);
    let existing_metadata = existing
        .as_ref()
        .map(|profile| profile.metadata.clone())
        .unwrap_or_else(|| Value::Object(Map::new()));
    let metadata = merge_onboarding_link_metadata(&existing_metadata);

    let profile = upsert_vendor_profile(
        pool,
        creator_user_id,
        Some(verification_status),
        Some(onboarding_status),
        Some(payouts_enabled),
        Some(payout_provider),
        Some(payout_account_ref),
        Some(metadata),
    )
    .await?;

    Ok((profile, linkage_created))
}

pub async fn complete_vendor_onboarding(
    pool: &PgPool,
    creator_user_id: &str,
    source: &str,
) -> Result<Option<(MarketplaceVendorProfile, bool)>, String> {
    let existing = match get_vendor_profile_by_creator(pool, creator_user_id).await? {
        Some(profile) => profile,
        None => return Ok(None),
    };

    if existing.payout_provider.is_none() || existing.payout_account_ref.is_none() {
        return Ok(None);
    }

    if existing.onboarding_status == "not_started" {
        return Ok(None);
    }

    if existing.onboarding_status == "completed" {
        return Ok(Some((existing, false)));
    }

    let metadata = merge_onboarding_completion_metadata(&existing.metadata, source);
    let profile = upsert_vendor_profile(
        pool,
        creator_user_id,
        Some(&existing.verification_status),
        Some("completed"),
        Some(existing.payouts_enabled),
        existing.payout_provider.as_deref(),
        existing.payout_account_ref.as_deref(),
        Some(metadata),
    )
    .await?;

    Ok(Some((profile, true)))
}

/// Save a security scan result as a review record with security_checklist populated
pub async fn save_security_scan(
    pool: &PgPool,
    template_id: &uuid::Uuid,
    reviewer_user_id: &str,
    security_checklist: serde_json::Value,
) -> Result<StackTemplateReview, String> {
    let query_span = tracing::info_span!("save_security_scan", template_id = %template_id);

    sqlx::query_as::<_, StackTemplateReview>(
        r#"
        INSERT INTO stack_template_review
            (template_id, reviewer_user_id, decision, review_reason, security_checklist, submitted_at, reviewed_at)
        VALUES ($1, $2, 'pending', 'Automated security scan', $3, now(), now())
        RETURNING id, template_id, reviewer_user_id, decision, review_reason, security_checklist, submitted_at, reviewed_at
        "#,
    )
    .bind(template_id)
    .bind(reviewer_user_id)
    .bind(&security_checklist)
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("save_security_scan error: {:?}", e);
        "Internal Server Error".to_string()
    })
}

/// Admin: update pricing fields on any template regardless of status.
/// Normalizes price to 0 when billing_cycle is "free".
pub async fn admin_update_pricing(
    pool: &PgPool,
    template_id: &uuid::Uuid,
    price: Option<f64>,
    billing_cycle: Option<&str>,
    required_plan_name: Option<&str>,
    currency: Option<&str>,
) -> Result<bool, String> {
    let query_span = tracing::info_span!(
        "marketplace_admin_update_pricing",
        template_id = %template_id
    );

    // Normalize price=0 when billing_cycle is "free"
    let normalized_price = match billing_cycle {
        Some("free") => Some(0.0_f64),
        _ => price,
    };

    let res = sqlx::query(
        r#"UPDATE stack_template SET
            price = COALESCE($2, price),
            billing_cycle = COALESCE($3, billing_cycle),
            required_plan_name = COALESCE($4, required_plan_name),
            currency = COALESCE($5, currency)
        WHERE id = $1"#,
    )
    .bind(*template_id)
    .bind(normalized_price)
    .bind(billing_cycle)
    .bind(required_plan_name)
    .bind(currency)
    .execute(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("admin_update_pricing error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok(res.rows_affected() > 0)
}

/// Merge `updates` into the `verifications` JSONB column on a template.
/// Uses the PostgreSQL `||` operator so only the provided keys are overwritten.
pub async fn update_verifications(
    pool: &PgPool,
    template_id: &uuid::Uuid,
    updates: serde_json::Value,
) -> Result<bool, String> {
    let query_span =
        tracing::info_span!("marketplace_update_verifications", template_id = %template_id);

    let res = sqlx::query(
        r#"UPDATE stack_template
           SET verifications = verifications || $2
           WHERE id = $1"#,
    )
    .bind(*template_id)
    .bind(&updates)
    .execute(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("update_verifications error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok(res.rows_affected() > 0)
}

/// Increment view_count for a marketplace template
pub async fn increment_view_count(pool: &PgPool, template_id: &uuid::Uuid) -> Result<bool, String> {
    let query_span =
        tracing::info_span!("marketplace_increment_view_count", template_id = %template_id);

    let res = sqlx::query(
        r#"UPDATE stack_template SET view_count = COALESCE(view_count, 0) + 1 WHERE id = $1"#,
    )
    .bind(*template_id)
    .execute(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("increment_view_count error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok(res.rows_affected() > 0)
}

/// Increment deploy_count for a marketplace template
pub async fn increment_deploy_count(
    pool: &PgPool,
    template_id: &uuid::Uuid,
) -> Result<bool, String> {
    let query_span =
        tracing::info_span!("marketplace_increment_deploy_count", template_id = %template_id);

    let res = sqlx::query(
        r#"UPDATE stack_template SET deploy_count = COALESCE(deploy_count, 0) + 1 WHERE id = $1"#,
    )
    .bind(*template_id)
    .execute(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("increment_deploy_count error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok(res.rows_affected() > 0)
}

/// Record a successful marketplace deployment and increment deploy_count only once.
///
/// Returns:
/// - Ok(None) when the template does not exist
/// - Ok(Some(true)) when a new deployment_hash was recorded and deploy_count incremented
/// - Ok(Some(false)) when deployment_hash was already recorded
pub async fn record_deploy_complete_once(
    pool: &PgPool,
    template_id: &uuid::Uuid,
    deployment_hash: &str,
    server_ip: Option<&str>,
) -> Result<Option<bool>, String> {
    let query_span = tracing::info_span!(
        "marketplace_record_deploy_complete_once",
        template_id = %template_id,
        deployment_hash = %deployment_hash
    );

    let mut tx = pool.begin().await.map_err(|e| {
        tracing::error!("record_deploy_complete_once begin error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    let template_exists: Option<i32> =
        sqlx::query_scalar(r#"SELECT 1 FROM stack_template WHERE id = $1"#)
            .bind(*template_id)
            .fetch_optional(&mut *tx)
            .instrument(query_span.clone())
            .await
            .map_err(|e| {
                tracing::error!("record_deploy_complete_once template lookup error: {:?}", e);
                "Internal Server Error".to_string()
            })?;

    if template_exists.is_none() {
        tx.rollback().await.map_err(|e| {
            tracing::error!("record_deploy_complete_once rollback error: {:?}", e);
            "Internal Server Error".to_string()
        })?;
        return Ok(None);
    }

    let insert_res = sqlx::query(
        r#"INSERT INTO stack_template_deployment (template_id, deployment_hash, server_ip)
           VALUES ($1, $2, $3)
           ON CONFLICT (deployment_hash) DO NOTHING"#,
    )
    .bind(*template_id)
    .bind(deployment_hash)
    .bind(server_ip)
    .execute(&mut *tx)
    .instrument(query_span.clone())
    .await
    .map_err(|e| {
        tracing::error!("record_deploy_complete_once insert error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    if insert_res.rows_affected() == 0 {
        tx.commit().await.map_err(|e| {
            tracing::error!(
                "record_deploy_complete_once duplicate commit error: {:?}",
                e
            );
            "Internal Server Error".to_string()
        })?;
        return Ok(Some(false));
    }

    sqlx::query(
        r#"UPDATE stack_template
           SET deploy_count = COALESCE(deploy_count, 0) + 1
           WHERE id = $1"#,
    )
    .bind(*template_id)
    .execute(&mut *tx)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("record_deploy_complete_once increment error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    tx.commit().await.map_err(|e| {
        tracing::error!("record_deploy_complete_once commit error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    Ok(Some(true))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// TDD Stub Functions for Metrics/Analytics
// These are intentionally unimplemented - tests will FAIL until implemented
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Insert a view event into marketplace_event table
///
/// TDD stub - unimplemented. Requires:
/// - marketplace_event table migration
/// - INSERT query with template_id, event_type='view', viewer_user_id, occurred_at, metadata
pub async fn insert_view_event(
    _pool: &PgPool,
    _template_id: uuid::Uuid,
    _viewer_user_id: &str,
    _metadata: serde_json::Value,
) -> Result<(), String> {
    Err("insert_view_event not implemented - requires marketplace_event table".to_string())
}

/// Insert a deploy event into marketplace_event table
///
/// TDD stub - unimplemented. Requires:
/// - marketplace_event table migration with cloud_provider column
/// - INSERT query with template_id, event_type='deploy', deployer_user_id, cloud_provider, occurred_at, metadata
pub async fn insert_deploy_event(
    _pool: &PgPool,
    _template_id: uuid::Uuid,
    _deployer_user_id: &str,
    _cloud_provider: &str,
    _metadata: serde_json::Value,
) -> Result<(), String> {
    Err("insert_deploy_event not implemented - requires marketplace_event table".to_string())
}

/// Get vendor analytics for all templates owned by creator_user_id
///
/// TDD stub - unimplemented. Requires:
/// - Query logic to aggregate events by template.creator_user_id
/// - Owner-scoped filtering (only templates where creator_user_id matches)
/// - Fallback to stack_template.view_count/deploy_count when no events exist
/// - Cloud breakdown with percentages
/// - Time series buckets
pub async fn get_vendor_analytics(
    pool: &PgPool,
    creator_user_id: &str,
    period: Option<&str>,
) -> Result<VendorAnalytics, String> {
    get_vendor_analytics_for_period(pool, creator_user_id, period.unwrap_or("30d"), None, None)
        .await
}

/// Get vendor analytics for a specific period with start/end dates
///
/// TDD stub - unimplemented. Requires:
/// - Period filtering logic (7d, 30d, 90d, all, custom)
/// - Date range filtering with start_date/end_date for custom period
/// - Zero-filled time series buckets for missing data
/// - Bucket granularity calculation (day/week/month based on period)
pub async fn get_vendor_analytics_for_period(
    pool: &PgPool,
    creator_user_id: &str,
    period_key: &str,
    start_date: Option<chrono::DateTime<chrono::Utc>>,
    end_date: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<VendorAnalytics, String> {
    let now = Utc::now();
    let (normalized_period, default_start, bucket) = match period_key {
        "7d" => ("7d", Some(now - Duration::days(7)), "day"),
        "30d" => ("30d", Some(now - Duration::days(30)), "day"),
        "90d" => ("90d", Some(now - Duration::days(90)), "week"),
        "all" => ("all", None, "all"),
        "custom" => ("custom", start_date, "day"),
        _ => ("30d", Some(now - Duration::days(30)), "day"),
    };
    let start = start_date.or(default_start);
    let end = end_date.or(Some(now));

    let query_span = tracing::info_span!(
        "marketplace_vendor_analytics",
        creator_user_id = %creator_user_id,
        period = %normalized_period
    );

    let templates = sqlx::query(
        r#"SELECT
            t.id,
            t.creator_user_id,
            t.slug,
            t.name,
            t.status,
            COALESCE(COUNT(e.id) FILTER (WHERE e.event_type = 'view'), 0)::bigint AS views,
            COALESCE(COUNT(e.id) FILTER (WHERE e.event_type = 'deploy'), 0)::bigint AS deployments
        FROM stack_template t
        LEFT JOIN marketplace_template_event e
            ON e.template_id = t.id
           AND ($2::timestamptz IS NULL OR e.occurred_at >= $2)
           AND ($3::timestamptz IS NULL OR e.occurred_at <= $3)
        WHERE t.creator_user_id = $1
        GROUP BY t.id, t.creator_user_id, t.slug, t.name, t.status, t.created_at
        ORDER BY deployments DESC, views DESC, t.created_at DESC"#,
    )
    .bind(creator_user_id)
    .bind(start)
    .bind(end)
    .fetch_all(pool)
    .instrument(query_span.clone())
    .await
    .map_err(|e| {
        tracing::error!("get_vendor_analytics templates error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    let mut total_views = 0_i64;
    let mut total_deployments = 0_i64;
    let mut top_template_id = None;
    let mut template_items = Vec::with_capacity(templates.len());
    let mut top_templates = Vec::with_capacity(templates.len());

    for row in templates {
        let template_id: uuid::Uuid = row.get("id");
        let views: i64 = row.get("views");
        let deployments: i64 = row.get("deployments");
        let conversion_rate = conversion_rate(views, deployments);

        total_views += views;
        total_deployments += deployments;
        if top_template_id.is_none() && (views > 0 || deployments > 0) {
            top_template_id = Some(template_id);
        }

        let slug: String = row.get("slug");
        let name: String = row.get("name");
        let creator_user_id_row: String = row.get("creator_user_id");
        let status: String = row.get("status");

        template_items.push(TemplateAnalytics {
            template_id,
            creator_user_id: creator_user_id_row,
            slug: slug.clone(),
            name: name.clone(),
            status,
            views,
            deployments,
            conversion_rate,
        });
        top_templates.push(TemplatePerformance {
            template_id,
            slug,
            name,
            views,
            deployments,
            conversion_rate,
        });
    }

    let published_templates: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint
           FROM stack_template
           WHERE creator_user_id = $1 AND status = 'approved'"#,
    )
    .bind(creator_user_id)
    .fetch_one(pool)
    .instrument(query_span.clone())
    .await
    .map_err(|e| {
        tracing::error!("get_vendor_analytics published count error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    let cloud_rows = sqlx::query(
        r#"SELECT
            COALESCE(e.cloud_provider, 'unknown') AS cloud_provider,
            COUNT(*)::bigint AS deployments
        FROM marketplace_template_event e
        INNER JOIN stack_template t ON t.id = e.template_id
        WHERE t.creator_user_id = $1
          AND e.event_type = 'deploy'
          AND ($2::timestamptz IS NULL OR e.occurred_at >= $2)
          AND ($3::timestamptz IS NULL OR e.occurred_at <= $3)
        GROUP BY COALESCE(e.cloud_provider, 'unknown')
        ORDER BY deployments DESC, cloud_provider ASC"#,
    )
    .bind(creator_user_id)
    .bind(start)
    .bind(end)
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("get_vendor_analytics cloud breakdown error: {:?}", e);
        "Internal Server Error".to_string()
    })?;

    let mut top_cloud = None;
    let cloud_breakdown = cloud_rows
        .into_iter()
        .enumerate()
        .map(|(index, row)| {
            let cloud_provider: String = row.get("cloud_provider");
            let deployments: i64 = row.get("deployments");
            if index == 0 {
                top_cloud = Some(cloud_provider.clone());
            }
            CloudBreakdown {
                cloud_provider,
                deployments,
                percentage: percentage(deployments, total_deployments),
            }
        })
        .collect();

    let bucket_start = start.unwrap_or(now);
    let bucket_end = end.unwrap_or(now);

    Ok(VendorAnalytics {
        creator_id: creator_user_id.to_string(),
        period: AnalyticsPeriod {
            key: normalized_period.to_string(),
            start_date: start,
            end_date: end,
            bucket: bucket.to_string(),
        },
        summary: AnalyticsSummary {
            total_views,
            total_deployments,
            conversion_rate: conversion_rate(total_views, total_deployments),
            published_templates: published_templates.try_into().unwrap_or(i32::MAX),
            top_cloud,
            top_template_id,
        },
        views_series: vec![SeriesBucket {
            bucket_start,
            bucket_end,
            count: total_views,
        }],
        deployments_series: vec![SeriesBucket {
            bucket_start,
            bucket_end,
            count: total_deployments,
        }],
        cloud_breakdown,
        top_templates,
        templates: template_items,
    })
}

fn conversion_rate(views: i64, deployments: i64) -> f64 {
    if views == 0 {
        0.0
    } else {
        ((deployments as f64 / views as f64) * 10000.0).round() / 100.0
    }
}

fn percentage(part: i64, total: i64) -> f64 {
    if total == 0 {
        0.0
    } else {
        ((part as f64 / total as f64) * 10000.0).round() / 100.0
    }
}

/// Get template events filtered by creator_user_id (owner-scoped)
///
/// TDD stub - unimplemented. Requires:
/// - JOIN marketplace_event with stack_template on template_id
/// - Filter WHERE stack_template.creator_user_id = $creator_user_id
/// - Optional date range filtering
pub async fn get_template_events_by_creator(
    _pool: &PgPool,
    _creator_user_id: &str,
    _start_date: Option<chrono::DateTime<chrono::Utc>>,
    _end_date: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Vec<crate::models::marketplace::MarketplaceEvent>, String> {
    Err("get_template_events_by_creator not implemented - requires owner-scoped query".to_string())
}
