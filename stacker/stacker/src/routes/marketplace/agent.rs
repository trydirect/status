use actix_web::{post, web, HttpResponse, Result};
use sqlx::PgPool;

#[derive(Debug, serde::Deserialize)]
pub struct AgentRegisterRequest {
    pub purchase_token: String,
    pub server_fingerprint: serde_json::Value,
    pub stack_id: String,
}

#[derive(Debug, serde::Serialize)]
pub struct AgentRegisterResponse {
    pub agent_id: String,
    pub agent_token: String,
    pub deployment_hash: String,
    pub dashboard_url: String,
}

/// Generate a secure random token (64 characters)
fn generate_token() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut rng = rand::thread_rng();
    (0..64)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

#[tracing::instrument(name = "Register marketplace agent", skip_all)]
#[post("/register")]
pub async fn register_marketplace_agent_handler(
    _pg_pool: web::Data<PgPool>,
    body: web::Json<AgentRegisterRequest>,
) -> Result<HttpResponse> {
    let req = body.into_inner();

    // TODO: 1. Validate purchase token with User Service
    //          POST /marketplace/purchase-token/validate
    // TODO: 2. Create agent record in DB
    // TODO: 3. Create deployment record
    // TODO: 4. Call User Service /marketplace/link-deployment

    tracing::info!(
        "Marketplace agent registration: purchase_token={}, stack_id={}",
        req.purchase_token,
        req.stack_id
    );

    let agent_id = uuid::Uuid::new_v4().to_string();
    let agent_token = generate_token();
    let deployment_hash = format!("mkt_{}", &agent_id[..8]);

    let response = AgentRegisterResponse {
        agent_id,
        agent_token,
        deployment_hash,
        dashboard_url: std::env::var("STACKER_PUBLIC_URL")
            .unwrap_or_else(|_| "https://stacker.try.direct".to_string()),
    };

    Ok(HttpResponse::Created().json(response))
}
