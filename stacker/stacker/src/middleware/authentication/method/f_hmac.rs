use crate::middleware::authentication::get_header; //todo move to helpers
use crate::models;
use actix_http::header::CONTENT_LENGTH;
use actix_web::{dev::ServiceRequest, web, HttpMessage};
use futures::StreamExt;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use tracing::Instrument;

async fn db_fetch_client(
    db_pool: &Pool<Postgres>,
    client_id: i32,
) -> Result<models::Client, String> {
    //todo
    let query_span = tracing::info_span!("Fetching the client by ID");

    sqlx::query_as!(
        models::Client,
        r#"SELECT id, user_id, secret FROM client c WHERE c.id = $1"#,
        client_id,
    )
    .fetch_one(db_pool)
    .instrument(query_span)
    .await
    .map_err(|err| match err {
        sqlx::Error::RowNotFound => "the client is not found".to_string(),
        e => {
            tracing::error!("Failed to execute fetch query: {:?}", e);
            String::new()
        }
    })
}

async fn compute_body_hash(
    req: &mut ServiceRequest,
    client_secret: &[u8],
) -> Result<String, String> {
    let content_length: usize = get_header(req, CONTENT_LENGTH.as_str())?.unwrap();
    let mut body = web::BytesMut::with_capacity(content_length);
    let mut payload = req.take_payload();
    while let Some(chunk) = payload.next().await {
        body.extend_from_slice(&chunk.expect("can't unwrap the chunk"));
    }

    let mut mac = match Hmac::<Sha256>::new_from_slice(client_secret) {
        Ok(mac) => mac,
        Err(err) => {
            tracing::error!("error generating hmac {err:?}");
            return Err("".to_string());
        }
    };

    mac.update(body.as_ref());
    let (_, mut payload) = actix_http::h1::Payload::create(true);
    payload.unread_data(body.into());
    req.set_payload(payload.into());

    Ok(format!("{:x}", mac.finalize().into_bytes()))
}

#[tracing::instrument(name = "try authenticate via hmac")]
pub async fn try_hmac(req: &mut ServiceRequest) -> Result<bool, String> {
    let client_id = get_header::<i32>(&req, "stacker-id")?;
    if client_id.is_none() {
        return Ok(false);
    }
    let client_id = client_id.unwrap();

    let header_hash = get_header::<String>(&req, "stacker-hash")?;
    if header_hash.is_none() {
        return Err("stacker-hash header is not set".to_string());
    } //todo
    let header_hash = header_hash.unwrap();

    let db_pool = req
        .app_data::<web::Data<Pool<Postgres>>>()
        .unwrap()
        .get_ref();
    let client: models::Client = db_fetch_client(db_pool, client_id).await?;
    if client.secret.is_none() {
        return Err("client is not active".to_string());
    }

    let client_secret = client.secret.as_ref().unwrap().as_bytes();
    let body_hash = compute_body_hash(req, client_secret).await?;
    if header_hash != body_hash {
        return Err("hash is wrong".to_string());
    }

    match req.extensions_mut().insert(Arc::new(client)) {
        Some(_) => {
            tracing::error!("client middleware already called once");
            return Err("".to_string());
        }
        None => {}
    }

    // Use "client" as the Casbin subject so it matches the Casbin policies
    // (e.g. `p, client, /api/v1/agent/register, POST`).
    // Previously this was `client_id.to_string()` which never matched any
    // group mapping and caused 403 for all HMAC-authenticated requests.
    let accesscontrol_vals = actix_casbin_auth::CasbinVals {
        subject: "client".to_string(),
        domain: None,
    };
    if req.extensions_mut().insert(accesscontrol_vals).is_some() {
        return Err("sth wrong with access control".to_string());
    }

    Ok(true)
}
