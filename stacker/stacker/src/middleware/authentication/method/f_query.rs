use crate::configuration::Settings;
use actix_web::{dev::ServiceRequest, web, HttpMessage};
use std::sync::Arc;
use urlencoding::decode;

#[tracing::instrument(name = "Authenticate with query token")]
pub async fn try_query(req: &mut ServiceRequest) -> Result<bool, String> {
    if !req.path().starts_with("/mcp") {
        return Ok(false);
    }

    let query = req.query_string();
    if query.is_empty() {
        return Ok(false);
    }

    let raw_token = query.split('&').find_map(|pair| {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next()?;
        let value = parts.next()?;
        if key == "access_token" {
            Some(value.to_string())
        } else {
            None
        }
    });

    if raw_token.is_none() {
        return Ok(false);
    }

    let raw_token = raw_token.unwrap();
    let token = decode(&raw_token)
        .map(|value| value.into_owned())
        .unwrap_or(raw_token);

    tracing::debug!("Found access_token in query for MCP request");

    let settings = req.app_data::<web::Data<Settings>>().unwrap();
    let http_client = req.app_data::<web::Data<reqwest::Client>>().unwrap();
    let cache = req
        .app_data::<web::Data<super::f_oauth::OAuthCache>>()
        .unwrap();

    let mut user = match cache.get(&token).await {
        Some(user) => user,
        None => {
            let user = super::f_oauth::fetch_user(
                http_client.get_ref(),
                settings.auth_url.as_str(),
                &token,
            )
            .await
            .map_err(|err| format!("{err}"))?;
            cache.insert(token.clone(), user.clone()).await;
            user
        }
    };

    user = user.with_token(token);

    tracing::debug!("ACL check for role (query auth): {}", user.role.clone());
    let acl_vals = actix_casbin_auth::CasbinVals {
        subject: user.role.clone(),
        domain: None,
    };

    if req.extensions_mut().insert(Arc::new(user)).is_some() {
        return Err("user already logged".to_string());
    }

    if req.extensions_mut().insert(acl_vals).is_some() {
        return Err("Something wrong with access control".to_string());
    }

    Ok(true)
}
