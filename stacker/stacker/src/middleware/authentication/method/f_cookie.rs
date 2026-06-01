use crate::configuration::Settings;
use crate::middleware::authentication::get_header;
use actix_web::{dev::ServiceRequest, web, HttpMessage};
use std::sync::Arc;

#[tracing::instrument(name = "Authenticate with cookie")]
pub async fn try_cookie(req: &mut ServiceRequest) -> Result<bool, String> {
    // Get Cookie header
    let cookie_header = get_header::<String>(&req, "cookie")?;
    if cookie_header.is_none() {
        return Ok(false);
    }

    // Parse cookies to find access_token
    let cookies = cookie_header.unwrap();
    let token = cookies.split(';').find_map(|cookie| {
        let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
        if parts.len() == 2 && parts[0] == "access_token" {
            Some(parts[1].to_string())
        } else {
            None
        }
    });

    if token.is_none() {
        return Ok(false);
    }

    tracing::debug!("Found access_token in cookies");

    // Use same OAuth validation as Bearer token
    let settings = req.app_data::<web::Data<Settings>>().unwrap();
    let http_client = req.app_data::<web::Data<reqwest::Client>>().unwrap();
    let cache = req
        .app_data::<web::Data<super::f_oauth::OAuthCache>>()
        .unwrap();
    let token = token.unwrap();
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

    // Attach the access token to the user for proxy requests and MFA-sensitive checks.
    user = user.with_token(token);

    // Control access using user role
    tracing::debug!("ACL check for role (cookie auth): {}", user.role.clone());
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
