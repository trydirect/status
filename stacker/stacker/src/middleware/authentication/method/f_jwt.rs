use crate::connectors::{
    extract_bearer_token, parse_jwt_claims, user_from_jwt_claims, validate_jwt_expiration,
};
use crate::middleware::authentication::get_header;
use actix_web::dev::ServiceRequest;
use actix_web::HttpMessage;
use std::sync::Arc;

#[tracing::instrument(name = "Authenticate with JWT (admin service)")]
pub async fn try_jwt(req: &mut ServiceRequest) -> Result<bool, String> {
    let authorization = get_header::<String>(req, "authorization")?;
    if authorization.is_none() {
        return Ok(false);
    }

    let authorization = authorization.unwrap();

    // Extract Bearer token from header
    let token = match extract_bearer_token(&authorization) {
        Ok(t) => t,
        Err(_) => {
            return Ok(false); // Not a Bearer token, try other auth methods
        }
    };

    // Parse JWT claims (validates structure and expiration)
    let claims = match parse_jwt_claims(token) {
        Ok(c) => c,
        Err(err) => {
            tracing::debug!("JWT parsing failed: {}", err);
            return Ok(false); // Not a valid JWT, try other auth methods
        }
    };

    // Validate token hasn't expired
    if let Err(err) = validate_jwt_expiration(&claims) {
        tracing::warn!("JWT validation failed: {}", err);
        return Err(err);
    }

    // Create User from JWT claims
    let user = user_from_jwt_claims(&claims);

    // control access using user role
    tracing::debug!("ACL check for JWT role: {}", user.role);
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

    tracing::info!("JWT authentication successful for role: {}", claims.role);
    Ok(true)
}
