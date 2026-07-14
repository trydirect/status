use crate::models;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwtClaims {
    pub role: String,
    pub email: String,
    pub exp: i64,
}

/// Parse and validate JWT payload from internal admin services
///
/// WARNING: This verifies expiration only, not cryptographic signature.
/// Use only for internal service-to-service auth where issuer is trusted.
/// For production with untrusted clients, add full JWT verification.
pub fn parse_jwt_claims(token: &str) -> Result<JwtClaims, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // JWT format: header.payload.signature
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format: expected 3 parts (header.payload.signature)".to_string());
    }

    let payload = parts[1];

    // Decode base64url payload
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| format!("Failed to decode JWT payload: {}", e))?;

    let json: JwtClaims = serde_json::from_slice(&decoded)
        .map_err(|e| format!("Failed to parse JWT claims: {}", e))?;

    Ok(json)
}

/// Validate JWT token expiration
pub fn validate_jwt_expiration(claims: &JwtClaims) -> Result<(), String> {
    let now = chrono::Utc::now().timestamp();
    if claims.exp < now {
        return Err(format!(
            "JWT token expired (exp: {}, now: {})",
            claims.exp, now
        ));
    }
    Ok(())
}

/// Create a User model from JWT claims
/// Used for admin service authentication
pub fn user_from_jwt_claims(claims: &JwtClaims) -> models::User {
    models::User {
        id: claims.role.clone(),
        role: claims.role.clone(),
        email: claims.email.clone(),
        email_confirmed: false,
        first_name: "Service".to_string(),
        last_name: "Account".to_string(),
        mfa_verified: false,
        access_token: None,
    }
}

/// Extract Bearer token from Authorization header
pub fn extract_bearer_token(authorization: &str) -> Result<&str, String> {
    let parts: Vec<&str> = authorization.split_whitespace().collect();
    if parts.len() != 2 {
        return Err("Invalid Authorization header format".to_string());
    }
    if parts[0] != "Bearer" {
        return Err("Expected Bearer scheme in Authorization header".to_string());
    }
    Ok(parts[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde_json::json;

    fn create_test_jwt(role: &str, email: &str, exp: i64) -> String {
        let header = json!({"alg": "HS256", "typ": "JWT"});
        let payload = json!({"role": role, "email": email, "exp": exp});

        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string());
        let signature = "fake_signature"; // For testing, signature validation is not performed

        format!("{}.{}.{}", header_b64, payload_b64, signature)
    }

    #[test]
    fn test_parse_valid_jwt() {
        let future_exp = chrono::Utc::now().timestamp() + 3600;
        let token = create_test_jwt("admin_service", "admin@test.com", future_exp);

        let claims = parse_jwt_claims(&token).expect("Failed to parse valid JWT");
        assert_eq!(claims.role, "admin_service");
        assert_eq!(claims.email, "admin@test.com");
    }

    #[test]
    fn test_validate_expired_jwt() {
        let past_exp = chrono::Utc::now().timestamp() - 3600;
        let claims = JwtClaims {
            role: "admin_service".to_string(),
            email: "admin@test.com".to_string(),
            exp: past_exp,
        };

        assert!(validate_jwt_expiration(&claims).is_err());
    }

    #[test]
    fn test_extract_bearer_token() {
        let auth_header = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz.abc";
        let token = extract_bearer_token(auth_header).expect("Failed to extract token");
        assert_eq!(token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz.abc");
    }

    #[test]
    fn test_user_from_claims() {
        let claims = JwtClaims {
            role: "admin_service".to_string(),
            email: "admin@test.com".to_string(),
            exp: chrono::Utc::now().timestamp() + 3600,
        };

        let user = user_from_jwt_claims(&claims);
        assert_eq!(user.role, "admin_service");
        assert_eq!(user.email, "admin@test.com");
        assert_eq!(user.first_name, "Service");
    }
}
