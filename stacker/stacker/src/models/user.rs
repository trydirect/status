use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize, Clone)]
pub struct User {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub role: String,
    pub email_confirmed: bool,
    #[serde(default)]
    pub mfa_verified: bool,
    /// Access token used for proxy requests to other services (e.g., User Service)
    /// This is set during authentication and used for MCP tool calls.
    #[serde(skip)]
    pub access_token: Option<String>,
}

impl User {
    /// Create a new User with an access token for service proxy requests
    pub fn with_token(mut self, token: String) -> Self {
        if access_token_has_mfa_claim(&token) {
            self.mfa_verified = true;
        }
        self.access_token = Some(token);
        self
    }

    pub fn has_verified_mfa(&self) -> bool {
        self.mfa_verified
            || self
                .access_token
                .as_deref()
                .map(access_token_has_mfa_claim)
                .unwrap_or(false)
    }
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .field("email", &self.email)
            .field("role", &self.role)
            .field("email_confirmed", &self.email_confirmed)
            .field("mfa_verified", &self.mfa_verified)
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

pub fn access_token_has_mfa_claim(token: &str) -> bool {
    let Some(payload) = token.split('.').nth(1) else {
        return false;
    };
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(payload) else {
        return false;
    };
    let Ok(claims) = serde_json::from_slice::<Value>(&decoded) else {
        return false;
    };

    claim_bool(
        &claims,
        &[
            "mfa",
            "mfa_verified",
            "mfaVerified",
            "two_factor_verified",
            "twoFactorVerified",
        ],
    ) || claim_contains_mfa(&claims, "amr")
        || claim_contains_mfa(&claims, "acr")
}

fn claim_bool(claims: &Value, names: &[&str]) -> bool {
    names
        .iter()
        .any(|name| claims.get(*name).and_then(Value::as_bool).unwrap_or(false))
}

fn claim_contains_mfa(claims: &Value, name: &str) -> bool {
    let Some(value) = claims.get(name) else {
        return false;
    };

    match value {
        Value::String(value) => is_mfa_method(value),
        Value::Array(values) => values.iter().filter_map(Value::as_str).any(is_mfa_method),
        _ => false,
    }
}

fn is_mfa_method(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "mfa" | "2fa" | "otp" | "totp" | "webauthn" | "fido" | "fido2" | "u2f"
    ) || value.to_ascii_lowercase().contains("multi-factor")
}

#[cfg(test)]
mod tests {
    use super::{access_token_has_mfa_claim, User};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde_json::json;

    fn token_with_claims(claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(json!({"alg": "none"}).to_string());
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        format!("{header}.{payload}.signature")
    }

    #[test]
    fn detects_mfa_from_amr_claim() {
        let token = token_with_claims(json!({"sub": "user-1", "amr": ["pwd", "totp"]}));
        assert!(access_token_has_mfa_claim(&token));
    }

    #[test]
    fn detects_mfa_from_boolean_claim() {
        let token = token_with_claims(json!({"sub": "user-1", "mfa_verified": true}));
        assert!(access_token_has_mfa_claim(&token));
    }

    #[test]
    fn rejects_token_without_mfa_claim() {
        let token = token_with_claims(json!({"sub": "user-1", "amr": ["pwd"]}));
        assert!(!access_token_has_mfa_claim(&token));
    }

    #[test]
    fn with_token_marks_user_mfa_verified_when_claim_is_present() {
        let token = token_with_claims(json!({"sub": "user-1", "amr": ["pwd", "webauthn"]}));
        let user = User {
            id: "user-1".to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            email: "user@example.com".to_string(),
            role: "group_user".to_string(),
            email_confirmed: true,
            mfa_verified: false,
            access_token: None,
        }
        .with_token(token);

        assert!(user.has_verified_mfa());
    }
}
