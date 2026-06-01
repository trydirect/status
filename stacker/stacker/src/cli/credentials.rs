use std::fmt;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::cli::error::CliError;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// StoredCredentials — what we persist to disk
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Credentials file stored at `~/.config/stacker/credentials.json`.
///
/// Mirrors the User Service OAuth token response (`/oauth_server/token`):
///   `{ access_token, refresh_token, token_type, scope, expires_in }`.
///
/// We additionally store the absolute expiry time and user email for
/// convenience (avoids a network call for `stacker whoami`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredentials {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_at: DateTime<Utc>,
    pub email: Option<String>,
    pub server_url: Option<String>,
    pub org: Option<String>,
    pub domain: Option<String>,
}

impl StoredCredentials {
    /// True when the access token's expiry has passed.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// True when the token will expire within the given duration.
    pub fn expires_within(&self, margin: Duration) -> bool {
        Utc::now() + margin >= self.expires_at
    }
}

/// Default session lifetime: 8 hours (28 800 seconds).
/// Can be overridden with the `STACKER_SESSION_TTL` environment variable
/// (value in seconds).
const DEFAULT_SESSION_TTL_SECS: u64 = 8 * 3600; // 8 hours

fn session_ttl_secs() -> u64 {
    std::env::var("STACKER_SESSION_TTL")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SESSION_TTL_SECS)
}

/// Convert an OAuth token response (with relative `expires_in`) into
/// `StoredCredentials` with an absolute `expires_at`.
///
/// The session lifetime is the **maximum** of the server-supplied
/// `expires_in` and the local default (8 h), so CLI sessions always
/// stay alive for a comfortable working window.
impl From<TokenResponse> for StoredCredentials {
    fn from(resp: TokenResponse) -> Self {
        let min_ttl = session_ttl_secs();
        let ttl = resp.expires_in.unwrap_or(min_ttl).max(min_ttl);
        let expires_at = Utc::now() + Duration::seconds(ttl as i64);

        Self {
            access_token: resp.access_token,
            refresh_token: resp.refresh_token,
            token_type: resp.token_type.unwrap_or_else(|| "Bearer".to_string()),
            expires_at,
            email: None,
            server_url: None,
            org: None,
            domain: None,
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// TokenResponse — raw OAuth /token reply
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Raw JSON returned by `POST /oauth_server/token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
    pub expires_in: Option<u64>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CredentialStore trait — abstraction for testability (DIP)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Pluggable storage back-end. Production writes to disk; tests use
/// an in-memory implementation.
pub trait CredentialStore: Send + Sync {
    fn save(&self, creds: &StoredCredentials) -> Result<(), CliError>;
    fn load(&self) -> Result<Option<StoredCredentials>, CliError>;
    fn delete(&self) -> Result<(), CliError>;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// FileCredentialStore — XDG-compliant file storage
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Stores credentials in `<config_dir>/stacker/credentials.json`.
///
/// On macOS: `~/Library/Application Support/stacker/credentials.json`
/// On Linux: `~/.config/stacker/credentials.json`
pub struct FileCredentialStore {
    path: PathBuf,
}

impl FileCredentialStore {
    /// Create a store rooted in the platform-specific config directory.
    /// Falls back to `~/.config/stacker/` if detection fails.
    pub fn default_path() -> PathBuf {
        let base = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
            .unwrap_or_else(|_| PathBuf::from("."));

        base.join("stacker").join("credentials.json")
    }

    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Use the platform default path.
    pub fn with_default_path() -> Self {
        Self::new(Self::default_path())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl CredentialStore for FileCredentialStore {
    fn save(&self, creds: &StoredCredentials) -> Result<(), CliError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(creds)
            .map_err(|e| CliError::AuthFailed(format!("Failed to serialize credentials: {e}")))?;

        std::fs::write(&self.path, &json)?;

        // Restrict permissions on Unix (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.path, perms)?;
        }

        Ok(())
    }

    fn load(&self) -> Result<Option<StoredCredentials>, CliError> {
        if !self.path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&self.path)?;
        let creds: StoredCredentials = serde_json::from_str(&content)
            .map_err(|e| CliError::AuthFailed(format!("Corrupt credentials file: {e}")))?;

        Ok(Some(creds))
    }

    fn delete(&self) -> Result<(), CliError> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CredentialsManager — high-level operations
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Orchestrates login, logout, token loading, and expiry checking.
///
/// Depends on `CredentialStore` (DIP) so tests can inject in-memory storage.
pub struct CredentialsManager<S: CredentialStore> {
    store: S,
}

impl<S: CredentialStore> CredentialsManager<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Persist a new credential set (typically after a successful login).
    pub fn save(&self, creds: &StoredCredentials) -> Result<(), CliError> {
        self.store.save(creds)
    }

    /// Load stored credentials, returning `None` if no file exists.
    pub fn load(&self) -> Result<Option<StoredCredentials>, CliError> {
        self.store.load()
    }

    /// Remove stored credentials (logout).
    pub fn logout(&self) -> Result<(), CliError> {
        self.store.delete()
    }

    /// Load credentials and ensure they are present and not expired.
    /// Returns `CliError::LoginRequired` when absent,
    /// `CliError::TokenExpired` when expired.
    pub fn require_valid_token(&self, feature: &str) -> Result<StoredCredentials, CliError> {
        let creds = self.store.load()?.ok_or_else(|| CliError::LoginRequired {
            feature: feature.to_string(),
        })?;

        if creds.is_expired() {
            return Err(CliError::TokenExpired);
        }

        Ok(creds)
    }

    /// Returns the bearer token header value if credentials are valid.
    pub fn bearer_header(&self, feature: &str) -> Result<String, CliError> {
        let creds = self.require_valid_token(feature)?;
        Ok(format!("{} {}", creds.token_type, creds.access_token))
    }
}

impl CredentialsManager<FileCredentialStore> {
    /// Convenience: create a manager backed by the default file path.
    pub fn with_default_store() -> Self {
        Self::new(FileCredentialStore::with_default_path())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// OAuthClient trait — abstraction over HTTP login calls
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// OAuth token endpoint path (relative to auth_url).
const TOKEN_ENDPOINT: &str = "/auth/login";

fn is_direct_login_endpoint(auth_url: &str) -> bool {
    let url = auth_url.trim_end_matches('/').to_lowercase();
    url.ends_with("/auth/login")
        || url.ends_with("/server/user/auth/login")
        || url.ends_with("/login")
}

fn resolve_auth_url(request: &LoginRequest) -> Result<String, CliError> {
    request
        .auth_url
        .clone()
        .or_else(|| std::env::var("STACKER_AUTH_URL").ok())
        .or_else(|| std::env::var("STACKER_API_URL").ok())
        .ok_or_else(|| {
            CliError::ConfigValidation(
                "Missing auth URL. Pass `stacker login --auth-url <user-service-url> --server-url <stacker-api-url>` or set STACKER_AUTH_URL (or STACKER_API_URL) and STACKER_URL.".to_string(),
            )
        })
}

fn resolve_server_url(request: &LoginRequest) -> Result<String, CliError> {
    request
        .server_url
        .clone()
        .or_else(|| std::env::var("STACKER_URL").ok())
        .map(|value| crate::cli::install_runner::normalize_stacker_server_url(&value))
        .ok_or_else(|| {
            CliError::ConfigValidation(
                "Missing Stacker API URL. Pass `stacker login --server-url <stacker-api-url>` (alias: `--api-url`) or set STACKER_URL.".to_string(),
            )
        })
}

/// Parameters for a login request.
#[derive(Debug, Clone)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub auth_url: Option<String>,
    pub server_url: Option<String>,
    pub org: Option<String>,
    pub domain: Option<String>,
}

/// Abstraction over the HTTP call to the OAuth token endpoint.
/// Production uses `HttpOAuthClient`; tests can inject a mock.
pub trait OAuthClient: Send + Sync {
    fn request_token(
        &self,
        auth_url: &str,
        email: &str,
        password: &str,
    ) -> Result<TokenResponse, CliError>;
}

/// Production OAuth client using `reqwest::blocking`.
pub struct HttpOAuthClient;

impl OAuthClient for HttpOAuthClient {
    fn request_token(
        &self,
        auth_url: &str,
        email: &str,
        password: &str,
    ) -> Result<TokenResponse, CliError> {
        let direct_login = is_direct_login_endpoint(auth_url);
        let url = if direct_login {
            auth_url.trim_end_matches('/').to_string()
        } else {
            format!("{}{}", auth_url.trim_end_matches('/'), TOKEN_ENDPOINT)
        };

        // Re-check: the constructed URL may now be a direct login endpoint
        let direct_login = direct_login || is_direct_login_endpoint(&url);

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| CliError::AuthFailed(format!("HTTP client error: {e}")))?;

        let resp = if direct_login {
            client
                .post(&url)
                .form(&[("email", email), ("password", password)])
                .send()
        } else {
            client
                .post(&url)
                .form(&[
                    ("grant_type", "password"),
                    ("username", email),
                    ("password", password),
                ])
                .send()
        }
        .map_err(|e| CliError::AuthFailed(format!("Network error: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            let body_preview: String = body.chars().take(240).collect();
            let html_404_hint = if status == reqwest::StatusCode::NOT_FOUND
                && (body.contains("<!DOCTYPE html") || body.contains("<html"))
            {
                format!(
                    "\nHint: if this is an API base URL, use `stacker-cli login --auth-url https://api.try.direct`; if this is a direct login endpoint, pass the full `/auth/login` URL (attempted: {}).",
                    auth_url
                )
            } else {
                String::new()
            };
            return Err(CliError::AuthFailed(format!(
                "Authentication failed (HTTP {status}): {body_preview}{html_404_hint}"
            )));
        }

        let token_resp: TokenResponse = resp
            .json()
            .map_err(|e| CliError::AuthFailed(format!("Invalid token response: {e}")))?;

        Ok(token_resp)
    }
}

/// High-level login function used by `LoginCommand`.
///
/// Obtains an OAuth token and persists credentials to the store.
pub fn login<S: CredentialStore, O: OAuthClient>(
    store: &CredentialsManager<S>,
    oauth: &O,
    request: &LoginRequest,
) -> Result<StoredCredentials, CliError> {
    let auth_url = resolve_auth_url(request)?;
    let server_url = resolve_server_url(request)?;
    let token_resp = oauth.request_token(&auth_url, &request.email, &request.password)?;
    let mut creds = StoredCredentials::from(token_resp);
    creds.email = Some(request.email.clone());
    creds.server_url = Some(server_url);
    creds.org = request.org.clone();
    creds.domain = request.domain.clone();

    store.save(&creds)?;
    Ok(creds)
}

impl fmt::Display for StoredCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let email = self.email.as_deref().unwrap_or("<unknown>");
        let expired = if self.is_expired() { " (expired)" } else { "" };
        write!(f, "Logged in as {email}{expired}")
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_is_direct_login_endpoint_detection() {
        assert!(is_direct_login_endpoint(
            "https://dev.try.direct/server/user/auth/login"
        ));
        assert!(is_direct_login_endpoint(
            "https://dev.try.direct/server/user/auth/login/"
        ));
        assert!(!is_direct_login_endpoint("https://api.try.direct"));
    }

    // ── In-memory mock store ────────────────────────

    #[derive(Clone, Default)]
    struct MockCredentialStore {
        inner: Arc<Mutex<Option<StoredCredentials>>>,
    }

    impl CredentialStore for MockCredentialStore {
        fn save(&self, creds: &StoredCredentials) -> Result<(), CliError> {
            *self.inner.lock().unwrap() = Some(creds.clone());
            Ok(())
        }

        fn load(&self) -> Result<Option<StoredCredentials>, CliError> {
            Ok(self.inner.lock().unwrap().clone())
        }

        fn delete(&self) -> Result<(), CliError> {
            *self.inner.lock().unwrap() = None;
            Ok(())
        }
    }

    fn valid_creds() -> StoredCredentials {
        StoredCredentials {
            access_token: "test-access-token".to_string(),
            refresh_token: Some("test-refresh-token".to_string()),
            token_type: "Bearer".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            email: Some("user@example.com".to_string()),
            server_url: Some("https://try.direct".to_string()),
            org: None,
            domain: None,
        }
    }

    fn expired_creds() -> StoredCredentials {
        StoredCredentials {
            access_token: "expired-token".to_string(),
            refresh_token: Some("expired-refresh".to_string()),
            token_type: "Bearer".to_string(),
            expires_at: Utc::now() - Duration::hours(1),
            email: Some("old@example.com".to_string()),
            server_url: None,
            org: None,
            domain: None,
        }
    }

    fn make_manager() -> (CredentialsManager<MockCredentialStore>, MockCredentialStore) {
        let store = MockCredentialStore::default();
        let manager = CredentialsManager::new(store.clone());
        (manager, store)
    }

    // ── StoredCredentials unit tests ────────────────

    #[test]
    fn test_valid_creds_not_expired() {
        let creds = valid_creds();
        assert!(!creds.is_expired());
    }

    #[test]
    fn test_expired_creds_is_expired() {
        let creds = expired_creds();
        assert!(creds.is_expired());
    }

    #[test]
    fn test_expires_within_margin() {
        let creds = StoredCredentials {
            access_token: "tok".into(),
            refresh_token: None,
            token_type: "Bearer".into(),
            expires_at: Utc::now() + Duration::minutes(3),
            email: None,
            server_url: None,
            org: None,
            domain: None,
        };
        assert!(creds.expires_within(Duration::minutes(5)));
        assert!(!creds.expires_within(Duration::minutes(1)));
    }

    #[test]
    fn test_display_shows_email() {
        let creds = valid_creds();
        let display = format!("{}", creds);
        assert!(display.contains("user@example.com"));
        assert!(!display.contains("expired"));
    }

    #[test]
    fn test_display_shows_expired() {
        let creds = expired_creds();
        let display = format!("{}", creds);
        assert!(display.contains("expired"));
    }

    // ── TokenResponse → StoredCredentials conversion ─

    #[test]
    fn test_token_response_to_stored_credentials() {
        let resp = TokenResponse {
            access_token: "new-token".into(),
            refresh_token: Some("new-refresh".into()),
            token_type: Some("Bearer".into()),
            scope: Some("read write".into()),
            expires_in: Some(7200),
        };
        let creds = StoredCredentials::from(resp);
        assert_eq!(creds.access_token, "new-token");
        assert_eq!(creds.refresh_token.as_deref(), Some("new-refresh"));
        assert_eq!(creds.token_type, "Bearer");
        // Server sent 7200 but minimum is 8 h → clamped to 8 h
        let expected = DEFAULT_SESSION_TTL_SECS as i64;
        let diff = creds.expires_at - Utc::now();
        assert!(diff.num_seconds() > expected - 100 && diff.num_seconds() <= expected);
    }

    #[test]
    fn test_token_response_respects_longer_server_ttl() {
        // When the server returns a TTL longer than 8 h, honour it.
        let ten_hours: u64 = 10 * 3600;
        let resp = TokenResponse {
            access_token: "tok".into(),
            refresh_token: None,
            token_type: None,
            scope: None,
            expires_in: Some(ten_hours),
        };
        let creds = StoredCredentials::from(resp);
        let diff = creds.expires_at - Utc::now();
        assert!(
            diff.num_seconds() > (ten_hours as i64) - 100 && diff.num_seconds() <= ten_hours as i64
        );
    }

    #[test]
    fn test_token_response_defaults() {
        let resp = TokenResponse {
            access_token: "tok".into(),
            refresh_token: None,
            token_type: None,
            scope: None,
            expires_in: None,
        };
        let creds = StoredCredentials::from(resp);
        assert_eq!(creds.token_type, "Bearer");
        // default expires_in is 8 hours (28800)
        let expected = DEFAULT_SESSION_TTL_SECS as i64;
        let diff = creds.expires_at - Utc::now();
        assert!(diff.num_seconds() > expected - 100 && diff.num_seconds() <= expected);
    }

    // ── CredentialsManager tests ────────────────────

    #[test]
    fn test_save_and_load() {
        let (manager, _) = make_manager();
        let creds = valid_creds();
        manager.save(&creds).unwrap();
        let loaded = manager.load().unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().access_token, "test-access-token");
    }

    #[test]
    fn test_load_returns_none_when_empty() {
        let (manager, _) = make_manager();
        let loaded = manager.load().unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_logout_removes_credentials() {
        let (manager, _) = make_manager();
        manager.save(&valid_creds()).unwrap();
        manager.logout().unwrap();
        let loaded = manager.load().unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_require_valid_token_succeeds() {
        let (manager, _) = make_manager();
        manager.save(&valid_creds()).unwrap();
        let creds = manager.require_valid_token("cloud deploy").unwrap();
        assert_eq!(creds.access_token, "test-access-token");
    }

    #[test]
    fn test_require_valid_token_login_required_when_empty() {
        let (manager, _) = make_manager();
        let err = manager.require_valid_token("cloud deploy").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Login required"));
        assert!(msg.contains("cloud deploy"));
    }

    #[test]
    fn test_require_valid_token_expired() {
        let (manager, _) = make_manager();
        manager.save(&expired_creds()).unwrap();
        let err = manager.require_valid_token("cloud deploy").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("expired"));
    }

    #[test]
    fn test_bearer_header_format() {
        let (manager, _) = make_manager();
        manager.save(&valid_creds()).unwrap();
        let header = manager.bearer_header("api call").unwrap();
        assert_eq!(header, "Bearer test-access-token");
    }

    #[test]
    fn test_bearer_header_login_required() {
        let (manager, _) = make_manager();
        let result = manager.bearer_header("api call");
        assert!(result.is_err());
    }

    // ── FileCredentialStore tests (real filesystem) ──

    #[test]
    fn test_file_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");
        let store = FileCredentialStore::new(path.clone());

        let creds = valid_creds();
        store.save(&creds).unwrap();

        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.access_token, creds.access_token);
        assert_eq!(loaded.email, creds.email);
    }

    #[test]
    fn test_file_store_load_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let store = FileCredentialStore::new(path);
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn test_file_store_delete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");
        let store = FileCredentialStore::new(path.clone());

        store.save(&valid_creds()).unwrap();
        assert!(path.exists());

        store.delete().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn test_file_store_delete_nonexistent_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let store = FileCredentialStore::new(path);
        assert!(store.delete().is_ok());
    }

    #[test]
    fn test_file_store_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("dir").join("creds.json");
        let store = FileCredentialStore::new(path.clone());

        store.save(&valid_creds()).unwrap();
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_file_store_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");
        let store = FileCredentialStore::new(path.clone());

        store.save(&valid_creds()).unwrap();

        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_default_path_contains_stacker() {
        let path = FileCredentialStore::default_path();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("stacker"));
        assert!(path_str.contains("credentials.json"));
    }

    // ── OAuthClient + login() tests ─────────────────

    /// Mock OAuthClient that returns a configurable result.
    struct MockOAuthClient {
        response: Option<TokenResponse>,
        error_msg: Option<String>,
    }

    impl MockOAuthClient {
        fn success() -> Self {
            Self {
                response: Some(TokenResponse {
                    access_token: "mock-access-token".into(),
                    refresh_token: Some("mock-refresh-token".into()),
                    token_type: Some("Bearer".into()),
                    scope: Some("read write".into()),
                    expires_in: Some(3600),
                }),
                error_msg: None,
            }
        }
        fn failure(msg: &str) -> Self {
            Self {
                response: None,
                error_msg: Some(msg.to_string()),
            }
        }
    }

    impl OAuthClient for MockOAuthClient {
        fn request_token(
            &self,
            _auth_url: &str,
            _email: &str,
            _password: &str,
        ) -> Result<TokenResponse, CliError> {
            match &self.response {
                Some(resp) => Ok(resp.clone()),
                None => Err(CliError::AuthFailed(
                    self.error_msg.clone().unwrap_or_default(),
                )),
            }
        }
    }

    #[test]
    fn test_login_saves_credentials() {
        let (manager, _store) = make_manager();
        let oauth = MockOAuthClient::success();
        let request = LoginRequest {
            email: "user@example.com".into(),
            password: "secret".into(),
            auth_url: Some("https://auth.example.com".into()),
            server_url: Some("https://stacker.example.com".into()),
            org: None,
            domain: None,
        };

        let creds = login(&manager, &oauth, &request).unwrap();
        assert_eq!(creds.access_token, "mock-access-token");
        assert_eq!(creds.email.as_deref(), Some("user@example.com"));
        assert_eq!(
            creds.server_url.as_deref(),
            Some("https://stacker.example.com")
        );

        // Verify persisted
        let loaded = manager.load().unwrap().unwrap();
        assert_eq!(loaded.access_token, "mock-access-token");
    }

    #[test]
    fn test_login_with_org_stores_org() {
        let (manager, _) = make_manager();
        let oauth = MockOAuthClient::success();
        let request = LoginRequest {
            email: "user@example.com".into(),
            password: "secret".into(),
            auth_url: Some("https://auth.example.com".into()),
            server_url: Some("https://stacker.example.com".into()),
            org: Some("acme".into()),
            domain: None,
        };

        let creds = login(&manager, &oauth, &request).unwrap();
        assert_eq!(creds.org.as_deref(), Some("acme"));
    }

    #[test]
    fn test_login_with_domain_stores_domain() {
        let (manager, _) = make_manager();
        let oauth = MockOAuthClient::success();
        let request = LoginRequest {
            email: "user@example.com".into(),
            password: "secret".into(),
            auth_url: Some("https://auth.example.com".into()),
            server_url: Some("https://stacker.example.com".into()),
            org: None,
            domain: Some("acme.com".into()),
        };

        let creds = login(&manager, &oauth, &request).unwrap();
        assert_eq!(creds.domain.as_deref(), Some("acme.com"));
    }

    #[test]
    fn test_login_invalid_credentials_returns_error() {
        let (manager, _) = make_manager();
        let oauth =
            MockOAuthClient::failure("Authentication failed (HTTP 401 Unauthorized): invalid");
        let request = LoginRequest {
            email: "bad@example.com".into(),
            password: "wrong".into(),
            auth_url: Some("https://auth.example.com".into()),
            server_url: Some("https://stacker.example.com".into()),
            org: None,
            domain: None,
        };

        let err = login(&manager, &oauth, &request).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Authentication failed"));
    }

    #[test]
    fn test_login_auth_url_override() {
        let (manager, _) = make_manager();
        let oauth = MockOAuthClient::success();
        let request = LoginRequest {
            email: "user@example.com".into(),
            password: "secret".into(),
            auth_url: Some("https://auth.example.com".into()),
            server_url: Some("https://custom.api".into()),
            org: None,
            domain: None,
        };

        let creds = login(&manager, &oauth, &request).unwrap();
        assert_eq!(creds.server_url.as_deref(), Some("https://custom.api"));
    }

    #[test]
    fn test_login_preserves_explicit_legacy_stacker_route() {
        let (manager, _) = make_manager();
        let oauth = MockOAuthClient::success();
        let request = LoginRequest {
            email: "user@example.com".into(),
            password: "secret".into(),
            auth_url: Some("https://dev.try.direct/server/user/auth/login".into()),
            server_url: Some("https://dev.try.direct/stacker".into()),
            org: None,
            domain: None,
        };

        let creds = login(&manager, &oauth, &request).unwrap();
        assert_eq!(
            creds.server_url.as_deref(),
            Some("https://dev.try.direct/stacker")
        );
    }

    #[test]
    fn test_login_preserves_explicit_api_gateway_url() {
        let (manager, _) = make_manager();
        let oauth = MockOAuthClient::success();
        let request = LoginRequest {
            email: "user@example.com".into(),
            password: "secret".into(),
            auth_url: Some("https://dev.try.direct/server/user/auth/login".into()),
            server_url: Some("https://api.try.direct".into()),
            org: None,
            domain: None,
        };

        let creds = login(&manager, &oauth, &request).unwrap();
        assert_eq!(creds.server_url.as_deref(), Some("https://api.try.direct"));
    }

    #[test]
    fn test_login_requires_auth_url_when_not_provided_by_flag_or_env() {
        let (manager, _) = make_manager();
        let oauth = MockOAuthClient::success();
        let request = LoginRequest {
            email: "user@example.com".into(),
            password: "secret".into(),
            auth_url: None,
            server_url: Some("https://dev.stacker.try.direct".into()),
            org: None,
            domain: None,
        };

        let err = login(&manager, &oauth, &request).unwrap_err();
        assert!(format!("{err}").contains("Missing auth URL"));
    }

    #[test]
    fn test_login_requires_server_url_when_not_provided_by_flag_or_env() {
        let (manager, _) = make_manager();
        let oauth = MockOAuthClient::success();
        let request = LoginRequest {
            email: "user@example.com".into(),
            password: "secret".into(),
            auth_url: Some("https://dev.try.direct/server/user/auth/login".into()),
            server_url: None,
            org: None,
            domain: None,
        };

        let err = login(&manager, &oauth, &request).unwrap_err();
        assert!(format!("{err}").contains("Missing Stacker API URL"));
    }

    #[test]
    fn test_login_refresh_existing_token() {
        let (manager, _) = make_manager();
        // Pre-populate with expired credentials
        manager.save(&expired_creds()).unwrap();

        let oauth = MockOAuthClient::success();
        let request = LoginRequest {
            email: "user@example.com".into(),
            password: "secret".into(),
            auth_url: Some("https://auth.example.com".into()),
            server_url: Some("https://stacker.example.com".into()),
            org: None,
            domain: None,
        };

        let creds = login(&manager, &oauth, &request).unwrap();
        assert_eq!(creds.access_token, "mock-access-token");
        assert!(!creds.is_expired());

        // Only one credential set stored (overwritten, not duplicated)
        let loaded = manager.load().unwrap().unwrap();
        assert_eq!(loaded.access_token, "mock-access-token");
    }
}
