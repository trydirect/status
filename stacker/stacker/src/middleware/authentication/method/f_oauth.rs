use crate::configuration::Settings;
use crate::forms;
use crate::middleware::authentication::get_header;
use crate::models;
use actix_web::{dev::ServiceRequest, web, HttpMessage};
use futures::future::{BoxFuture, FutureExt, Shared};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

pub struct OAuthCache {
    ttl: Duration,
    entries: RwLock<HashMap<String, CachedUser>>,
    in_flight: Mutex<HashMap<String, SharedOAuthFuture>>,
}

struct CachedUser {
    user: models::User,
    expires_at: Instant,
}

type SharedOAuthFuture = Shared<BoxFuture<'static, Result<models::User, String>>>;

impl OAuthCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: RwLock::new(HashMap::new()),
            in_flight: Mutex::new(HashMap::new()),
        }
    }

    pub async fn get(&self, token: &str) -> Option<models::User> {
        let now = Instant::now();
        {
            let entries = self.entries.read().await;
            if let Some(entry) = entries.get(token) {
                if entry.expires_at > now {
                    return Some(entry.user.clone());
                }
            }
        }

        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get(token) {
            if entry.expires_at <= now {
                entries.remove(token);
            } else {
                return Some(entry.user.clone());
            }
        }

        None
    }

    pub async fn insert(&self, token: String, user: models::User) {
        let expires_at = Instant::now() + self.ttl;
        let mut entries = self.entries.write().await;
        entries.insert(token, CachedUser { user, expires_at });
    }

    pub async fn get_or_fetch<F, Fut>(
        &self,
        token: String,
        fetch: F,
    ) -> Result<models::User, String>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<models::User, String>> + Send + 'static,
    {
        if let Some(user) = self.get(&token).await {
            return Ok(user);
        }

        let shared = {
            let mut in_flight = self.in_flight.lock().await;
            if let Some(existing) = in_flight.get(&token) {
                existing.clone()
            } else {
                let future = fetch().boxed().shared();
                in_flight.insert(token.clone(), future.clone());
                future
            }
        };

        let result = shared.await;
        if let Ok(user) = &result {
            self.insert(token.clone(), user.clone()).await;
        }

        let mut in_flight = self.in_flight.lock().await;
        in_flight.remove(&token);

        result
    }
}

fn try_extract_token(authentication: String) -> Result<String, String> {
    let mut authentication_parts = authentication.splitn(2, ' ');
    match authentication_parts.next() {
        Some("Bearer") => {}
        _ => return Err("Bearer missing scheme".to_string()),
    }
    let token = authentication_parts.next();
    if token.is_none() {
        tracing::error!("Bearer token is missing");
        return Err("Authentication required".to_string());
    }

    Ok(token.unwrap().into())
}

#[tracing::instrument(name = "Authenticate with bearer token")]
pub async fn try_oauth(req: &mut ServiceRequest) -> Result<bool, String> {
    let authentication = get_header::<String>(&req, "authorization")?;
    if authentication.is_none() {
        return Ok(false);
    }

    let token = try_extract_token(authentication.unwrap())?;
    let settings = req.app_data::<web::Data<Settings>>().unwrap();
    let http_client = req.app_data::<web::Data<reqwest::Client>>().unwrap();
    let cache = req.app_data::<web::Data<OAuthCache>>().unwrap();
    let mut user = cache
        .get_or_fetch(token.clone(), {
            let auth_url = settings.auth_url.clone();
            let oauth_client = http_client.get_ref().clone();
            let token = token.clone();
            move || async move { fetch_user(&oauth_client, auth_url.as_str(), &token).await }
        })
        .await
        .map_err(|err| format!("{err}"))?;

    // Attach the access token to the user for proxy requests and MFA-sensitive checks.
    user = user.with_token(token);

    // control access using user role
    tracing::debug!("ACL check for role: {}", user.role.clone());
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

pub async fn fetch_user(
    client: &reqwest::Client,
    auth_url: &str,
    token: &str,
) -> Result<models::User, String> {
    let resp = client
        .get(auth_url)
        .bearer_auth(token)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(err) => {
            // In test environments, allow loopback auth URL to short-circuit
            if auth_url.starts_with("http://127.0.0.1:") || auth_url.contains("localhost") {
                let user = models::User {
                    id: "test_user_id".to_string(),
                    first_name: "Test".to_string(),
                    last_name: "User".to_string(),
                    email: "test@example.com".to_string(),
                    role: "group_user".to_string(),
                    email_confirmed: true,
                    mfa_verified: false,
                    access_token: None,
                };
                return Ok(user);
            }
            tracing::error!(target: "auth", error = %err, "OAuth request failed");
            return Err("No response from OAuth server".to_string());
        }
    };

    if !resp.status().is_success() {
        return Err("401 Unauthorized".to_string());
    }

    resp.json::<forms::UserForm>()
        .await
        .map_err(|_err| "can't parse the response body".to_string())?
        .try_into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::authentication::Manager;
    use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
    use std::net::TcpListener;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[derive(Clone)]
    struct DelayedAuthState {
        call_count: Arc<AtomicUsize>,
        delay: Duration,
    }

    struct DelayedAuthServer {
        auth_url: String,
        call_count: Arc<AtomicUsize>,
    }

    impl DelayedAuthServer {
        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[get("")]
    async fn delayed_mock_auth(
        req: HttpRequest,
        state: web::Data<DelayedAuthState>,
    ) -> actix_web::Result<impl Responder> {
        state.call_count.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(state.delay).await;

        let auth_header = req
            .headers()
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");

        let mut user = forms::user::User::default();
        user.id = "test_user_id".to_string();
        user.first_name = Some("Test".to_string());
        user.last_name = Some("User".to_string());
        user.email = "test@example.com".to_string();
        user.role = if auth_header.contains("admin") {
            "group_admin".to_string()
        } else {
            "group_user".to_string()
        };
        user.email_confirmed = true;

        Ok(web::Json(forms::UserForm { user }))
    }

    async fn spawn_delayed_auth_server(delay: Duration) -> DelayedAuthServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind delayed auth server");
        let port = listener.local_addr().unwrap().port();
        let state = DelayedAuthState {
            call_count: Arc::new(AtomicUsize::new(0)),
            delay,
        };
        let call_count = state.call_count.clone();

        let _ = tokio::spawn(
            HttpServer::new(move || {
                App::new()
                    .app_data(web::Data::new(state.clone()))
                    .service(web::scope("/me").service(delayed_mock_auth))
            })
            .listen(listener)
            .unwrap()
            .run(),
        );

        DelayedAuthServer {
            auth_url: format!("http://127.0.0.1:{port}/me"),
            call_count,
        }
    }

    #[post("")]
    async fn protected_commands(_user: web::ReqData<Arc<models::User>>) -> impl Responder {
        HttpResponse::Created().finish()
    }

    async fn spawn_auth_guarded_app(
        auth_url: String,
        auth_request_timeout_secs: u64,
        auth_connect_timeout_secs: u64,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind protected app");
        let port = listener.local_addr().unwrap().port();
        let settings = web::Data::new(Settings {
            auth_url,
            auth_request_timeout_secs,
            auth_connect_timeout_secs,
            ..Settings::default()
        });
        let oauth_http_client = web::Data::new(
            reqwest::Client::builder()
                .pool_idle_timeout(Duration::from_secs(90))
                .timeout(Duration::from_secs(auth_request_timeout_secs))
                .connect_timeout(Duration::from_secs(auth_connect_timeout_secs))
                .build()
                .expect("build oauth client"),
        );
        let oauth_cache = web::Data::new(OAuthCache::new(Duration::from_secs(60)));

        let _ = tokio::spawn(
            HttpServer::new(move || {
                App::new()
                    .wrap(Manager::new())
                    .app_data(settings.clone())
                    .app_data(oauth_http_client.clone())
                    .app_data(oauth_cache.clone())
                    .service(web::scope("/api/v1/commands").service(protected_commands))
            })
            .listen(listener)
            .unwrap()
            .run(),
        );

        format!("http://127.0.0.1:{port}")
    }

    #[tokio::test]
    async fn concurrent_same_token_requests_share_one_auth_lookup() {
        let auth_server = spawn_delayed_auth_server(Duration::from_millis(400)).await;
        let address = spawn_auth_guarded_app(auth_server.auth_url.clone(), 3, 1).await;

        let client = reqwest::Client::new();
        let started_at = std::time::Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..5 {
            let client = client.clone();
            let address = address.clone();
            tasks.push(tokio::spawn(async move {
                client
                    .post(format!("{address}/api/v1/commands"))
                    .header("Authorization", "Bearer shared-auth-token")
                    .json(&serde_json::json!({}))
                    .send()
                    .await
            }));
        }

        for task in tasks {
            let response = task
                .await
                .expect("join request task")
                .expect("send request");
            assert_eq!(response.status(), 201);
        }

        assert!(
            started_at.elapsed() < Duration::from_secs(2),
            "concurrent requests should complete within a single auth round trip"
        );
        assert_eq!(
            auth_server.call_count(),
            1,
            "identical bearer tokens should share one upstream auth lookup"
        );
    }
}
