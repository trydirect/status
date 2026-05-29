# External Service Connectors

This directory contains adapters for all external service integrations for your project.
 **All communication with external services MUST go through connectors** - this is a core architectural rule for Stacker.

## Why Connectors?

| Benefit | Description |
|---------|-------------|
| **Independence** | Stacker works standalone; external services are optional |
| **Testability** | Mock connectors in tests without calling external APIs |
| **Replaceability** | Swap HTTP for gRPC without changing route code |
| **Configuration** | Enable/disable services per environment |
| **Separation of Concerns** | Routes contain business logic only, not HTTP details |
| **Error Handling** | Centralized retry logic, timeouts, circuit breakers |

## Architecture Pattern

```
┌─────────────────────────────────────────────────────────┐
│                      Route Handler                       │
│  (Pure business logic - no HTTP/AMQP knowledge)         │
└─────────────────────────┬───────────────────────────────┘
                          │ Uses trait methods
                          ▼
┌─────────────────────────────────────────────────────────┐
│              Connector Trait (Interface)                 │
│  pub trait UserServiceConnector: Send + Sync            │
└─────────────────────────┬───────────────────────────────┘
                          │ Implemented by
                ┌─────────┴─────────┐
                ▼                   ▼
     ┌──────────────────┐  ┌──────────────────┐
     │  HTTP Client     │  │  Mock Connector  │
     │  (Production)    │  │  (Tests/Dev)     │
     └──────────────────┘  └──────────────────┘
```

## Existing Connectors

| Service | Status | Purpose |
|---------|--------|---------|
| User Service | ✅ Implemented | Create/manage stacks in TryDirect User Service |
| Payment Service | 🚧 Planned | Process marketplace template payments |
| Event Bus (RabbitMQ) | 🚧 Planned | Async notifications (template approved, deployment complete) |

## Adding a New Connector

### Step 1: Define Configuration

Add your service config to `config.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentServiceConfig {
    pub enabled: bool,
    pub base_url: String,
    pub timeout_secs: u64,
    #[serde(skip)]
    pub auth_token: Option<String>,
}

impl Default for PaymentServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "http://localhost:8000".to_string(),
            timeout_secs: 15,
            auth_token: None,
        }
    }
}
```

Then add to `ConnectorConfig`:
```rust
pub struct ConnectorConfig {
    pub user_service: Option<UserServiceConfig>,
    pub payment_service: Option<PaymentServiceConfig>, // Add this
}
```

### Step 2: Create Service File

Create `src/connectors/payment_service.rs`:

```rust
use super::config::PaymentServiceConfig;
use super::errors::ConnectorError;
use actix_web::web;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::Instrument;

// 1. Define response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResponse {
    pub payment_id: String,
    pub status: String,
    pub amount: f64,
}

// 2. Define trait interface
#[async_trait::async_trait]
pub trait PaymentServiceConnector: Send + Sync {
    async fn create_payment(
        &self,
        user_id: &str,
        amount: f64,
        currency: &str,
    ) -> Result<PaymentResponse, ConnectorError>;
    
    async fn get_payment_status(
        &self,
        payment_id: &str,
    ) -> Result<PaymentResponse, ConnectorError>;
}

// 3. Implement HTTP client
pub struct PaymentServiceClient {
    base_url: String,
    http_client: reqwest::Client,
    auth_token: Option<String>,
}

impl PaymentServiceClient {
    pub fn new(config: PaymentServiceConfig) -> Self {
        let timeout = std::time::Duration::from_secs(config.timeout_secs);
        let http_client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            base_url: config.base_url,
            http_client,
            auth_token: config.auth_token,
        }
    }

    fn auth_header(&self) -> Option<String> {
        self.auth_token
            .as_ref()
            .map(|token| format!("Bearer {}", token))
    }
}

#[async_trait::async_trait]
impl PaymentServiceConnector for PaymentServiceClient {
    async fn create_payment(
        &self,
        user_id: &str,
        amount: f64,
        currency: &str,
    ) -> Result<PaymentResponse, ConnectorError> {
        let span = tracing::info_span!(
            "payment_service_create_payment",
            user_id = %user_id,
            amount = %amount
        );

        let url = format!("{}/api/payments", self.base_url);
        let payload = serde_json::json!({
            "user_id": user_id,
            "amount": amount,
            "currency": currency,
        });

        let mut req = self.http_client.post(&url).json(&payload);
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send()
            .instrument(span)
            .await
            .and_then(|resp| resp.error_for_status())
            .map_err(|e| {
                tracing::error!("create_payment error: {:?}", e);
                ConnectorError::HttpError(format!("Failed to create payment: {}", e))
            })?;

        let text = resp.text().await
            .map_err(|e| ConnectorError::HttpError(e.to_string()))?;
        
        serde_json::from_str::<PaymentResponse>(&text)
            .map_err(|_| ConnectorError::InvalidResponse(text))
    }

    async fn get_payment_status(
        &self,
        payment_id: &str,
    ) -> Result<PaymentResponse, ConnectorError> {
        let span = tracing::info_span!(
            "payment_service_get_status",
            payment_id = %payment_id
        );

        let url = format!("{}/api/payments/{}", self.base_url, payment_id);
        let mut req = self.http_client.get(&url);
        
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send()
            .instrument(span)
            .await
            .map_err(|e| {
                if e.status().map_or(false, |s| s == 404) {
                    ConnectorError::NotFound(format!("Payment {} not found", payment_id))
                } else {
                    ConnectorError::HttpError(format!("Failed to get payment: {}", e))
                }
            })?;

        if resp.status() == 404 {
            return Err(ConnectorError::NotFound(format!("Payment {} not found", payment_id)));
        }

        let text = resp.text().await
            .map_err(|e| ConnectorError::HttpError(e.to_string()))?;
        
        serde_json::from_str::<PaymentResponse>(&text)
            .map_err(|_| ConnectorError::InvalidResponse(text))
    }
}

// 4. Provide mock for testing
pub mod mock {
    use super::*;

    pub struct MockPaymentServiceConnector;

    #[async_trait::async_trait]
    impl PaymentServiceConnector for MockPaymentServiceConnector {
        async fn create_payment(
            &self,
            user_id: &str,
            amount: f64,
            currency: &str,
        ) -> Result<PaymentResponse, ConnectorError> {
            Ok(PaymentResponse {
                payment_id: "mock_payment_123".to_string(),
                status: "completed".to_string(),
                amount,
            })
        }

        async fn get_payment_status(
            &self,
            payment_id: &str,
        ) -> Result<PaymentResponse, ConnectorError> {
            Ok(PaymentResponse {
                payment_id: payment_id.to_string(),
                status: "completed".to_string(),
                amount: 99.99,
            })
        }
    }
}

// 5. Add init function for startup.rs
pub fn init(connector_config: &super::config::ConnectorConfig) -> web::Data<Arc<dyn PaymentServiceConnector>> {
    let connector: Arc<dyn PaymentServiceConnector> = if let Some(payment_config) = 
        connector_config.payment_service.as_ref().filter(|c| c.enabled) 
    {
        let mut config = payment_config.clone();
        if config.auth_token.is_none() {
            config.auth_token = std::env::var("PAYMENT_SERVICE_AUTH_TOKEN").ok();
        }
        tracing::info!("Initializing Payment Service connector: {}", config.base_url);
        Arc::new(PaymentServiceClient::new(config))
    } else {
        tracing::warn!("Payment Service connector disabled - using mock");
        Arc::new(mock::MockPaymentServiceConnector)
    };
    
    web::Data::new(connector)
}
```

### Step 3: Export from mod.rs

Update `src/connectors/mod.rs`:

```rust
pub mod payment_service;

pub use payment_service::{PaymentServiceConnector, PaymentServiceClient};
pub use payment_service::init as init_payment_service;
```

### Step 4: Update Configuration Files

Add to `configuration.yaml` and `configuration.yaml.dist`:

```yaml
connectors:
  payment_service:
    enabled: false
    base_url: "http://localhost:8000"
    timeout_secs: 15
```

### Step 5: Register in startup.rs

Add to `src/startup.rs`:

```rust
// Initialize connectors
let payment_service = connectors::init_payment_service(&settings.connectors);

// In App builder:
App::new()
    .app_data(payment_service)
    // ... other middleware
```

### Step 6: Use in Routes

```rust
use crate::connectors::PaymentServiceConnector;

#[post("/purchase/{template_id}")]
pub async fn purchase_handler(
    user: web::ReqData<Arc<User>>,
    payment_connector: web::Data<Arc<dyn PaymentServiceConnector>>,
    path: web::Path<(String,)>,
) -> Result<impl Responder> {
    let template_id = path.into_inner().0;
    
    // Route logic never knows about HTTP
    let payment = payment_connector
        .create_payment(&user.id, 99.99, "USD")
        .await
        .map_err(|e| JsonResponse::build().bad_request(e.to_string()))?;
    
    Ok(JsonResponse::build().ok(payment))
}
```

## Testing Connectors

### Unit Tests (with Mock)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::payment_service::mock::MockPaymentServiceConnector;

    #[tokio::test]
    async fn test_purchase_without_external_api() {
        let connector = Arc::new(MockPaymentServiceConnector);
        
        let result = connector.create_payment("user_123", 99.99, "USD").await;
        assert!(result.is_ok());
        
        let payment = result.unwrap();
        assert_eq!(payment.status, "completed");
    }
}
```

### Integration Tests (with Real Service)

```rust
#[tokio::test]
#[ignore] // Run with: cargo test -- --ignored
async fn test_real_payment_service() {
    let config = PaymentServiceConfig {
        enabled: true,
        base_url: "http://localhost:8000".to_string(),
        timeout_secs: 10,
        auth_token: Some("test_token".to_string()),
    };
    
    let connector = Arc::new(PaymentServiceClient::new(config));
    let result = connector.create_payment("test_user", 1.00, "USD").await;
    
    assert!(result.is_ok());
}
```

## Best Practices

### ✅ DO

- **Use trait objects** (`Arc<dyn Trait>`) for flexibility
- **Add retries** for transient failures (network issues)
- **Log errors** with context (user_id, request_id)
- **Use tracing spans** for observability
- **Handle timeouts** explicitly
- **Validate responses** before deserializing
- **Return typed errors** (ConnectorError enum)
- **Mock for tests** - never call real APIs in unit tests

### ❌ DON'T

- **Call HTTP directly from routes** - always use connectors
- **Panic on errors** - return `Result<T, ConnectorError>`
- **Expose reqwest types** - wrap in ConnectorError
- **Hardcode URLs** - always use config
- **Share HTTP clients** across different services
- **Skip error context** - log with tracing for debugging
- **Test with real APIs** unless explicitly integration tests

## Error Handling

All connectors use `ConnectorError` enum:

```rust
pub enum ConnectorError {
    HttpError(String),           // Network/HTTP errors
    ServiceUnavailable(String),  // Service down or timeout
    InvalidResponse(String),     // Bad JSON/unexpected format
    Unauthorized(String),        // 401/403
    NotFound(String),           // 404
    RateLimited(String),        // 429
    Internal(String),           // Unexpected errors
}
```

Convert external errors:
```rust
.map_err(|e| {
    if e.is_timeout() {
        ConnectorError::ServiceUnavailable(e.to_string())
    } else if e.status() == Some(404) {
        ConnectorError::NotFound("Resource not found".to_string())
    } else {
        ConnectorError::HttpError(e.to_string())
    }
})
```

## Environment Variables

Connectors can load auth tokens from environment:

```bash
# .env or export
export USER_SERVICE_AUTH_TOKEN="Bearer abc123..."
export PAYMENT_SERVICE_AUTH_TOKEN="Bearer xyz789..."
```

Tokens are loaded in the `init()` function:
```rust
if config.auth_token.is_none() {
    config.auth_token = std::env::var("PAYMENT_SERVICE_AUTH_TOKEN").ok();
}
```

## Configuration Reference

### Enable/Disable Services

```yaml
connectors:
  user_service:
    enabled: true   # ← Toggle here
```

- `enabled: true` → Uses HTTP client (production)
- `enabled: false` → Uses mock connector (tests/development)

### Timeouts

```yaml
timeout_secs: 10  # Request timeout in seconds
```

Applies to entire request (connection + response).

### Retries

Implement retry logic in client:
```rust
retry_attempts: 3  # Number of retry attempts
```

Use exponential backoff between retries.

## Debugging

### Enable Connector Logs

```bash
RUST_LOG=stacker::connectors=debug cargo run
```

### Check Initialization

Look for these log lines at startup:
```
INFO stacker::connectors::user_service: Initializing User Service connector: https://api.example.com
WARN stacker::connectors::payment_service: Payment Service connector disabled - using mock
```

### Trace HTTP Requests

```rust
let span = tracing::info_span!(
    "user_service_create_stack",
    template_id = %marketplace_template_id,
    user_id = %user_id
);

req.send()
    .instrument(span)  // ← Adds tracing
    .await
```

## Checklist for New Connector

- [ ] Config struct in `config.rs` with `Default` impl
- [ ] Add to `ConnectorConfig` struct
- [ ] Create `{service}.rs` with trait, client, mock, `init()`
- [ ] Export in `mod.rs`
- [ ] Add to `configuration.yaml` and `.yaml.dist`
- [ ] Register in `startup.rs`
- [ ] Write unit tests with mock
- [ ] Write integration tests (optional, marked `#[ignore]`)
- [ ] Document in copilot instructions
- [ ] Update this README with new connector in table

## Further Reading

- [Error Handling Patterns](../helpers/README.md)
- [Testing Guide](../../tests/README.md)
