use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCapacity {
    pub id: String,
    pub ram_mb: Option<i32>,
    pub cpu_cores: Option<i32>,
    pub disk_gb: Option<i32>,
}

pub fn app_service_base_url() -> String {
    std::env::var("APP_SERVICE_URL").unwrap_or_else(|_| "http://app:4200".to_string())
}

pub fn is_supported_cloud_provider(provider: &str) -> bool {
    matches!(
        provider,
        "do" | "htz" | "lo" | "scw" | "aws" | "gc" | "vu" | "ovh" | "upc" | "ali"
    )
}

pub async fn fetch_catalog(
    provider: &str,
    resource: &str,
    cloud_id: Option<i32>,
    access_token: Option<&str>,
) -> Result<Value, String> {
    if !is_supported_cloud_provider(provider) {
        return Err(
            "Unsupported provider. Use one of: do, htz, lo, scw, aws, gc, vu, ovh, upc, ali"
                .to_string(),
        );
    }

    let base_url = app_service_base_url().trim_end_matches('/').to_string();
    let mut url = format!("{}/{}/{}", base_url, provider, resource);

    if let Some(cloud_id) = cloud_id {
        url.push_str(&format!("?cloud_id={}", cloud_id));
    }

    let client = reqwest::Client::new();
    let mut request = client.get(&url);

    if let Some(token) = access_token.filter(|token| !token.is_empty()) {
        request = request.header("Authorization", format!("Bearer {}", token));
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("Failed to call App Service: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("App Service error {}: {}", status, body));
    }

    response
        .json::<Value>()
        .await
        .map_err(|e| format!("Failed to parse App Service response: {}", e))
}

fn parse_i32(value: Option<&Value>) -> Option<i32> {
    match value {
        Some(Value::Number(number)) => {
            if let Some(integer) = number.as_i64() {
                i32::try_from(integer).ok()
            } else {
                number.as_f64().map(|float| float.round() as i32)
            }
        }
        Some(Value::String(string)) => string
            .parse::<i64>()
            .ok()
            .and_then(|integer| i32::try_from(integer).ok())
            .or_else(|| string.parse::<f64>().ok().map(|float| float.round() as i32)),
        _ => None,
    }
}

fn parse_ram_mb(value: Option<&Value>) -> Option<i32> {
    match value {
        Some(Value::Number(number)) => number
            .as_f64()
            .map(|ram_gb| (ram_gb * 1024.0).round() as i32),
        Some(Value::String(string)) => string
            .parse::<f64>()
            .ok()
            .map(|ram_gb| (ram_gb * 1024.0).round() as i32),
        _ => None,
    }
}

pub fn resolve_server_capacity(payload: &Value, server_slug: &str) -> Option<ServerCapacity> {
    let servers = payload.get("servers")?.as_array()?;
    let server = servers.iter().find(|server| {
        server
            .get("id")
            .and_then(Value::as_str)
            .map(|id| id.eq_ignore_ascii_case(server_slug))
            .unwrap_or(false)
    })?;

    Some(ServerCapacity {
        id: server.get("id")?.as_str()?.to_string(),
        ram_mb: parse_ram_mb(server.get("ram")),
        cpu_cores: parse_i32(server.get("vcpu")).or_else(|| parse_i32(server.get("cpu"))),
        disk_gb: parse_i32(server.get("disk_size")),
    })
}

#[cfg(test)]
mod tests {
    use super::{resolve_server_capacity, ServerCapacity};
    use serde_json::json;

    #[test]
    fn resolve_server_capacity_maps_standard_server_shape() {
        let payload = json!({
            "_status": "OK",
            "servers": [
                {
                    "id": "cx22",
                    "ram": 4,
                    "vcpu": 2,
                    "disk_size": 40
                }
            ]
        });

        assert_eq!(
            Some(ServerCapacity {
                id: "cx22".to_string(),
                ram_mb: Some(4096),
                cpu_cores: Some(2),
                disk_gb: Some(40),
            }),
            resolve_server_capacity(&payload, "cx22")
        );
    }

    #[test]
    fn resolve_server_capacity_supports_string_numbers() {
        let payload = json!({
            "_status": "OK",
            "servers": [
                {
                    "id": "cpx31",
                    "ram": "8",
                    "vcpu": "4",
                    "disk_size": "160"
                }
            ]
        });

        assert_eq!(
            Some(ServerCapacity {
                id: "cpx31".to_string(),
                ram_mb: Some(8192),
                cpu_cores: Some(4),
                disk_gb: Some(160),
            }),
            resolve_server_capacity(&payload, "cpx31")
        );
    }

    #[test]
    fn resolve_server_capacity_returns_none_when_server_missing() {
        let payload = json!({
            "_status": "OK",
            "servers": [
                { "id": "cx11", "ram": 2, "vcpu": 1, "disk_size": 20 }
            ]
        });

        assert_eq!(None, resolve_server_capacity(&payload, "cx22"));
    }
}
