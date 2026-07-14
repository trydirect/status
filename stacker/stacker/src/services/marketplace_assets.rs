use crate::configuration::MarketplaceAssetSettings;
use crate::models::marketplace::MarketplaceAsset;
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::StatusCode;
use reqwest::Url;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

pub const MARKETPLACE_ASSET_STORAGE_PROVIDER: &str = "hetzner-object-storage";

#[derive(Debug, Clone)]
pub struct MarketplaceAssetUploadRequest {
    pub filename: String,
    pub sha256: String,
    pub size: i64,
    pub content_type: Option<String>,
    pub mount_path: Option<String>,
    pub fetch_target: Option<String>,
    pub decompress: bool,
    pub executable: bool,
    pub immutable: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PresignedMarketplaceAssetResponse {
    pub method: String,
    pub url: String,
    pub expires_in_seconds: i64,
    pub headers: BTreeMap<String, String>,
    pub asset: MarketplaceAsset,
}

#[derive(Debug, Error)]
pub enum MarketplaceAssetStorageError {
    #[error("Marketplace asset storage is not configured")]
    NotConfigured,
    #[error("endpoint_url is not a valid URL")]
    InvalidEndpoint,
    #[error("filename is required")]
    MissingFilename,
    #[error("sha256 is required")]
    MissingChecksum,
    #[error("size must be a positive integer")]
    InvalidSize,
    #[error("unsupported server-side encryption mode: {0}")]
    UnsupportedServerSideEncryption(String),
    #[error("uploaded asset could not be verified in object storage")]
    VerificationFailed,
    #[error("uploaded asset size does not match expected size")]
    SizeMismatch,
}

pub fn build_asset_key(template_id: &Uuid, version: &str, sha256: &str, filename: &str) -> String {
    format!(
        "templates/{}/versions/{}/assets/{}/{}",
        template_id, version, sha256, filename
    )
}

pub fn presign_asset_upload(
    settings: &MarketplaceAssetSettings,
    template_id: &Uuid,
    version: &str,
    request: MarketplaceAssetUploadRequest,
) -> Result<PresignedMarketplaceAssetResponse, MarketplaceAssetStorageError> {
    ensure_storage_configured(settings)?;
    let filename = sanitize_filename(&request.filename)?;
    let sha256 = normalize_non_empty(&request.sha256)
        .ok_or(MarketplaceAssetStorageError::MissingChecksum)?;
    if request.size <= 0 {
        return Err(MarketplaceAssetStorageError::InvalidSize);
    }

    let content_type = request
        .content_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("application/octet-stream")
        .to_string();
    let bucket = settings.active_bucket().to_string();
    let key = build_asset_key(template_id, version, &sha256, &filename);

    let asset = MarketplaceAsset {
        storage_provider: MARKETPLACE_ASSET_STORAGE_PROVIDER.to_string(),
        bucket: bucket.clone(),
        key: key.clone(),
        filename,
        sha256,
        size: request.size,
        content_type: content_type.clone(),
        mount_path: request.mount_path.as_deref().and_then(normalize_non_empty),
        fetch_target: request
            .fetch_target
            .as_deref()
            .and_then(normalize_non_empty),
        decompress: request.decompress,
        executable: request.executable,
        immutable: request.immutable,
    };

    let mut headers = BTreeMap::from([("content-type".to_string(), content_type)]);
    headers.insert("x-amz-meta-sha256".to_string(), request.sha256.clone());
    if let Some(sse) = normalize_server_side_encryption(settings.server_side_encryption.as_deref())?
    {
        headers.insert("x-amz-server-side-encryption".to_string(), sse);
    }

    let url = presign_request(
        settings,
        "PUT",
        &bucket,
        &key,
        settings.presign_put_ttl_secs,
        &headers,
    )?;

    Ok(PresignedMarketplaceAssetResponse {
        method: "PUT".to_string(),
        url,
        expires_in_seconds: settings.presign_put_ttl_secs as i64,
        headers,
        asset,
    })
}

pub fn presign_asset_download(
    settings: &MarketplaceAssetSettings,
    asset: &MarketplaceAsset,
) -> Result<PresignedMarketplaceAssetResponse, MarketplaceAssetStorageError> {
    ensure_storage_configured(settings)?;
    let headers = BTreeMap::new();
    let url = presign_request(
        settings,
        "GET",
        &asset.bucket,
        &asset.key,
        settings.presign_get_ttl_secs,
        &headers,
    )?;

    Ok(PresignedMarketplaceAssetResponse {
        method: "GET".to_string(),
        url,
        expires_in_seconds: settings.presign_get_ttl_secs as i64,
        headers,
        asset: asset.clone(),
    })
}

pub async fn verify_asset_upload(
    settings: &MarketplaceAssetSettings,
    asset: &MarketplaceAsset,
) -> Result<(), MarketplaceAssetStorageError> {
    ensure_storage_configured(settings)?;

    if settings.current_env == "test" {
        return Ok(());
    }

    let url = presign_request(
        settings,
        "HEAD",
        &asset.bucket,
        &asset.key,
        settings.presign_get_ttl_secs,
        &BTreeMap::new(),
    )?;

    let response = reqwest::Client::new()
        .head(url)
        .send()
        .await
        .map_err(|_| MarketplaceAssetStorageError::VerificationFailed)?;

    if response.status() != StatusCode::OK {
        return Err(MarketplaceAssetStorageError::VerificationFailed);
    }

    if let Some(length) = response.content_length() {
        if length as i64 != asset.size {
            return Err(MarketplaceAssetStorageError::SizeMismatch);
        }
    }

    let checksum = response
        .headers()
        .get("x-amz-meta-sha256")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    if checksum != Some(asset.sha256.as_str()) {
        return Err(MarketplaceAssetStorageError::VerificationFailed);
    }

    Ok(())
}

fn presign_request(
    settings: &MarketplaceAssetSettings,
    method: &str,
    bucket: &str,
    key: &str,
    expires_in_seconds: u64,
    headers: &BTreeMap<String, String>,
) -> Result<String, MarketplaceAssetStorageError> {
    let endpoint = Url::parse(&settings.endpoint_url)
        .map_err(|_| MarketplaceAssetStorageError::InvalidEndpoint)?;
    let host = endpoint
        .host_str()
        .ok_or(MarketplaceAssetStorageError::InvalidEndpoint)?;
    let canonical_uri = build_canonical_uri(bucket, key);
    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let short_date = now.format("%Y%m%d").to_string();
    let credential_scope = format!("{}/{}/s3/aws4_request", short_date, settings.region);
    let credential = format!("{}/{}", settings.access_key_id, credential_scope);

    let mut canonical_headers = BTreeMap::from([("host".to_string(), host.to_string())]);
    canonical_headers.extend(headers.clone());
    let signed_headers = canonical_headers
        .keys()
        .map(|key| key.to_lowercase())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers_string = canonical_headers
        .iter()
        .map(|(key, value)| format!("{}:{}\n", key.to_lowercase(), value.trim()))
        .collect::<String>();

    let mut query_params = BTreeMap::from([
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        ("X-Amz-Credential".to_string(), credential),
        ("X-Amz-Date".to_string(), amz_date.clone()),
        ("X-Amz-Expires".to_string(), expires_in_seconds.to_string()),
        ("X-Amz-SignedHeaders".to_string(), signed_headers.clone()),
    ]);
    let canonical_query_string = build_canonical_query_string(&query_params);

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers_string}\n{signed_headers}\nUNSIGNED-PAYLOAD"
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signing_key = build_signing_key(&settings.secret_access_key, &short_date, &settings.region);
    let signature = hmac_hex(&signing_key, string_to_sign.as_bytes());
    query_params.insert("X-Amz-Signature".to_string(), signature);

    let mut final_url = endpoint;
    final_url.set_path(&canonical_uri);
    final_url.set_query(Some(&build_canonical_query_string(&query_params)));

    Ok(final_url.to_string())
}

fn ensure_storage_configured(
    settings: &MarketplaceAssetSettings,
) -> Result<(), MarketplaceAssetStorageError> {
    if settings.is_configured() {
        Ok(())
    } else {
        Err(MarketplaceAssetStorageError::NotConfigured)
    }
}

fn sanitize_filename(filename: &str) -> Result<String, MarketplaceAssetStorageError> {
    let raw = normalize_non_empty(filename).ok_or(MarketplaceAssetStorageError::MissingFilename)?;
    let sanitized = Path::new(&raw)
        .file_name()
        .and_then(|value| value.to_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(MarketplaceAssetStorageError::MissingFilename)?;

    Ok(sanitized.to_string())
}

fn normalize_non_empty(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.to_string())
    }
}

fn normalize_server_side_encryption(
    value: Option<&str>,
) -> Result<Option<String>, MarketplaceAssetStorageError> {
    match value.map(str::trim).filter(|entry| !entry.is_empty()) {
        None => Ok(None),
        Some("AES256") => Ok(Some("AES256".to_string())),
        Some(other) => {
            Err(MarketplaceAssetStorageError::UnsupportedServerSideEncryption(other.to_string()))
        }
    }
}

fn build_canonical_uri(bucket: &str, key: &str) -> String {
    let encoded_bucket = percent_encode(bucket);
    let encoded_key = key
        .split('/')
        .map(percent_encode)
        .collect::<Vec<_>>()
        .join("/");
    format!("/{encoded_bucket}/{encoded_key}")
}

fn build_canonical_query_string(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn build_signing_key(secret_access_key: &str, date: &str, region: &str) -> Vec<u8> {
    let k_date = hmac_bytes(
        format!("AWS4{secret_access_key}").as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac_bytes(&k_date, region.as_bytes());
    let k_service = hmac_bytes(&k_region, b"s3");
    hmac_bytes(&k_service, b"aws4_request")
}

fn hmac_bytes(key: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key should be valid");
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_hex(key: &[u8], payload: &[u8]) -> String {
    hex_encode(&hmac_bytes(key, payload))
}

fn sha256_hex(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        let ch = *byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            encoded.push(ch);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{build_asset_key, presign_asset_upload, MarketplaceAssetUploadRequest};
    use crate::configuration::MarketplaceAssetSettings;
    use uuid::Uuid;

    fn storage_settings() -> MarketplaceAssetSettings {
        MarketplaceAssetSettings {
            enabled: true,
            current_env: "test".to_string(),
            endpoint_url: "https://objects.trydirect.test".to_string(),
            region: "eu-central".to_string(),
            access_key_id: "access".to_string(),
            secret_access_key: "secret".to_string(),
            bucket_dev: "marketplace-assets-dev".to_string(),
            bucket_test: "marketplace-assets-test".to_string(),
            bucket_staging: "marketplace-assets-staging".to_string(),
            bucket_prod: "marketplace-assets-prod".to_string(),
            server_side_encryption: Some("AES256".to_string()),
            presign_put_ttl_secs: 900,
            presign_get_ttl_secs: 300,
        }
    }

    #[test]
    fn build_asset_key_uses_immutable_layout() {
        let template_id = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let key = build_asset_key(&template_id, "1.0.0", "abc12345", "bundle.tgz");

        assert_eq!(
            "templates/11111111-2222-3333-4444-555555555555/versions/1.0.0/assets/abc12345/bundle.tgz",
            key
        );
    }

    #[test]
    fn presign_asset_upload_uses_test_bucket_and_sse_header() {
        let response = presign_asset_upload(
            &storage_settings(),
            &Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap(),
            "1.0.0",
            MarketplaceAssetUploadRequest {
                filename: "bundle.tgz".to_string(),
                sha256: "abc12345".to_string(),
                size: 1024,
                content_type: Some("application/gzip".to_string()),
                mount_path: None,
                fetch_target: Some("/bootstrap/bundle.tgz".to_string()),
                decompress: false,
                executable: false,
                immutable: true,
            },
        )
        .expect("presign should succeed");

        assert_eq!("PUT", response.method);
        assert_eq!("marketplace-assets-test", response.asset.bucket);
        assert_eq!(
            Some(&"AES256".to_string()),
            response.headers.get("x-amz-server-side-encryption")
        );
        assert_eq!(
            Some(&"abc12345".to_string()),
            response.headers.get("x-amz-meta-sha256")
        );
        assert!(
            response.url.contains("X-Amz-Signature="),
            "presigned url should contain a SigV4 signature"
        );
        assert!(response
            .asset
            .key
            .contains("/versions/1.0.0/assets/abc12345/bundle.tgz"));
    }
}
