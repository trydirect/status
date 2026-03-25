use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use base64::{engine::general_purpose, Engine};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

// HMAC-SHA256(request_body, AGENT_TOKEN) → X-Agent-Signature (base64)

type HmacSha256 = Hmac<Sha256>;

pub fn compute_signature_base64(key: &str, body: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(body);
    let sig = mac.finalize().into_bytes();
    general_purpose::STANDARD.encode(sig)
}

fn decode_signature(sig: &str) -> Result<Vec<u8>> {
    // Prefer base64; if it fails, try hex as a fallback
    if let Ok(bytes) = general_purpose::STANDARD.decode(sig) {
        return Ok(bytes);
    }
    // hex fallback
    fn from_hex(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        for i in (0..s.len()).step_by(2) {
            let hi = (bytes[i] as char).to_digit(16)? as u8;
            let lo = (bytes[i + 1] as char).to_digit(16)? as u8;
            out.push((hi << 4) | lo);
        }
        Some(out)
    }
    from_hex(sig).ok_or_else(|| anyhow!("invalid signature encoding"))
}

pub fn verify_signature(
    headers: &HeaderMap,
    body: &[u8],
    key: &str,
    max_skew_secs: i64,
) -> Result<()> {
    // Require timestamp freshness
    let ts = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("missing X-Timestamp"))?;
    let ts_val: i64 = ts.parse().map_err(|_| anyhow!("invalid X-Timestamp"))?;
    let now = Utc::now().timestamp();
    let skew = (now - ts_val).abs();
    if skew > max_skew_secs {
        return Err(anyhow!("stale request (timestamp skew)"));
    }

    // Require signature header
    let sig_hdr = headers
        .get("X-Agent-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("missing X-Agent-Signature"))?;
    let provided = decode_signature(sig_hdr)?;

    // Compute expected
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| anyhow!("invalid hmac key"))?;
    mac.update(body);
    let expected = mac.finalize().into_bytes();

    if provided.ct_eq(expected.as_slice()).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(anyhow!("signature mismatch"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_signature_deterministic() {
        let sig1 = compute_signature_base64("secret", b"hello");
        let sig2 = compute_signature_base64("secret", b"hello");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn compute_signature_different_keys() {
        let sig1 = compute_signature_base64("key1", b"body");
        let sig2 = compute_signature_base64("key2", b"body");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn compute_signature_different_bodies() {
        let sig1 = compute_signature_base64("key", b"body1");
        let sig2 = compute_signature_base64("key", b"body2");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn compute_signature_empty_body() {
        let sig = compute_signature_base64("key", b"");
        assert!(!sig.is_empty());
        // Verify it's valid base64
        assert!(general_purpose::STANDARD.decode(&sig).is_ok());
    }

    #[test]
    fn decode_signature_base64() {
        let original = b"test data for signature";
        let encoded = general_purpose::STANDARD.encode(original);
        let decoded = decode_signature(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_signature_hex_fallback() {
        // "hello" in hex
        let decoded = decode_signature("68656c6c6f").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn decode_signature_hex_uppercase() {
        let decoded = decode_signature("48454C4C4F").unwrap();
        assert_eq!(decoded, b"HELLO");
    }

    #[test]
    fn decode_signature_invalid_encoding() {
        // Odd-length string that's not valid base64 and not valid hex
        let result = decode_signature("xyz");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid signature encoding"));
    }

    #[test]
    fn verify_signature_valid() {
        let key = "test-secret";
        let body = b"request body";
        let sig = compute_signature_base64(key, body);
        let ts = Utc::now().timestamp().to_string();

        let mut headers = HeaderMap::new();
        headers.insert("X-Timestamp", ts.parse().unwrap());
        headers.insert("X-Agent-Signature", sig.parse().unwrap());

        assert!(verify_signature(&headers, body, key, 60).is_ok());
    }

    #[test]
    fn verify_signature_missing_timestamp() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Agent-Signature", "sig".parse().unwrap());

        let result = verify_signature(&headers, b"body", "key", 60);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("missing X-Timestamp"));
    }

    #[test]
    fn verify_signature_invalid_timestamp() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Timestamp", "not-a-number".parse().unwrap());
        headers.insert("X-Agent-Signature", "sig".parse().unwrap());

        let result = verify_signature(&headers, b"body", "key", 60);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid X-Timestamp"));
    }

    #[test]
    fn verify_signature_stale_timestamp() {
        let key = "test-secret";
        let body = b"body";
        let sig = compute_signature_base64(key, body);
        let old_ts = (Utc::now().timestamp() - 120).to_string();

        let mut headers = HeaderMap::new();
        headers.insert("X-Timestamp", old_ts.parse().unwrap());
        headers.insert("X-Agent-Signature", sig.parse().unwrap());

        let result = verify_signature(&headers, body, key, 60);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("stale request"));
    }

    #[test]
    fn verify_signature_missing_signature_header() {
        let ts = Utc::now().timestamp().to_string();
        let mut headers = HeaderMap::new();
        headers.insert("X-Timestamp", ts.parse().unwrap());

        let result = verify_signature(&headers, b"body", "key", 60);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("missing X-Agent-Signature"));
    }

    #[test]
    fn verify_signature_wrong_key() {
        let body = b"body";
        let sig = compute_signature_base64("correct-key", body);
        let ts = Utc::now().timestamp().to_string();

        let mut headers = HeaderMap::new();
        headers.insert("X-Timestamp", ts.parse().unwrap());
        headers.insert("X-Agent-Signature", sig.parse().unwrap());

        let result = verify_signature(&headers, body, "wrong-key", 60);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("signature mismatch"));
    }

    #[test]
    fn verify_signature_tampered_body() {
        let key = "test-secret";
        let body = b"original body";
        let sig = compute_signature_base64(key, body);
        let ts = Utc::now().timestamp().to_string();

        let mut headers = HeaderMap::new();
        headers.insert("X-Timestamp", ts.parse().unwrap());
        headers.insert("X-Agent-Signature", sig.parse().unwrap());

        // Verify with a different body
        let result = verify_signature(&headers, b"tampered body", key, 60);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("signature mismatch"));
    }

    #[test]
    fn verify_signature_large_skew_allowed() {
        let key = "test-secret";
        let body = b"body";
        let sig = compute_signature_base64(key, body);
        // Timestamp 30 seconds in the past
        let ts = (Utc::now().timestamp() - 30).to_string();

        let mut headers = HeaderMap::new();
        headers.insert("X-Timestamp", ts.parse().unwrap());
        headers.insert("X-Agent-Signature", sig.parse().unwrap());

        // 60 second skew allows 30 second old request
        assert!(verify_signature(&headers, body, key, 60).is_ok());
    }
}
