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
