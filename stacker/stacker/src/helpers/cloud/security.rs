use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose, Engine as _};

/// AES-GCM nonce size in bytes (96 bits)
const NONCE_SIZE: usize = 12;

#[derive(Debug, Default, PartialEq, Clone)]
pub struct Secret {
    pub(crate) user_id: String,
    pub(crate) provider: String,
    pub(crate) field: String, // cloud_token/cloud_key/cloud_secret
}

impl Secret {
    pub fn new() -> Self {
        Secret {
            user_id: "".to_string(),
            provider: "".to_string(),
            field: "".to_string(),
        }
    }

    pub fn b64_encode(value: &Vec<u8>) -> String {
        general_purpose::STANDARD.encode(value)
    }

    pub fn b64_decode(value: &String) -> Result<Vec<u8>, String> {
        general_purpose::STANDARD
            .decode(value)
            .map_err(|e| format!("b64_decode error {}", e))
    }

    /// Encrypts a token using AES-256-GCM.
    /// Returns nonce (12 bytes) prepended to ciphertext.
    #[tracing::instrument(name = "encrypt.")]
    pub fn encrypt(&self, token: String) -> Result<Vec<u8>, String> {
        let sec_key = std::env::var("SECURITY_KEY")
            .map_err(|_| "SECURITY_KEY environment variable is not set".to_string())?;

        if sec_key.len() != 32 {
            return Err(format!(
                "SECURITY_KEY must be exactly 32 bytes, got {}",
                sec_key.len()
            ));
        }

        let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(sec_key.as_bytes());
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
                                                           // eprintln!("Nonce bytes {nonce:?}");
                                                           // let nonce_b64: String = general_purpose::STANDARD.encode(nonce);
                                                           // eprintln!("Nonce b64 {nonce_b64:?}");
                                                           // Avoid logging the plaintext token to prevent leaking sensitive data.
                                                           // eprintln!("token {token:?}");
                                                           // Avoid logging the plaintext token to prevent leaking sensitive data.

        let ciphertext = cipher
            .encrypt(&nonce, token.as_ref())
            .map_err(|e| format!("Encryption failed: {:?}", e))?;

        // Prepend nonce to ciphertext: [nonce (12 bytes) || ciphertext]
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(nonce.as_slice());
        result.extend_from_slice(&ciphertext);

        tracing::debug!(
            "Encrypted {} for {}/{}: {} bytes",
            self.field,
            self.user_id,
            self.provider,
            result.len()
        );

        Ok(result)
    }

    /// Decrypts data that has nonce prepended (first 12 bytes).
    #[tracing::instrument(name = "decrypt.")]
    pub fn decrypt(&mut self, encrypted_data: Vec<u8>) -> Result<String, String> {
        if encrypted_data.len() < NONCE_SIZE {
            return Err(format!(
                "Encrypted data too short: {} bytes, need at least {}",
                encrypted_data.len(),
                NONCE_SIZE
            ));
        }

        let sec_key = std::env::var("SECURITY_KEY")
            .map_err(|_| "SECURITY_KEY environment variable is not set".to_string())?;

        if sec_key.len() != 32 {
            return Err(format!(
                "SECURITY_KEY must be exactly 32 bytes, got {}",
                sec_key.len()
            ));
        }

        let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(sec_key.as_bytes());

        // Extract nonce (first 12 bytes) and ciphertext (rest)
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        tracing::debug!(
            "Decrypting {} for {}/{}: {} bytes ciphertext",
            self.field,
            self.user_id,
            self.provider,
            ciphertext.len()
        );

        let cipher = Aes256Gcm::new(key);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {:?}", e))?;

        String::from_utf8(plaintext).map_err(|e| format!("UTF-8 conversion failed: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    const TEST_KEY: &str = "01234567890123456789012345678901";

    #[test]
    fn test_secret_new() {
        let secret = Secret::new();
        assert_eq!(secret.user_id, "");
        assert_eq!(secret.provider, "");
        assert_eq!(secret.field, "");
    }

    #[test]
    fn test_b64_encode() {
        let data = vec![72, 101, 108, 108, 111]; // "Hello"
        let encoded = Secret::b64_encode(&data);
        assert_eq!(encoded, "SGVsbG8=");
    }

    #[test]
    fn test_b64_decode_valid() {
        let result = Secret::b64_decode(&"SGVsbG8=".to_string());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![72, 101, 108, 108, 111]);
    }

    #[test]
    fn test_b64_decode_invalid() {
        let result = Secret::b64_decode(&"not!valid!base64!!!".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_b64_roundtrip() {
        let original = vec![1, 2, 3, 4, 5, 255, 0, 128];
        let encoded = Secret::b64_encode(&original);
        let decoded = Secret::b64_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_b64_encode_empty() {
        let data: Vec<u8> = vec![];
        let encoded = Secret::b64_encode(&data);
        assert_eq!(encoded, "");
    }

    #[test]
    fn test_b64_decode_empty() {
        let result = Secret::b64_decode(&"".to_string());
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_encrypt_requires_security_key() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("SECURITY_KEY");
        let secret = Secret {
            user_id: "u1".to_string(),
            provider: "aws".to_string(),
            field: "cloud_token".to_string(),
        };
        let result = secret.encrypt("my-token".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SECURITY_KEY"));
    }

    #[test]
    fn test_encrypt_invalid_key_length() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("SECURITY_KEY", "short-key");
        let secret = Secret {
            user_id: "u1".to_string(),
            provider: "aws".to_string(),
            field: "cloud_token".to_string(),
        };
        let result = secret.encrypt("my-token".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("32 bytes"));
        std::env::remove_var("SECURITY_KEY");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("SECURITY_KEY", TEST_KEY);

        let mut secret = Secret {
            user_id: "u1".to_string(),
            provider: "aws".to_string(),
            field: "cloud_token".to_string(),
        };

        let original = "my-super-secret-token-123";
        let encrypted = secret.encrypt(original.to_string()).unwrap();
        assert!(!encrypted.is_empty());
        assert!(encrypted.len() > 12); // nonce (12) + ciphertext

        let decrypted = secret.decrypt(encrypted).unwrap();
        assert_eq!(decrypted, original);

        std::env::remove_var("SECURITY_KEY");
    }

    #[test]
    fn test_decrypt_too_short_data() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("SECURITY_KEY", TEST_KEY);
        let mut secret = Secret::new();
        let result = secret.decrypt(vec![1, 2, 3]); // less than 12 bytes
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
        std::env::remove_var("SECURITY_KEY");
    }
}
