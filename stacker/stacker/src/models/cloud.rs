use chrono::{DateTime, Utc};
use serde_derive::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Cloud {
    pub id: i32,
    pub user_id: String,
    pub name: String,
    pub provider: String,
    pub cloud_token: Option<String>,
    pub cloud_key: Option<String>,
    pub cloud_secret: Option<String>,
    pub save_token: Option<bool>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl std::fmt::Debug for Cloud {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cloud")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("name", &self.name)
            .field("provider", &self.provider)
            .field("cloud_token", &"[REDACTED]")
            .field("cloud_key", &"[REDACTED]")
            .field("cloud_secret", &"[REDACTED]")
            .field("save_token", &self.save_token)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

fn mask_string(s: Option<&String>) -> String {
    match s {
        Some(val) => val.chars().take(4).collect::<String>() + "****",
        None => "".to_string(),
    }
}

impl std::fmt::Display for Cloud {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cloud_key = mask_string(self.cloud_key.as_ref());
        let cloud_token = mask_string(self.cloud_token.as_ref());
        let cloud_secret = mask_string(self.cloud_secret.as_ref());

        write!(
            f,
            "{} cloud creds: cloud_key : {} cloud_token: {} cloud_secret: {}",
            self.provider, cloud_key, cloud_token, cloud_secret,
        )
    }
}

impl Cloud {
    pub fn new(
        user_id: String,
        name: String,
        provider: String,
        cloud_token: Option<String>,
        cloud_key: Option<String>,
        cloud_secret: Option<String>,
        save_token: Option<bool>,
    ) -> Self {
        Self {
            id: 0,
            user_id,
            name,
            provider,
            cloud_token,
            cloud_key,
            cloud_secret,
            save_token,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

impl Default for Cloud {
    fn default() -> Self {
        Cloud {
            id: 0,
            name: "".to_string(),
            provider: "".to_string(),
            user_id: "".to_string(),
            cloud_key: Default::default(),
            cloud_token: Default::default(),
            cloud_secret: Default::default(),
            save_token: Some(false),
            created_at: Default::default(),
            updated_at: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_string_some() {
        assert_eq!(mask_string(Some(&"abcdefgh".to_string())), "abcd****");
    }

    #[test]
    fn test_mask_string_short() {
        assert_eq!(mask_string(Some(&"ab".to_string())), "ab****");
    }

    #[test]
    fn test_mask_string_none() {
        assert_eq!(mask_string(None), "");
    }

    #[test]
    fn test_mask_string_empty() {
        assert_eq!(mask_string(Some(&"".to_string())), "****");
    }

    #[test]
    fn test_cloud_display_masks_credentials() {
        let cloud = Cloud::new(
            "user1".to_string(),
            "my-cloud".to_string(),
            "aws".to_string(),
            Some("token12345".to_string()),
            Some("key12345".to_string()),
            Some("secret12345".to_string()),
            Some(true),
        );
        let display = format!("{}", cloud);
        assert!(display.contains("aws"));
        assert!(display.contains("toke****"));
        assert!(display.contains("key1****"));
        assert!(display.contains("secr****"));
        assert!(!display.contains("token12345"));
        assert!(!display.contains("key12345"));
        assert!(!display.contains("secret12345"));
    }

    #[test]
    fn test_cloud_display_none_credentials() {
        let cloud = Cloud::default();
        let display = format!("{}", cloud);
        assert!(display.contains("cloud_key : "));
    }

    #[test]
    fn test_cloud_new() {
        let cloud = Cloud::new(
            "user1".to_string(),
            "test".to_string(),
            "hetzner".to_string(),
            None,
            Some("key".to_string()),
            None,
            Some(false),
        );
        assert_eq!(cloud.id, 0);
        assert_eq!(cloud.user_id, "user1");
        assert_eq!(cloud.provider, "hetzner");
        assert!(cloud.cloud_token.is_none());
        assert_eq!(cloud.cloud_key, Some("key".to_string()));
        assert!(cloud.cloud_secret.is_none());
    }

    #[test]
    fn test_cloud_default() {
        let cloud = Cloud::default();
        assert_eq!(cloud.id, 0);
        assert_eq!(cloud.provider, "");
        assert_eq!(cloud.save_token, Some(false));
    }

    #[test]
    fn test_cloud_serialization() {
        let cloud = Cloud::new(
            "u1".to_string(),
            "c".to_string(),
            "do".to_string(),
            Some("tok".to_string()),
            None,
            None,
            None,
        );
        let json = serde_json::to_string(&cloud).unwrap();
        let deserialized: Cloud = serde_json::from_str(&json).unwrap();
        assert_eq!(cloud, deserialized);
    }
}
