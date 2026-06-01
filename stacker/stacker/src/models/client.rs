use serde::Serialize;

#[derive(Default, Serialize)]
pub struct Client {
    pub id: i32,
    pub user_id: String,
    pub secret: Option<String>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let secret: String = match self.secret.as_ref() {
            Some(val) => val.chars().take(4).collect::<String>() + "****",
            None => "".to_string(),
        };

        write!(
            f,
            "Client {{id: {:?}, user_id: {:?}, secret: {}}}",
            self.id, self.user_id, secret
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_debug_masks_secret() {
        let client = Client {
            id: 1,
            user_id: "user1".to_string(),
            secret: Some("mysecretvalue".to_string()),
        };
        let debug = format!("{:?}", client);
        assert!(debug.contains("myse****"));
        assert!(!debug.contains("mysecretvalue"));
        assert!(debug.contains("user1"));
    }

    #[test]
    fn test_client_debug_no_secret() {
        let client = Client {
            id: 2,
            user_id: "user2".to_string(),
            secret: None,
        };
        let debug = format!("{:?}", client);
        assert!(debug.contains("user2"));
    }

    #[test]
    fn test_client_debug_short_secret() {
        let client = Client {
            id: 3,
            user_id: "u".to_string(),
            secret: Some("ab".to_string()),
        };
        let debug = format!("{:?}", client);
        assert!(debug.contains("ab****"));
    }

    #[test]
    fn test_client_default() {
        let client = Client::default();
        assert_eq!(client.id, 0);
        assert_eq!(client.user_id, "");
        assert!(client.secret.is_none());
    }
}
