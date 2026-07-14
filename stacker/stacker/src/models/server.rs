use chrono::{DateTime, Utc};
use serde_derive::{Deserialize, Serialize};
use serde_valid::Validate;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct Server {
    pub id: i32,
    pub user_id: String,
    pub project_id: i32,
    /// Reference to the cloud provider (DO, Hetzner, AWS, etc.)
    pub cloud_id: Option<i32>,
    #[validate(min_length = 2)]
    #[validate(max_length = 50)]
    pub region: Option<String>,
    #[validate(min_length = 2)]
    #[validate(max_length = 50)]
    pub zone: Option<String>,
    #[validate(min_length = 2)]
    #[validate(max_length = 50)]
    pub server: Option<String>,
    #[validate(min_length = 2)]
    #[validate(max_length = 50)]
    pub os: Option<String>,
    #[validate(min_length = 3)]
    #[validate(max_length = 50)]
    pub disk_type: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[validate(min_length = 8)]
    #[validate(max_length = 50)]
    pub srv_ip: Option<String>,
    #[validate(minimum = 20)]
    #[validate(maximum = 65535)]
    pub ssh_port: Option<i32>,
    #[validate(min_length = 3)]
    #[validate(max_length = 50)]
    pub ssh_user: Option<String>,
    /// Path in Vault where SSH key is stored (e.g., "users/{user_id}/servers/{server_id}/ssh")
    pub vault_key_path: Option<String>,
    /// Connection mode: "ssh" (default) or "password"
    #[serde(default = "default_connection_mode")]
    pub connection_mode: String,
    /// SSH key status: "none", "pending", "active", "failed"
    #[serde(default = "default_key_status")]
    pub key_status: String,
    /// Optional friendly name for the server
    #[validate(max_length = 100)]
    pub name: Option<String>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            id: 0,
            user_id: String::new(),
            project_id: 0,
            cloud_id: None,
            region: None,
            zone: None,
            server: None,
            os: None,
            disk_type: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            srv_ip: None,
            ssh_port: None,
            ssh_user: None,
            vault_key_path: None,
            connection_mode: default_connection_mode(),
            key_status: default_key_status(),
            name: None,
        }
    }
}

fn default_connection_mode() -> String {
    "ssh".to_string()
}

fn default_key_status() -> String {
    "none".to_string()
}

/// Server with provider information for API responses
/// Used when we need to show the cloud provider name alongside server data
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerWithProvider {
    pub id: i32,
    pub user_id: String,
    pub project_id: i32,
    pub cloud_id: Option<i32>,
    /// Cloud provider name (e.g., "digital_ocean", "hetzner", "aws")
    pub cloud: Option<String>,
    pub region: Option<String>,
    pub zone: Option<String>,
    pub server: Option<String>,
    pub os: Option<String>,
    pub disk_type: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub srv_ip: Option<String>,
    pub ssh_port: Option<i32>,
    pub ssh_user: Option<String>,
    pub vault_key_path: Option<String>,
    pub connection_mode: String,
    pub key_status: String,
    pub name: Option<String>,
}

impl From<Server> for ServerWithProvider {
    fn from(server: Server) -> Self {
        Self {
            id: server.id,
            user_id: server.user_id,
            project_id: server.project_id,
            cloud_id: server.cloud_id,
            cloud: None, // Will be populated by the query
            region: server.region,
            zone: server.zone,
            server: server.server,
            os: server.os,
            disk_type: server.disk_type,
            created_at: server.created_at,
            updated_at: server.updated_at,
            srv_ip: server.srv_ip,
            ssh_port: server.ssh_port,
            ssh_user: server.ssh_user,
            vault_key_path: server.vault_key_path,
            connection_mode: server.connection_mode,
            key_status: server.key_status,
            name: server.name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_valid::Validate;

    #[test]
    fn test_server_default() {
        let server = Server::default();
        assert_eq!(server.id, 0);
        assert_eq!(server.connection_mode, "ssh");
        assert_eq!(server.key_status, "none");
        assert!(server.region.is_none());
        assert!(server.ssh_port.is_none());
    }

    #[test]
    fn test_default_connection_mode() {
        assert_eq!(default_connection_mode(), "ssh");
    }

    #[test]
    fn test_default_key_status() {
        assert_eq!(default_key_status(), "none");
    }

    #[test]
    fn test_server_validation_valid() {
        let server = Server {
            region: Some("us-east-1".to_string()),
            zone: Some("us-east-1a".to_string()),
            server: Some("s-2vcpu-4gb".to_string()),
            os: Some("ubuntu-22".to_string()),
            disk_type: Some("ssd".to_string()),
            srv_ip: Some("192.168.1.100".to_string()),
            ssh_port: Some(22),
            ssh_user: Some("root".to_string()),
            ..Default::default()
        };
        assert!(server.validate().is_ok());
    }

    #[test]
    fn test_server_validation_short_region() {
        let server = Server {
            region: Some("a".to_string()), // too short, min 2
            ..Default::default()
        };
        assert!(server.validate().is_err());
    }

    #[test]
    fn test_server_validation_ssh_port_too_low() {
        let server = Server {
            ssh_port: Some(10), // minimum 20
            ..Default::default()
        };
        assert!(server.validate().is_err());
    }

    #[test]
    fn test_server_validation_ssh_port_too_high() {
        let server = Server {
            ssh_port: Some(70000), // maximum 65535
            ..Default::default()
        };
        assert!(server.validate().is_err());
    }

    #[test]
    fn test_server_validation_ssh_port_valid_range() {
        let server = Server {
            ssh_port: Some(22),
            ..Default::default()
        };
        assert!(server.validate().is_ok());

        let server_max = Server {
            ssh_port: Some(65535),
            ..Default::default()
        };
        assert!(server_max.validate().is_ok());
    }

    #[test]
    fn test_server_to_server_with_provider() {
        let server = Server {
            id: 42,
            user_id: "user1".to_string(),
            project_id: 5,
            cloud_id: Some(10),
            region: Some("eu-west-1".to_string()),
            connection_mode: "ssh".to_string(),
            key_status: "active".to_string(),
            name: Some("my-server".to_string()),
            ..Default::default()
        };
        let provider: ServerWithProvider = server.into();
        assert_eq!(provider.id, 42);
        assert_eq!(provider.user_id, "user1");
        assert_eq!(provider.project_id, 5);
        assert_eq!(provider.cloud_id, Some(10));
        assert!(provider.cloud.is_none()); // Populated by query later
        assert_eq!(provider.region, Some("eu-west-1".to_string()));
        assert_eq!(provider.connection_mode, "ssh");
        assert_eq!(provider.key_status, "active");
        assert_eq!(provider.name, Some("my-server".to_string()));
    }

    #[test]
    fn test_server_serialization_defaults() {
        let json = r#"{"id":0,"user_id":"","project_id":0,"cloud_id":null,"region":null,"zone":null,"server":null,"os":null,"disk_type":null,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","srv_ip":null,"ssh_port":null,"ssh_user":null,"vault_key_path":null,"connection_mode":"ssh","key_status":"none","name":null}"#;
        let server: Server = serde_json::from_str(json).unwrap();
        assert_eq!(server.connection_mode, "ssh");
        assert_eq!(server.key_status, "none");
    }
}
