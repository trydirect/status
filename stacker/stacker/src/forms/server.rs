use crate::models;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_valid::Validate;

#[derive(Default, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct ServerForm {
    /// If provided, update this existing server instead of creating new
    pub server_id: Option<i32>,
    /// Reference to the cloud provider (DO, Hetzner, AWS, etc.)
    pub cloud_id: Option<i32>,
    pub region: Option<String>,
    pub zone: Option<String>,
    pub server: Option<String>,
    pub os: Option<String>,
    pub disk_type: Option<String>,
    pub srv_ip: Option<String>,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: Option<i32>,
    pub ssh_user: Option<String>,
    /// Optional friendly name for the server
    pub name: Option<String>,
    /// Connection mode: "ssh" or "password" or "status_panel"
    pub connection_mode: Option<String>,
    /// Path in Vault where SSH key is stored (e.g., "secret/users/{user_id}/servers/{server_id}/ssh")
    pub vault_key_path: Option<String>,
    /// The actual public key content (ed25519 or rsa).
    /// Populated at deploy time so the Install Service can inject it into
    /// `authorized_keys` on the target server without a separate Vault call.
    /// Not persisted to the database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// The actual SSH private key content (PEM).
    /// Populated at deploy time for "own" flow re-deploys so the Install Service
    /// can SSH into the server without relying on a cached file path in Redis.
    /// Not persisted to the database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_private_key: Option<String>,
}

impl std::fmt::Debug for ServerForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerForm")
            .field("server_id", &self.server_id)
            .field("cloud_id", &self.cloud_id)
            .field("region", &self.region)
            .field("zone", &self.zone)
            .field("server", &self.server)
            .field("os", &self.os)
            .field("disk_type", &self.disk_type)
            .field("srv_ip", &self.srv_ip)
            .field("ssh_port", &self.ssh_port)
            .field("ssh_user", &self.ssh_user)
            .field("name", &self.name)
            .field("connection_mode", &self.connection_mode)
            .field("vault_key_path", &self.vault_key_path)
            .field("public_key", &"[REDACTED]")
            .field("ssh_private_key", &"[REDACTED]")
            .finish()
    }
}

pub fn default_ssh_port() -> Option<i32> {
    Some(22)
}

impl From<&ServerForm> for models::Server {
    fn from(val: &ServerForm) -> Self {
        let mut server = models::Server::default();
        server.cloud_id = val.cloud_id;
        server.disk_type = val.disk_type.clone();
        server.region = val.region.clone();
        server.server = val.server.clone();
        server.zone = val.zone.clone();
        server.os = val.os.clone();
        server.created_at = Utc::now();
        server.updated_at = Utc::now();
        server.srv_ip = val.srv_ip.clone();
        server.ssh_port = val.ssh_port.clone().or_else(default_ssh_port);
        server.ssh_user = val.ssh_user.clone();
        server.name = val.name.clone();
        server.connection_mode = val
            .connection_mode
            .clone()
            .unwrap_or_else(|| "ssh".to_string());
        server.vault_key_path = val.vault_key_path.clone();

        server
    }
}

impl Into<ServerForm> for models::Server {
    fn into(self) -> ServerForm {
        let mut form = ServerForm::default();
        form.server_id = Some(self.id);
        form.cloud_id = self.cloud_id;
        form.disk_type = self.disk_type;
        form.region = self.region;
        form.server = self.server;
        form.zone = self.zone;
        form.os = self.os;
        form.srv_ip = self.srv_ip;
        form.ssh_port = self.ssh_port;
        form.ssh_user = self.ssh_user;
        form.name = self.name;
        form.connection_mode = Some(self.connection_mode);
        form.vault_key_path = self.vault_key_path;

        form
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_ssh_port() {
        assert_eq!(default_ssh_port(), Some(22));
    }

    #[test]
    fn test_server_form_to_model() {
        let form = ServerForm {
            server_id: None,
            cloud_id: Some(5),
            region: Some("us-east-1".to_string()),
            zone: Some("us-east-1a".to_string()),
            server: Some("s-2vcpu".to_string()),
            os: Some("ubuntu".to_string()),
            disk_type: Some("ssd".to_string()),
            srv_ip: Some("10.0.0.1".to_string()),
            ssh_port: Some(2222),
            ssh_user: Some("admin".to_string()),
            name: Some("my-server".to_string()),
            connection_mode: Some("ssh".to_string()),
            vault_key_path: Some("/vault/path".to_string()),
            public_key: None,
            ssh_private_key: None,
        };
        let server: models::Server = (&form).into();
        assert_eq!(server.cloud_id, Some(5));
        assert_eq!(server.region, Some("us-east-1".to_string()));
        assert_eq!(server.ssh_port, Some(2222));
        assert_eq!(server.ssh_user, Some("admin".to_string()));
        assert_eq!(server.connection_mode, "ssh");
        assert_eq!(server.name, Some("my-server".to_string()));
    }

    #[test]
    fn test_server_form_to_model_defaults() {
        let form = ServerForm::default();
        let server: models::Server = (&form).into();
        assert_eq!(server.ssh_port, Some(22)); // default_ssh_port fallback
        assert_eq!(server.connection_mode, "ssh");
    }

    #[test]
    fn test_model_to_server_form() {
        let server = models::Server {
            id: 42,
            cloud_id: Some(10),
            region: Some("eu-west-1".to_string()),
            ssh_port: Some(22),
            ssh_user: Some("root".to_string()),
            connection_mode: "ssh".to_string(),
            name: Some("prod".to_string()),
            vault_key_path: Some("/v/k".to_string()),
            ..Default::default()
        };
        let form: ServerForm = server.into();
        assert_eq!(form.server_id, Some(42));
        assert_eq!(form.cloud_id, Some(10));
        assert_eq!(form.region, Some("eu-west-1".to_string()));
        assert_eq!(form.ssh_port, Some(22));
        assert_eq!(form.connection_mode, Some("ssh".to_string()));
        assert_eq!(form.name, Some("prod".to_string()));
    }

    #[test]
    fn test_server_form_roundtrip() {
        let server = models::Server {
            id: 1,
            cloud_id: Some(3),
            region: Some("us-west".to_string()),
            zone: Some("a".to_string()),
            server: Some("large".to_string()),
            os: Some("debian".to_string()),
            disk_type: Some("nvme".to_string()),
            srv_ip: Some("1.2.3.4".to_string()),
            ssh_port: Some(2222),
            ssh_user: Some("deploy".to_string()),
            connection_mode: "ssh".to_string(),
            vault_key_path: Some("path".to_string()),
            name: Some("test".to_string()),
            ..Default::default()
        };
        let form: ServerForm = server.into();
        let back: models::Server = (&form).into();
        assert_eq!(back.cloud_id, Some(3));
        assert_eq!(back.region, Some("us-west".to_string()));
        assert_eq!(back.ssh_port, Some(2222));
    }
}
