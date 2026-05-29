use reqwest::{Client, Response};

/// AgentClient for agent-initiated connections only.
///
/// In the pull-only architecture, agents poll Stacker (not the other way around).
/// This client is kept for potential Compose Agent sidecar use cases where
/// Stacker may need to communicate with a local control plane.
pub struct AgentClient {
    http: Client,
    base_url: String,
    agent_id: String,
    agent_token: String,
}

impl AgentClient {
    pub fn new<S1: Into<String>, S2: Into<String>, S3: Into<String>>(
        base_url: S1,
        agent_id: S2,
        agent_token: S3,
    ) -> Self {
        Self {
            http: Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            agent_id: agent_id.into(),
            agent_token: agent_token.into(),
        }
    }

    /// GET request with agent auth headers (for Compose Agent sidecar path only)
    pub async fn get(&self, path: &str) -> Result<Response, reqwest::Error> {
        let url = format!(
            "{}{}{}",
            self.base_url,
            if path.starts_with('/') { "" } else { "/" },
            path
        );
        self.http
            .get(url)
            .header("X-Agent-Id", &self.agent_id)
            .header("Authorization", format!("Bearer {}", self.agent_token))
            .send()
            .await
    }
}
