use crate::connectors::errors::ConnectorError;

use super::UserProfile;
use super::UserServiceClient;

impl UserServiceClient {
    /// Get current user profile
    pub async fn get_user_profile(
        &self,
        bearer_token: &str,
    ) -> Result<UserProfile, ConnectorError> {
        let url = format!("{}/auth/me", self.base_url);

        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", bearer_token))
            .send()
            .await
            .map_err(ConnectorError::from)?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::HttpError(format!(
                "User Service error ({}): {}",
                status, body
            )));
        }

        response
            .json::<UserProfile>()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))
    }
}
