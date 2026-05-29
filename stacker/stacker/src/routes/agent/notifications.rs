use crate::{helpers, models};
use actix_web::{get, web, Responder, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct NotificationsQuery {
    pub deployment_hash: String,
}

#[derive(Debug, Serialize, Default)]
pub struct NotificationsResponse {
    pub notifications: Vec<serde_json::Value>,
}

#[tracing::instrument(name = "Agent list notifications", skip_all)]
#[get("/notifications")]
pub async fn notifications_handler(
    agent: web::ReqData<Arc<models::Agent>>,
    query: web::Query<NotificationsQuery>,
) -> Result<impl Responder> {
    if agent.deployment_hash != query.deployment_hash {
        return Err(helpers::JsonResponse::forbidden(
            "Not authorized for this deployment",
        ));
    }

    Ok(helpers::JsonResponse::build()
        .set_item(NotificationsResponse::default())
        .ok("Notifications fetched"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_query_carries_deployment_hash() {
        let query = NotificationsQuery {
            deployment_hash: "deployment_123".to_string(),
        };
        assert_eq!(query.deployment_hash, "deployment_123");
    }

    #[test]
    fn notifications_response_defaults_to_empty_list() {
        let response = NotificationsResponse::default();
        assert!(response.notifications.is_empty());
    }
}
