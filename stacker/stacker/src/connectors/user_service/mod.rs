pub mod app;
pub mod category_sync;
pub mod client;
pub mod connector;
pub mod deployment_resolver;
pub mod deployment_validator;
pub mod init;
pub mod install;
pub mod marketplace_search;
pub mod marketplace_webhook;
pub mod mock;
pub mod notifications;
pub mod plan;
pub mod profile;
pub mod stack;
pub mod types;
pub mod utils;

pub use category_sync::sync_categories_from_user_service;
pub use client::UserServiceClient;
pub use connector::UserServiceConnector;
pub use deployment_resolver::{ResolvedDeploymentInfo, UserServiceDeploymentResolver};
pub use deployment_validator::{DeploymentValidationError, DeploymentValidator};
pub use init::init;
pub use marketplace_webhook::{
    MarketplaceWebhookPayload, MarketplaceWebhookSender, WebhookResponse, WebhookSenderConfig,
};
pub use mock::MockUserServiceConnector;
pub use types::{
    CategoryInfo, PlanDefinition, ProductInfo, StackResponse, UserPlanInfo, UserProduct,
    UserProfile,
};

#[cfg(test)]
mod tests;
