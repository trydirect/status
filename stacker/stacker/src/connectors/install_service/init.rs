use actix_web::web;
use std::sync::Arc;

use crate::connectors::config::ConnectorConfig;

use super::{InstallServiceClient, InstallServiceConnector, MockInstallServiceConnector};

pub fn init(connector_config: &ConnectorConfig) -> web::Data<Arc<dyn InstallServiceConnector>> {
    let connector: Arc<dyn InstallServiceConnector> = if connector_config
        .install_service
        .as_ref()
        .map(|cfg| cfg.enabled)
        .unwrap_or(true)
    {
        Arc::new(InstallServiceClient)
    } else {
        tracing::warn!("Install Service connector disabled - using mock");
        Arc::new(MockInstallServiceConnector)
    };

    web::Data::new(connector)
}
