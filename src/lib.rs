pub mod agent;
pub mod commands;
pub mod comms;
pub mod connectors;
pub mod monitoring;
pub mod security;
pub mod transport;
pub mod utils;

// Crate version exposed for runtime queries
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
