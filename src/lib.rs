pub mod agent;
pub mod comms;
pub mod security;
pub mod monitoring;
pub mod utils;
pub mod transport;
pub mod commands;

// Crate version exposed for runtime queries
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
