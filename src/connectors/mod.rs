//! Connectors for external services
//!
//! This module contains API clients and integrations for external services
//! that Status Panel can interact with (nginx proxy manager, etc.)

pub mod npm;

pub use npm::NpmClient;
