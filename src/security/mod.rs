pub mod auth;

// @todo crypto operations, keys, validation per GOAL.md
pub mod audit_log;
pub mod rate_limit;
pub mod replay;
pub mod request_signer;
pub mod scopes;

// Vault integration for token rotation
pub mod token_cache;
pub mod token_refresh;
pub mod vault_client;
