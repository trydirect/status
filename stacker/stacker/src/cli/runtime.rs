//! Shared CLI runtime — eliminates boilerplate repeated across every CLI command.
//!
//! Every CLI command needs: load credentials → build tokio runtime → create
//! `StackerClient`. This module wraps that into a single `CliRuntime` struct
//! so each command is ~3 lines instead of ~15.

use crate::cli::credentials::{CredentialsManager, FileCredentialStore, StoredCredentials};
use crate::cli::error::CliError;
use crate::cli::stacker_client::StackerClient;

/// Pre-built CLI execution context: credentials + async runtime + HTTP client.
///
/// # Example
/// ```ignore
/// let ctx = CliRuntime::new("agent health")?;
/// ctx.block_on(async {
///     let result = ctx.client.list_projects().await?;
///     Ok(())
/// })
/// ```
pub struct CliRuntime {
    pub creds: StoredCredentials,
    pub client: StackerClient,
    rt: tokio::runtime::Runtime,
}

impl CliRuntime {
    /// Build a runtime for the given feature name (used in login-required messages).
    pub fn new(feature: &str) -> Result<Self, CliError> {
        let cred_manager = CredentialsManager::<FileCredentialStore>::with_default_store();
        let creds = cred_manager.require_valid_token(feature)?;
        let env_server_url = std::env::var("STACKER_URL").ok();
        let base_url = creds
            .server_url
            .as_deref()
            .or(env_server_url.as_deref())
            .map(crate::cli::install_runner::normalize_stacker_server_url)
            .ok_or_else(|| {
                CliError::ConfigValidation(
                    "No Stacker API URL configured. Re-run `stacker login --auth-url <user-service-url> --server-url <stacker-api-url>` or set STACKER_URL.".to_string(),
                )
            })?;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                CliError::ConfigValidation(format!("Failed to create async runtime: {}", e))
            })?;

        let client = StackerClient::new(&base_url, &creds.access_token);

        Ok(Self { creds, client, rt })
    }

    /// Run an async closure on the single-threaded tokio runtime.
    pub fn block_on<F, T>(&self, future: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        self.rt.block_on(future)
    }
}
