//! Native `backup` command (WS-1): run a dump/restore process and stream the
//! archive to a pluggable backup-storage backend over HTTP.
//!
//! Contract (source of truth):
//! `config/shared-fixtures/api-contracts/backups-storage.json` (`BackupCommand`,
//! `DumpPlan`, `RestorePlan`, `UploadBody`, `Auth`, `UploadTarget`,
//! `DownloadTarget`) — the same wire format the Stacker `backup-core` crate
//! serializes. The plan is pure data queued through the command queue; this
//! module interprets it generically: no vendor-specific storage logic, no
//! shell strings, no embedded credentials.
//!
//! Security invariants (FEATURES.md):
//! - `$ENV` resolution is allowlisted: `AGENT_ID`, `BACKUP_*`, the env-var
//!   *names* referenced by the plan's own `Auth` block, and the agent-generated
//!   `$BACKUP_FILENAME`. Any other `$VAR` in a resolved value fails the
//!   command — the plan is queue data and unrestricted `$ENV` resolution is an
//!   exfiltration channel.
//! - Only header values and multipart field values are env-resolved. `argv` is
//!   never resolved: plans legitimately embed container-side scripts such as
//!   `pg_dump -Fc "$POSTGRES_DB"` (see `backup-core` `container_script`).
//! - Header names/values containing CR/LF are rejected (header injection).
//! - `$AGENT_ID` is the registered `agent_id` (`AGENT_ID` env, set at
//!   registration) — never `deployment_hash`.
//! - Errors are redacted through [`crate::commands::stacker::redact_message`];
//!   resolved credentials only ever go into request headers/tokens.
//! - `argv` runs directly via `tokio::process` — never through a host shell.

use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use chrono::Utc;
use futures_util::Stream;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStderr, Command};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout as tokio_timeout, Duration};
use tracing::{debug, info, warn};

use crate::commands::stacker::{base_result, redact_message};
use crate::transport::{Command as AgentCommand, CommandError, CommandResult};

/// Cap for captured child stderr (diagnostics only; shown redacted on failure).
const STDERR_CAP_BYTES: usize = 8 * 1024;
/// Cap for upload response bodies read back (metadata such as `file_id`).
const RESPONSE_CAP_BYTES: usize = 64 * 1024;
/// Grace period between SIGTERM and SIGKILL when terminating a child
/// (executor.rs parity).
const TERMINATE_GRACE_SECS: u64 = 5;
/// Default per-command execution deadline when no `timeout` is provided and
/// `COMMAND_TIMEOUT_SECS` is unset. Backups stream many GB, so this is much
/// larger than the daemon's shell-command default.
const DEFAULT_BACKUP_TIMEOUT_SECS: u64 = 3600;
/// Upper bound for the execution deadline.
const MAX_BACKUP_TIMEOUT_SECS: u64 = 86_400;

// ---------------------------------------------------------------------------
// Wire types (mirror crates/backup-core; see the contract for semantics)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackupAction {
    Dump,
    Restore,
}

impl BackupAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            BackupAction::Dump => "dump",
            BackupAction::Restore => "restore",
        }
    }
}

/// A literal form field; `value` may reference an env var (`$AGENT_ID`, ...).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FormField {
    pub name: String,
    pub value: String,
}

/// How the archive is encoded into the upload request body.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UploadBody {
    /// The archive stream is the request body.
    Raw,
    /// `multipart/form-data`: the archive rides in `file_field`, plus literal
    /// form fields (values may reference environment variables).
    Multipart {
        file_field: String,
        fields: Vec<FormField>,
    },
}

/// How a request is authenticated. Every credential is referenced by env-var
/// *name* — never carried as a value in the plan.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Auth {
    /// No authentication.
    None,
    /// `Authorization: Bearer <value of $token_env>`.
    Bearer { token_env: String },
    /// OAuth2 client_credentials: POST `token_url` → `access_token` → Bearer.
    ClientCredentials {
        token_url: String,
        client_id_env: String,
        client_secret_env: String,
        #[serde(default)]
        scope: Option<String>,
    },
    /// HTTP Basic from env.
    Basic {
        username_env: String,
        password_env: String,
    },
}

impl Auth {
    /// Env-var names this auth block references. They form part of the
    /// `$ENV` allowlist (FEATURES.md §3) and resolve at run time.
    fn env_names(&self) -> Vec<&str> {
        match self {
            Auth::None => Vec::new(),
            Auth::Bearer { token_env } => vec![token_env.as_str()],
            Auth::ClientCredentials {
                client_id_env,
                client_secret_env,
                ..
            } => vec![client_id_env.as_str(), client_secret_env.as_str()],
            Auth::Basic {
                username_env,
                password_env,
            } => vec![username_env.as_str(), password_env.as_str()],
        }
    }
}

/// The upload leg of a storage backend: where to POST the archive and how.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UploadTarget {
    /// Full upload URL.
    pub url: String,
    pub body: UploadBody,
    pub auth: Auth,
    /// Extra headers; values may reference env vars.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

/// The download leg (restore): where to GET a stored archive and how.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DownloadTarget {
    /// Full file URL (the caller embeds the remote file id).
    pub url: String,
    pub auth: Auth,
    /// Extra headers; values may reference env vars.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

/// Typed execution plan for a dump: run `argv`, stream stdout to `upload`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DumpPlan {
    pub argv: Vec<String>,
    pub upload: UploadTarget,
}

/// Typed execution plan for a restore: stream `download` into stdin of `argv`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RestorePlan {
    pub argv: Vec<String>,
    pub download: DownloadTarget,
}

/// `plan` of a `backup` command, selected by `action`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupPlan {
    Dump(DumpPlan),
    Restore(RestorePlan),
}

impl BackupPlan {
    pub fn auth(&self) -> &Auth {
        match self {
            BackupPlan::Dump(plan) => &plan.upload.auth,
            BackupPlan::Restore(plan) => &plan.download.auth,
        }
    }
}

// ---------------------------------------------------------------------------
// Command envelope
// ---------------------------------------------------------------------------

/// Deserialization shape of the `backup` command params. `run_id` is required
/// (the correlation key for `backup_run`); a command without it is rejected.
#[derive(Debug, Deserialize)]
struct RawBackupCommand {
    action: BackupAction,
    run_id: i32,
    plan: Value,
    /// Optional execution deadline in seconds. Fallbacks (in order): the
    /// `COMMAND_TIMEOUT_SECS` env, then [`DEFAULT_BACKUP_TIMEOUT_SECS`].
    #[serde(default)]
    timeout: Option<u64>,
}

/// Parsed `backup` command: `{ action, run_id, plan }` per the contract's
/// `BackupCommand` envelope.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawBackupCommand")]
pub struct BackupCommand {
    pub action: BackupAction,
    pub run_id: i32,
    pub plan: BackupPlan,
    pub timeout: Option<u64>,
    pub deployment_hash: String,
}

impl TryFrom<RawBackupCommand> for BackupCommand {
    type Error = String;

    fn try_from(raw: RawBackupCommand) -> Result<Self, String> {
        if raw.run_id <= 0 {
            return Err(
                "run_id is required and must be a positive integer (backup_run.id)".to_string(),
            );
        }
        let plan = match raw.action {
            BackupAction::Dump => {
                let plan: DumpPlan = serde_json::from_value(raw.plan)
                    .map_err(|e| format!("invalid dump plan: {}", e))?;
                plan.validate().map_err(|e| e.to_string())?;
                BackupPlan::Dump(plan)
            }
            BackupAction::Restore => {
                let plan: RestorePlan = serde_json::from_value(raw.plan)
                    .map_err(|e| format!("invalid restore plan: {}", e))?;
                plan.validate().map_err(|e| e.to_string())?;
                BackupPlan::Restore(plan)
            }
        };
        Ok(BackupCommand {
            action: raw.action,
            run_id: raw.run_id,
            plan,
            timeout: raw.timeout,
            deployment_hash: String::new(),
        })
    }
}

impl BackupCommand {
    pub fn normalize(mut self) -> Self {
        match &mut self.plan {
            BackupPlan::Dump(plan) => {
                plan.upload.url = plan.upload.url.trim().to_string();
            }
            BackupPlan::Restore(plan) => {
                plan.download.url = plan.download.url.trim().to_string();
            }
        }
        self
    }

    pub fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.run_id <= 0 {
            bail!("run_id is required and must be a positive integer (backup_run.id)");
        }
        Ok(())
    }

    /// Execution deadline in seconds.
    pub fn timeout_secs(&self) -> u64 {
        let raw = self.timeout.unwrap_or_else(default_backup_timeout);
        raw.clamp(1, MAX_BACKUP_TIMEOUT_SECS)
    }
}

fn default_backup_timeout() -> u64 {
    std::env::var("COMMAND_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_BACKUP_TIMEOUT_SECS)
}

// ---------------------------------------------------------------------------
// Plan validation
// ---------------------------------------------------------------------------

impl DumpPlan {
    fn validate(&self) -> Result<()> {
        validate_argv(&self.argv)?;
        validate_url(&self.upload.url)?;
        validate_auth(&self.upload.auth)?;
        validate_headers(&self.upload.headers, &self.upload.auth)?;
        match &self.upload.body {
            UploadBody::Raw => {}
            UploadBody::Multipart { file_field, fields } => {
                if file_field.trim().is_empty() {
                    bail!("multipart file_field must not be empty");
                }
                for field in fields {
                    if field.name.trim().is_empty() {
                        bail!("multipart field name must not be empty");
                    }
                    scan_env_refs(&field.value, &self.upload.auth)?;
                }
            }
        }
        Ok(())
    }
}

impl RestorePlan {
    fn validate(&self) -> Result<()> {
        validate_argv(&self.argv)?;
        validate_url(&self.download.url)?;
        validate_auth(&self.download.auth)?;
        validate_headers(&self.download.headers, &self.download.auth)
    }
}

fn validate_argv(argv: &[String]) -> Result<()> {
    match argv.first() {
        None => bail!("plan argv must not be empty"),
        Some(program) if program.trim().is_empty() => {
            bail!("plan argv program must not be empty")
        }
        Some(_) => Ok(()),
    }
}

fn validate_url(url: &str) -> Result<()> {
    if url.trim().is_empty() {
        bail!("plan target url must not be empty");
    }
    Ok(())
}

fn validate_auth(auth: &Auth) -> Result<()> {
    for name in auth.env_names() {
        if name.trim().is_empty() {
            bail!("auth env var name must not be empty");
        }
    }
    if let Auth::ClientCredentials { token_url, .. } = auth {
        if token_url.trim().is_empty() {
            bail!("client_credentials token_url must not be empty");
        }
    }
    Ok(())
}

fn validate_headers(headers: &[(String, String)], auth: &Auth) -> Result<()> {
    for (name, value) in headers {
        if name.trim().is_empty() {
            bail!("header name must not be empty");
        }
        if contains_crlf(name) || contains_crlf(value) {
            bail!("header must not contain CR or LF");
        }
        scan_env_refs(value, auth)?;
    }
    Ok(())
}

fn contains_crlf(value: &str) -> bool {
    value.contains('\r') || value.contains('\n')
}

// ---------------------------------------------------------------------------
// $ENV resolution (allowlisted)
// ---------------------------------------------------------------------------

/// Names every plan value may reference, beyond the plan's own auth env names.
fn env_name_allowed(name: &str, auth: &Auth) -> bool {
    name == "AGENT_ID"
        || name == "BACKUP_FILENAME"
        || name.starts_with("BACKUP_")
        || auth.env_names().contains(&name)
}

/// `$VAR` / `${VAR}` references in `value`, in order of appearance.
fn env_refs(value: &str) -> Vec<String> {
    let bytes = value.as_bytes();
    let mut refs = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'$' {
            index += 1;
            continue;
        }
        let mut cursor = index + 1;
        let braced = cursor < bytes.len() && bytes[cursor] == b'{';
        if braced {
            cursor += 1;
        }
        let start = cursor;
        while cursor < bytes.len() {
            let ch = bytes[cursor];
            let ok = ch.is_ascii_alphanumeric() || ch == b'_';
            if !ok {
                break;
            }
            cursor += 1;
        }
        let name = &value[start..cursor];
        if braced {
            if cursor < bytes.len() && bytes[cursor] == b'}' {
                cursor += 1;
            } else {
                // Unterminated brace: treat the `$` as a literal.
                index += 1;
                continue;
            }
        }
        if name.is_empty() {
            index += 1;
            continue;
        }
        refs.push(name.to_string());
        index = cursor;
    }
    refs
}

/// Fail if `value` references any `$VAR` outside the allowlist.
fn scan_env_refs(value: &str, auth: &Auth) -> Result<()> {
    for name in env_refs(value) {
        if !env_name_allowed(&name, auth) {
            bail!(
                "backup plan value references non-allowlisted environment variable '${}' - refusing to resolve it",
                name
            );
        }
    }
    Ok(())
}

/// Resolves `$VAR` references in header/field values from the agent's
/// environment (or an injected map in tests).
#[derive(Debug, Clone)]
pub struct PlanEnv {
    /// Agent-generated archive filename for this run (`$BACKUP_FILENAME`).
    filename: String,
    /// Env names declared by the plan's own `Auth` block.
    auth: Auth,
    /// Test-only value overrides; empty when reading the process environment.
    overrides: std::collections::HashMap<String, String>,
}

impl PlanEnv {
    pub fn from_process(filename: String, auth: Auth) -> Self {
        Self {
            filename,
            auth,
            overrides: std::collections::HashMap::new(),
        }
    }

    #[cfg(test)]
    fn with_overrides(
        filename: String,
        auth: Auth,
        overrides: std::collections::HashMap<String, String>,
    ) -> Self {
        Self {
            filename,
            auth,
            overrides,
        }
    }

    pub fn filename(&self) -> &str {
        &self.filename
    }

    #[cfg(test)]
    fn auth(&self) -> &Auth {
        &self.auth
    }

    fn lookup(&self, name: &str) -> Result<String> {
        if name == "BACKUP_FILENAME" {
            return Ok(self.filename.clone());
        }
        if !env_name_allowed(name, &self.auth) {
            bail!(
                "backup plan value references non-allowlisted environment variable '${}' - refusing to resolve it",
                name
            );
        }
        if let Some(value) = self.overrides.get(name) {
            return Ok(value.clone());
        }
        std::env::var(name).map_err(|_| anyhow!("environment variable ${} is not set", name))
    }

    /// Substitute `$VAR` / `${VAR}` references in `value`.
    fn resolve_value(&self, value: &str) -> Result<String> {
        let mut out = String::with_capacity(value.len());
        let mut rest = value;
        while let Some(position) = rest.find('$') {
            out.push_str(&rest[..position]);
            let after = &rest[position + 1..];
            // `consumed` counts from `after`'s start (i.e. after the `$`).
            let (name, consumed) = match after.strip_prefix('{') {
                Some(brace_rest) => match brace_rest.find('}') {
                    Some(end) => (&brace_rest[..end], end + 2),
                    None => ("", 1),
                },
                None => {
                    let end = after
                        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                        .unwrap_or(after.len());
                    (&after[..end], end)
                }
            };
            if name.is_empty() {
                // Not a reference (`$` followed by `{` without a name, etc.).
                out.push('$');
                rest = &rest[position + 1..];
                continue;
            }
            out.push_str(&self.lookup(name)?);
            rest = &rest[position + 1 + consumed..];
        }
        out.push_str(rest);
        Ok(out)
    }
}

/// Resolve header values and rebuild the (name, value) list. Rejects CR/LF in
/// names and in raw or resolved values.
fn resolve_headers(headers: &[(String, String)], env: &PlanEnv) -> Result<Vec<(String, String)>> {
    let mut resolved = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let name = name.trim();
        if name.is_empty() {
            bail!("header name must not be empty");
        }
        if contains_crlf(name) || contains_crlf(value) {
            bail!("header must not contain CR or LF");
        }
        let value = env.resolve_value(value)?;
        if contains_crlf(&value) {
            bail!("header value resolves to a string containing CR or LF");
        }
        resolved.push((name.to_string(), value));
    }
    Ok(resolved)
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/// Per-run cache of a `client_credentials` access token.
#[derive(Debug, Clone, Default)]
struct TokenCache {
    token: Arc<Mutex<Option<String>>>,
}

impl TokenCache {
    fn cached(&self) -> Option<String> {
        self.token.lock().expect("token cache poisoned").clone()
    }

    fn store(&self, token: String) {
        *self.token.lock().expect("token cache poisoned") = Some(token);
    }

    fn invalidate(&self) {
        *self.token.lock().expect("token cache poisoned") = None;
    }
}

/// Build the `Authorization` header value for `auth`. `force_refresh` drops a
/// cached `client_credentials` token first (refresh on 401).
async fn auth_header(
    auth: &Auth,
    env: &PlanEnv,
    cache: &TokenCache,
    force_refresh: bool,
) -> Result<Option<(String, String)>> {
    if force_refresh {
        cache.invalidate();
    }
    match auth {
        Auth::None => Ok(None),
        Auth::Bearer { token_env } => Ok(Some((
            "Authorization".to_string(),
            format!("Bearer {}", env.lookup(token_env)?),
        ))),
        Auth::Basic {
            username_env,
            password_env,
        } => {
            let raw = format!(
                "{}:{}",
                env.lookup(username_env)?,
                env.lookup(password_env)?
            );
            Ok(Some((
                "Authorization".to_string(),
                format!("Basic {}", general_purpose::STANDARD.encode(raw)),
            )))
        }
        Auth::ClientCredentials {
            token_url,
            client_id_env,
            client_secret_env,
            scope,
        } => {
            if let Some(token) = cache.cached() {
                return Ok(Some((
                    "Authorization".to_string(),
                    format!("Bearer {}", token),
                )));
            }
            let client_id = env.lookup(client_id_env)?;
            let client_secret = env.lookup(client_secret_env)?;
            let mut form = vec![
                ("grant_type", "client_credentials".to_string()),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ];
            if let Some(scope) = scope {
                form.push(("scope", scope.clone()));
            }
            let response = reqwest::Client::new()
                .post(token_url)
                .form(&form)
                .send()
                .await
                .map_err(|e| anyhow!("token request failed: {}", e))?;
            if !response.status().is_success() {
                bail!("token request rejected: {}", response.status());
            }
            let body: Value = response
                .json()
                .await
                .map_err(|e| anyhow!("token response invalid: {}", e))?;
            let token = body
                .get("access_token")
                .and_then(|value| value.as_str())
                .ok_or_else(|| anyhow!("token response missing access_token"))?
                .to_string();
            cache.store(token.clone());
            Ok(Some((
                "Authorization".to_string(),
                format!("Bearer {}", token),
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Streaming (count + SHA-256 while the archive passes through)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct StreamState {
    bytes: AtomicU64,
    hasher: Mutex<Sha256>,
}

impl StreamState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            bytes: AtomicU64::new(0),
            hasher: Mutex::new(Sha256::new()),
        })
    }

    fn push(&self, chunk: &[u8]) {
        self.bytes.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        self.hasher
            .lock()
            .expect("stream hasher poisoned")
            .update(chunk);
    }

    fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    fn checksum_hex(&self) -> String {
        let digest = self
            .hasher
            .lock()
            .expect("stream hasher poisoned")
            .finalize_reset();
        digest.iter().map(|byte| format!("{:02x}", byte)).collect()
    }
}

/// `AsyncRead` → `Stream<Bytes>` that counts bytes and feeds the SHA-256
/// hasher while the archive streams through (never buffered in memory).
struct HashingStream<R> {
    inner: R,
    state: Arc<StreamState>,
    buf: Box<[u8]>,
}

impl<R: AsyncRead + Unpin> HashingStream<R> {
    fn new(inner: R, state: Arc<StreamState>) -> Self {
        Self {
            inner,
            state,
            buf: vec![0u8; 64 * 1024].into_boxed_slice(),
        }
    }
}

impl<R: AsyncRead + Unpin> Stream for HashingStream<R> {
    type Item = std::io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut read_buf = tokio::io::ReadBuf::new(&mut this.buf);
        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                if filled.is_empty() {
                    Poll::Ready(None)
                } else {
                    this.state.push(filled);
                    Poll::Ready(Some(Ok(Bytes::copy_from_slice(filled))))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------

/// Spawn `argv` directly (no shell): stdout/stderr piped, stdin optionally
/// piped (restore). `kill_on_drop` so a cancelled/timeout run cannot leak the
/// process.
fn spawn_process(argv: &[String], with_stdin: bool) -> Result<Child> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| anyhow!("plan argv must not be empty"))?;
    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if with_stdin {
        command.stdin(Stdio::piped());
    }
    command
        .spawn()
        .map_err(|e| anyhow!("failed to start backup process '{}': {}", program, e))
}

/// Capture at most [`STDERR_CAP_BYTES`] of the child's stderr for diagnostics.
async fn drain_stderr(stream: Option<ChildStderr>) -> Vec<u8> {
    let Some(mut stream) = stream else {
        return Vec::new();
    };
    let mut captured = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                let room = STDERR_CAP_BYTES.saturating_sub(captured.len());
                captured.extend_from_slice(&chunk[..read.min(room)]);
            }
        }
    }
    captured
}

fn stderr_text(captured: &[u8]) -> String {
    String::from_utf8_lossy(captured).trim().to_string()
}

/// SIGTERM, then SIGKILL after a grace period (executor.rs parity).
async fn terminate_child(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
        if tokio_timeout(Duration::from_secs(TERMINATE_GRACE_SECS), child.wait())
            .await
            .is_ok()
        {
            return;
        }
    }
    let _ = child.kill().await;
}

/// Read at most `cap` bytes of a response body (upload metadata / error text).
async fn read_capped(response: reqwest::Response, cap: usize) -> Result<String> {
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| anyhow!("failed to read response body: {}", e))?
    {
        let room = cap.saturating_sub(body.len());
        if room == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..chunk.len().min(room)]);
    }
    Ok(String::from_utf8_lossy(&body).to_string())
}

/// The file id the storage returned from an upload. Key order follows the
/// storage contract candidates; falls back to the archive filename (the
/// contract's "archive basename" form).
fn extract_remote_file_id(body: &str, filename: &str) -> String {
    const KEYS: [&str; 5] = ["file_id", "remote_file_id", "id", "file_name", "filename"];
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        for key in KEYS {
            if let Some(text) = value.get(key).and_then(|v| v.as_str()) {
                if !text.trim().is_empty() {
                    return text.trim().to_string();
                }
            }
            for wrapper in ["item", "data"] {
                if let Some(text) = value
                    .get(wrapper)
                    .and_then(|v| v.get(key))
                    .and_then(|v| v.as_str())
                {
                    if !text.trim().is_empty() {
                        return text.trim().to_string();
                    }
                }
            }
        }
    }
    filename.to_string()
}

/// Agent-generated archive filename for a run: `run-<run_id>-<utc timestamp>`.
fn backup_filename(run_id: i32) -> String {
    format!("run-{}-{}", run_id, Utc::now().format("%Y%m%dT%H%M%SZ"))
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// What the run streamed/received, reported back to Stacker either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    /// `"success"` | `"failed"` | `"timeout"`.
    pub status: String,
    pub error: Option<String>,
    pub size_bytes: u64,
    /// SHA-256 of the archive (dump success only).
    pub checksum: Option<String>,
    /// File id returned by the storage (dump only).
    pub remote_file_id: Option<String>,
    /// Restore reports `false` explicitly: `DownloadTarget` carries no
    /// checksum, so the agent cannot verify the downloaded archive
    /// (FEATURES.md §5) — it must not silently claim verification.
    pub integrity_verified: Option<bool>,
}

impl RunReport {
    fn failed(message: impl Into<String>, size_bytes: u64) -> Self {
        Self {
            status: "failed".to_string(),
            error: Some(message.into()),
            size_bytes,
            checksum: None,
            remote_file_id: None,
            integrity_verified: None,
        }
    }

    fn timed_out(message: impl Into<String>, size_bytes: u64) -> Self {
        Self {
            status: "timeout".to_string(),
            error: Some(message.into()),
            size_bytes,
            checksum: None,
            remote_file_id: None,
            integrity_verified: None,
        }
    }
}

/// Failure of a dump upload leg; carries the `remote_file_id` the storage
/// returned so Stacker/storage can clean up the partial file.
struct UploadError {
    message: String,
    remote_file_id: Option<String>,
}

impl UploadError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            remote_file_id: None,
        }
    }
}

/// Build the upload request from the plan's data: `raw` streams the archive as
/// the request body, `multipart` streams it into `file_field` alongside the
/// literal fields. Both stream — the archive is never buffered in memory.
async fn build_upload_request(
    client: &reqwest::Client,
    target: &UploadTarget,
    env: &PlanEnv,
    filename: &str,
    stream: HashingStream<tokio::process::ChildStdout>,
) -> Result<reqwest::RequestBuilder> {
    let request = client.post(&target.url);
    let request = match &target.body {
        UploadBody::Raw => request
            .header("Content-Type", "application/octet-stream")
            .body(reqwest::Body::wrap_stream(stream)),
        UploadBody::Multipart { file_field, fields } => {
            let mut form = reqwest::multipart::Form::new();
            for field in fields {
                form = form.text(field.name.clone(), env.resolve_value(&field.value)?);
            }
            let part = reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(stream))
                .file_name(filename.to_string());
            request.multipart(form.part(file_field.clone(), part))
        }
    };
    apply_headers_and_auth(request, &target.headers, &target.auth, env).await
}

/// Apply the plan's resolved headers, then the auth header (auth wins over a
/// plan-provided `Authorization`).
async fn apply_headers_and_auth(
    mut request: reqwest::RequestBuilder,
    headers: &[(String, String)],
    auth: &Auth,
    env: &PlanEnv,
) -> Result<reqwest::RequestBuilder> {
    for (name, value) in resolve_headers(headers, env)? {
        request = request.header(name, value);
    }
    let cache = TokenCache::default();
    if let Some((name, value)) = auth_header(auth, env, &cache, false).await? {
        request = request.header(name, value);
    }
    Ok(request)
}

async fn run_dump(
    client: &reqwest::Client,
    plan: &DumpPlan,
    env: &PlanEnv,
    filename: &str,
    deadline: Duration,
) -> RunReport {
    let state = StreamState::new();
    let mut child = match spawn_process(&plan.argv, false) {
        Ok(child) => child,
        Err(error) => return RunReport::failed(error.to_string(), 0),
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_child(&mut child).await;
        return RunReport::failed("dump process has no stdout to stream", 0);
    };
    let stderr_task = tokio::spawn(drain_stderr(child.stderr.take()));
    let stream = HashingStream::new(stdout, state.clone());

    let outcome = tokio_timeout(
        deadline,
        dump_upload(
            client,
            &plan.upload,
            env,
            filename,
            stream,
            &mut child,
            stderr_task,
        ),
    )
    .await;

    match outcome {
        Ok(Ok(remote_file_id)) => RunReport {
            status: "success".to_string(),
            error: None,
            size_bytes: state.bytes(),
            checksum: Some(state.checksum_hex()),
            remote_file_id: Some(remote_file_id),
            integrity_verified: None,
        },
        Ok(Err(failure)) => RunReport {
            status: "failed".to_string(),
            error: Some(failure.message),
            size_bytes: state.bytes(),
            checksum: None,
            remote_file_id: failure.remote_file_id,
            integrity_verified: None,
        },
        Err(_elapsed) => {
            terminate_child(&mut child).await;
            RunReport::timed_out(
                format!(
                    "backup timed out after {}s; the dump process was terminated",
                    deadline.as_secs()
                ),
                state.bytes(),
            )
        }
    }
}

async fn dump_upload(
    client: &reqwest::Client,
    target: &UploadTarget,
    env: &PlanEnv,
    filename: &str,
    stream: HashingStream<tokio::process::ChildStdout>,
    child: &mut Child,
    stderr_task: JoinHandle<Vec<u8>>,
) -> std::result::Result<String, UploadError> {
    let request = build_upload_request(client, target, env, filename, stream)
        .await
        .map_err(|e| UploadError::new(e.to_string()))?;
    let response = request
        .send()
        .await
        .map_err(|e| UploadError::new(format!("upload request failed: {}", e)))?;
    let status = response.status();
    let body = read_capped(response, RESPONSE_CAP_BYTES)
        .await
        .map_err(|e| UploadError::new(e.to_string()))?;
    let remote_file_id = extract_remote_file_id(&body, filename);

    if !status.is_success() {
        if status.as_u16() == 401 {
            warn!("upload auth rejected (401) by the backup storage");
        }
        return Err(UploadError {
            message: format!("upload rejected: {} {}", status, body.trim()),
            remote_file_id: Some(remote_file_id),
        });
    }

    // A non-zero exit after streaming invalidates the archive: the storage
    // kept a partial/corrupt dump even though the upload itself succeeded.
    let exit = child
        .wait()
        .await
        .map_err(|e| UploadError::new(format!("failed to wait for dump process: {}", e)))?;
    let stderr = stderr_text(&stderr_task.await.unwrap_or_default());
    if !exit.success() {
        let mut message = format!("dump process exited with {}", exit);
        if !stderr.is_empty() {
            message.push_str(": ");
            message.push_str(&stderr);
        }
        return Err(UploadError {
            message,
            remote_file_id: Some(remote_file_id),
        });
    }

    debug!(remote_file_id = %remote_file_id, "dump upload completed");
    Ok(remote_file_id)
}

async fn run_restore(
    client: &reqwest::Client,
    plan: &RestorePlan,
    env: &PlanEnv,
    deadline: Duration,
) -> RunReport {
    let state = StreamState::new();
    let mut child = match spawn_process(&plan.argv, true) {
        Ok(child) => child,
        Err(error) => return RunReport::failed(error.to_string(), 0),
    };
    let Some(stdin) = child.stdin.take() else {
        terminate_child(&mut child).await;
        return RunReport::failed("restore process has no stdin to stream into", 0);
    };
    let stderr_task = tokio::spawn(drain_stderr(child.stderr.take()));

    let state_inner = state.clone();
    let outcome = tokio_timeout(
        deadline,
        restore_download(
            client,
            &plan.download,
            env,
            stdin,
            &mut child,
            stderr_task,
            state_inner,
        ),
    )
    .await;

    match outcome {
        Ok(Ok(())) => RunReport {
            status: "success".to_string(),
            error: None,
            size_bytes: state.bytes(),
            checksum: None,
            remote_file_id: None,
            integrity_verified: Some(false),
        },
        Ok(Err(message)) => RunReport::failed(message, state.bytes()),
        Err(_elapsed) => {
            terminate_child(&mut child).await;
            RunReport::timed_out(
                format!(
                    "restore timed out after {}s; the restore process was terminated",
                    deadline.as_secs()
                ),
                state.bytes(),
            )
        }
    }
}

async fn restore_download(
    client: &reqwest::Client,
    target: &DownloadTarget,
    env: &PlanEnv,
    mut stdin: tokio::process::ChildStdin,
    child: &mut Child,
    stderr_task: JoinHandle<Vec<u8>>,
    state: Arc<StreamState>,
) -> std::result::Result<(), String> {
    let response = send_download(client, target, env)
        .await
        .map_err(|e| e.to_string())?;

    // Stream the archive into the restore process's stdin (never buffered).
    let mut response = response;
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|e| format!("download stream failed: {}", e))?;
        let Some(chunk) = chunk else { break };
        state.push(&chunk);
        if let Err(error) = stdin.write_all(&chunk).await {
            let stderr = stderr_text(&stderr_task.await.unwrap_or_default());
            let mut message = format!("restore process rejected the archive stream: {}", error);
            if !stderr.is_empty() {
                message.push_str(": ");
                message.push_str(&stderr);
            }
            return Err(message);
        }
    }
    // EOF: drop stdin so the restore process sees end-of-stream and finishes.
    drop(stdin);

    let exit = child
        .wait()
        .await
        .map_err(|e| format!("failed to wait for restore process: {}", e))?;
    let stderr = stderr_text(&stderr_task.await.unwrap_or_default());
    if !exit.success() {
        let mut message = format!("restore process exited with {}", exit);
        if !stderr.is_empty() {
            message.push_str(": ");
            message.push_str(&stderr);
        }
        return Err(message);
    }
    Ok(())
}

/// GET the stored archive. Replayable, so it retries on transient failures and
/// refreshes a `client_credentials` token once on 401 (the upload leg streams
/// a child's stdout and cannot be replayed).
async fn send_download(
    client: &reqwest::Client,
    target: &DownloadTarget,
    env: &PlanEnv,
) -> Result<reqwest::Response> {
    let cache = TokenCache::default();
    let headers = resolve_headers(&target.headers, env)?;
    const ATTEMPTS: u32 = 3;

    let mut attempt = 0;
    let mut force_refresh = false;
    loop {
        attempt += 1;
        let mut request = client.get(&target.url);
        for (name, value) in &headers {
            request = request.header(name, value);
        }
        if let Some((name, value)) = auth_header(&target.auth, env, &cache, force_refresh).await? {
            request = request.header(name, value);
        }
        force_refresh = false;

        match request.send().await {
            Ok(response) if response.status().is_success() => return Ok(response),
            Ok(response) if response.status().as_u16() == 401 && attempt < ATTEMPTS => {
                cache.invalidate();
                force_refresh = true;
                warn!("download auth rejected (401); refreshing token and retrying");
                continue;
            }
            Ok(response) if response.status().is_server_error() && attempt < ATTEMPTS => {
                warn!(attempt, "download rejected with server error; retrying");
                sleep(Duration::from_millis(200 * attempt as u64)).await;
                continue;
            }
            Ok(response) => {
                let status = response.status();
                let body = read_capped(response, RESPONSE_CAP_BYTES)
                    .await
                    .unwrap_or_default();
                bail!("download rejected: {} {}", status, body.trim());
            }
            Err(error) if attempt < ATTEMPTS => {
                warn!(attempt, error = %error, "download request failed; retrying");
                sleep(Duration::from_millis(200 * attempt as u64)).await;
                continue;
            }
            Err(error) => bail!("download request failed: {}", error),
        }
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Execute a `backup` command and build the `CommandResult` envelope for the
/// existing report path (`agent/daemon.rs` `execute_and_report`).
pub async fn handle_backup(
    agent_cmd: &AgentCommand,
    data: &BackupCommand,
) -> Result<CommandResult> {
    let mut result = base_result(agent_cmd, &data.deployment_hash, "", "backup");
    let filename = backup_filename(data.run_id);
    let deadline = Duration::from_secs(data.timeout_secs());

    info!(
        run_id = data.run_id,
        action = data.action.as_str(),
        filename = %filename,
        timeout_secs = deadline.as_secs(),
        "backup command started"
    );

    let env = PlanEnv::from_process(filename, data.plan.auth().clone());

    let client = reqwest::Client::new();
    let report = match &data.plan {
        BackupPlan::Dump(plan) => run_dump(&client, plan, &env, env.filename(), deadline).await,
        BackupPlan::Restore(plan) => run_restore(&client, plan, &env, deadline).await,
    };

    info!(
        run_id = data.run_id,
        action = data.action.as_str(),
        status = %report.status,
        size_bytes = report.size_bytes,
        "backup command finished"
    );

    let mut body = json!({
        "type": "backup",
        "action": data.action.as_str(),
        "run_id": data.run_id,
        "size_bytes": report.size_bytes,
    });
    if let Some(checksum) = &report.checksum {
        body["checksum"] = json!(checksum);
    }
    if let Some(remote_file_id) = &report.remote_file_id {
        body["remote_file_id"] = json!(remote_file_id);
    }
    if let Some(integrity_verified) = report.integrity_verified {
        body["integrity_verified"] = json!(integrity_verified);
    }

    result.status = report.status.clone();
    match &report.error {
        None => {
            result.result = Some(body);
        }
        Some(message) => {
            let (redacted, _) = redact_message(message, true);
            // Stacker's run lifecycle reads `result.error` when marking the
            // backup_run failed, so the redacted message goes in the body too.
            body["error"] = json!(redacted);
            result.result = Some(body);
            result.error = Some(redacted.clone());
            // Non-empty `errors` also makes Stacker classify `status:
            // "timeout"` as failed (its report handler only maps `"failed"` or
            // a non-empty `errors` list to Failed).
            result.errors = Some(vec![CommandError {
                code: if report.status == "timeout" {
                    "backup_timeout".to_string()
                } else {
                    "backup_failed".to_string()
                },
                message: redacted,
                details: None,
            }]);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::stacker::{parse_stacker_command, StackerCommand};
    use serde_json::json;

    fn agent_command(params: Value) -> AgentCommand {
        AgentCommand {
            id: "test-id".to_string(),
            command_id: "test-cmd".to_string(),
            name: "backup".to_string(),
            params,
            deployment_hash: Some("hash-1".to_string()),
            app_code: None,
        }
    }

    fn dump_params() -> Value {
        json!({
            "action": "dump",
            "run_id": 123,
            "plan": {
                "argv": ["docker","exec","shop-postgres-1","pg_dump","-Fc","shop"],
                "upload": {
                    "url": "https://api.example/upload",
                    "body": {
                        "type": "multipart",
                        "file_field": "file",
                        "fields": [{"name":"device_id","value":"$AGENT_ID"}]
                    },
                    "auth": {
                        "type": "client_credentials",
                        "token_url": "https://login.example/oauth/v2/token",
                        "client_id_env": "BACKUP_CLIENT_ID",
                        "client_secret_env": "BACKUP_CLIENT_SECRET",
                        "scope": "openid"
                    },
                    "headers": [["X-Backup-Filename","$BACKUP_FILENAME"]]
                }
            }
        })
    }

    // ==================== PARSING ====================

    #[test]
    fn parses_dump_envelope_from_the_features_example() {
        let parsed = parse_stacker_command(&agent_command(dump_params())).unwrap();
        match parsed {
            Some(StackerCommand::Backup(cmd)) => {
                assert_eq!(cmd.action, BackupAction::Dump);
                assert_eq!(cmd.run_id, 123);
                match &cmd.plan {
                    BackupPlan::Dump(plan) => {
                        assert_eq!(plan.argv.len(), 6);
                        assert_eq!(plan.upload.url, "https://api.example/upload");
                        assert_eq!(plan.upload.headers[0].0, "X-Backup-Filename");
                        match &plan.upload.body {
                            UploadBody::Multipart { file_field, fields } => {
                                assert_eq!(file_field, "file");
                                assert_eq!(fields[0].value, "$AGENT_ID");
                            }
                            other => panic!("expected multipart, got {:?}", other),
                        }
                    }
                    other => panic!("expected dump plan, got {:?}", other),
                }
            }
            other => panic!("expected backup command, got {:?}", other),
        }
    }

    #[test]
    fn parses_restore_envelope() {
        let params = json!({
            "action": "restore",
            "run_id": 7,
            "plan": {
                "argv": ["docker","exec","-i","shop-postgres-1","pg_restore","--clean"],
                "download": {
                    "url": "https://api.example/upload/files/f-1",
                    "auth": {"type": "bearer", "token_env": "BACKUP_TOKEN"},
                    "headers": []
                }
            }
        });
        let parsed = parse_stacker_command(&agent_command(params)).unwrap();
        match parsed {
            Some(StackerCommand::Backup(cmd)) => {
                assert_eq!(cmd.action, BackupAction::Restore);
                assert!(matches!(cmd.plan, BackupPlan::Restore(_)));
            }
            other => panic!("expected backup command, got {:?}", other),
        }
    }

    #[test]
    fn rejects_command_without_run_id() {
        let params = json!({
            "action": "dump",
            "plan": {
                "argv": ["true"],
                "upload": {
                    "url": "https://api.example/upload",
                    "body": {"type": "raw"},
                    "auth": {"type": "none"},
                    "headers": []
                }
            }
        });
        let error = parse_stacker_command(&agent_command(params)).unwrap_err();
        let text = format!("{:#}", error);
        assert!(text.contains("run_id"), "unexpected error: {}", text);
    }

    #[test]
    fn rejects_non_positive_run_id() {
        let mut params = dump_params();
        params["run_id"] = json!(0);
        let error = parse_stacker_command(&agent_command(params)).unwrap_err();
        assert!(format!("{:#}", error).contains("run_id"));
    }

    #[test]
    fn rejects_dump_action_with_a_restore_plan() {
        let params = json!({
            "action": "dump",
            "run_id": 1,
            "plan": {
                "argv": ["true"],
                "download": {
                    "url": "https://api.example/upload/files/f-1",
                    "auth": {"type": "none"},
                    "headers": []
                }
            }
        });
        assert!(parse_stacker_command(&agent_command(params)).is_err());
    }

    #[test]
    fn rejects_empty_argv_and_url() {
        let mut params = dump_params();
        params["plan"]["argv"] = json!([]);
        assert!(parse_stacker_command(&agent_command(params)).is_err());

        let mut params = dump_params();
        params["plan"]["upload"]["url"] = json!("  ");
        assert!(parse_stacker_command(&agent_command(params)).is_err());
    }

    // ==================== HEADER / FIELD SAFETY ====================

    #[test]
    fn rejects_crlf_in_headers() {
        let mut params = dump_params();
        params["plan"]["upload"]["headers"] = json!([["X-Bad", "value\r\nInjected: 1"]]);
        let error = parse_stacker_command(&agent_command(params)).unwrap_err();
        assert!(format!("{:#}", error).contains("CR or LF"));
    }

    #[test]
    fn rejects_crlf_in_header_names() {
        let mut params = dump_params();
        params["plan"]["upload"]["headers"] = json!([["X-Bad\r\nInjected", "1"]]);
        assert!(parse_stacker_command(&agent_command(params)).is_err());
    }

    #[test]
    fn rejects_unknown_env_reference_in_headers() {
        let mut params = dump_params();
        params["plan"]["upload"]["headers"] = json!([["X-Leak", "$VAULT_TOKEN"]]);
        let error = parse_stacker_command(&agent_command(params)).unwrap_err();
        assert!(format!("{:#}", error).contains("VAULT_TOKEN"));
    }

    #[test]
    fn rejects_unknown_env_reference_in_fields() {
        let mut params = dump_params();
        params["plan"]["upload"]["body"]["fields"] =
            json!([{"name": "device_id", "value": "$AWS_SECRET"}]);
        let error = parse_stacker_command(&agent_command(params)).unwrap_err();
        assert!(format!("{:#}", error).contains("AWS_SECRET"));
    }

    #[test]
    fn allows_declared_auth_env_and_backup_references() {
        let mut params = dump_params();
        // `$BACKUP_*` and `$AGENT_ID` are allowlisted; the plan's own auth
        // env names are too.
        params["plan"]["upload"]["body"]["fields"] = json!([
            {"name": "device_id", "value": "$AGENT_ID"},
            {"name": "client", "value": "${BACKUP_CLIENT_ID}"},
            {"name": "secret", "value": "$BACKUP_CLIENT_SECRET"}
        ]);
        assert!(parse_stacker_command(&agent_command(params)).is_ok());
    }

    // ==================== $ENV RESOLUTION ====================

    fn test_env(overrides: std::collections::HashMap<String, String>) -> PlanEnv {
        PlanEnv::with_overrides(
            "run-1-20261126T000000Z".to_string(),
            Auth::Bearer {
                token_env: "BACKUP_TOKEN".to_string(),
            },
            overrides,
        )
    }

    #[test]
    fn resolve_value_substitutes_agent_id_and_filename() {
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("AGENT_ID".to_string(), "agent-9".to_string());
        let env = test_env(overrides);
        assert_eq!(env.resolve_value("$AGENT_ID").unwrap(), "agent-9");
        assert_eq!(
            env.resolve_value("${BACKUP_FILENAME}").unwrap(),
            "run-1-20261126T000000Z"
        );
        assert_eq!(
            env.resolve_value("pre-$AGENT_ID-post").unwrap(),
            "pre-agent-9-post"
        );
    }

    #[test]
    fn resolve_value_rejects_missing_env() {
        let env = test_env(std::collections::HashMap::new());
        let error = env.resolve_value("$BACKUP_TOKEN").unwrap_err();
        assert!(error.to_string().contains("BACKUP_TOKEN"));
    }

    #[test]
    fn resolve_value_rejects_non_allowlisted_names() {
        let env = test_env(std::collections::HashMap::new());
        let error = env.resolve_value("$VAULT_TOKEN").unwrap_err();
        assert!(error.to_string().contains("VAULT_TOKEN"));
    }

    #[test]
    fn env_refs_parses_braced_and_plain_names() {
        assert_eq!(env_refs("$A and ${B_C} and $$"), vec!["A", "B_C"]);
        assert!(env_refs("no references here").is_empty());
        assert!(env_refs("$").is_empty());
    }

    // ==================== AUTH HEADERS ====================

    #[tokio::test]
    async fn auth_header_none_bearer_and_basic() {
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("BACKUP_TOKEN".to_string(), "tok-1".to_string());
        overrides.insert("BACKUP_USER".to_string(), "u".to_string());
        overrides.insert("BACKUP_PASS".to_string(), "p".to_string());
        let cache = TokenCache::default();

        let env = test_env(overrides.clone());
        assert_eq!(
            auth_header(&Auth::None, &env, &cache, false).await.unwrap(),
            None
        );
        assert_eq!(
            auth_header(
                &Auth::Bearer {
                    token_env: "BACKUP_TOKEN".to_string()
                },
                &env,
                &cache,
                false
            )
            .await
            .unwrap(),
            Some(("Authorization".to_string(), "Bearer tok-1".to_string()))
        );
        let basic = auth_header(
            &Auth::Basic {
                username_env: "BACKUP_USER".to_string(),
                password_env: "BACKUP_PASS".to_string(),
            },
            &env,
            &cache,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(basic.0, "Authorization");
        assert_eq!(
            basic.1,
            format!("Basic {}", general_purpose::STANDARD.encode("u:p"))
        );
    }

    #[tokio::test]
    async fn client_credentials_exchanges_and_caches_the_token() {
        let mut server = mockito::Server::new_async().await;
        let token_mock = server
            .mock("POST", "/oauth/v2/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::Regex("grant_type=client_credentials".to_string()),
                mockito::Matcher::Regex("client_id=cid-1".to_string()),
                mockito::Matcher::Regex("scope=openid".to_string()),
            ]))
            .with_status(200)
            .with_body(r#"{"access_token":"tok-123","token_type":"Bearer"}"#)
            .expect(1)
            .create_async()
            .await;

        let mut overrides = std::collections::HashMap::new();
        overrides.insert("BACKUP_CLIENT_ID".to_string(), "cid-1".to_string());
        overrides.insert("BACKUP_CLIENT_SECRET".to_string(), "sec-1".to_string());
        let env = PlanEnv::with_overrides(
            "run-1-f".to_string(),
            Auth::ClientCredentials {
                token_url: format!("{}/oauth/v2/token", server.url()),
                client_id_env: "BACKUP_CLIENT_ID".to_string(),
                client_secret_env: "BACKUP_CLIENT_SECRET".to_string(),
                scope: Some("openid".to_string()),
            },
            overrides,
        );
        let cache = TokenCache::default();

        let first = auth_header(env.auth(), &env, &cache, false).await.unwrap();
        let second = auth_header(env.auth(), &env, &cache, false).await.unwrap();
        assert_eq!(
            first,
            Some(("Authorization".to_string(), "Bearer tok-123".to_string()))
        );
        assert_eq!(first, second);
        // Cached per run: the token endpoint is hit exactly once.
        token_mock.assert_async().await;

        // Refresh on 401: a forced refresh drops the cache and re-exchanges.
        let refreshed = auth_header(env.auth(), &env, &cache, true).await.unwrap();
        assert_eq!(refreshed, first);
    }

    // ==================== MISC ====================

    #[test]
    fn extract_remote_file_id_prefers_response_and_falls_back() {
        assert_eq!(
            extract_remote_file_id(r#"{"file_id":"f-42"}"#, "run-1-x"),
            "f-42"
        );
        assert_eq!(
            extract_remote_file_id(r#"{"item":{"file_id":"f-9"}}"#, "run-1-x"),
            "f-9"
        );
        assert_eq!(extract_remote_file_id("not json", "run-1-x"), "run-1-x");
    }

    #[test]
    fn backup_filename_carries_the_run_id() {
        let name = backup_filename(42);
        assert!(name.starts_with("run-42-"), "unexpected filename: {}", name);
    }
}
