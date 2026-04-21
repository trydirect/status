# Changelog

## 0.1.8 — 2026-04-21
### Added
- `status --version` now includes the git short hash (for example `0.1.8 (abc1234)`) so production builds can be identified instantly.

### Changed
- Docker builds now include the protobuf build inputs required for gRPC client code generation in musl/release images.
- Pipe-contract fixtures remain sourced from `trydirect/config`, while fork PRs and unauthorized CI runs now skip only the shared-fixture tests instead of failing the entire workflow.

## 0.1.7 — 2026-04-10
### Security — OWASP Top 10 Hardening

This is a **security release** addressing 6 Critical and 5 High severity findings from a comprehensive OWASP Top 10 audit.

#### A01: Broken Access Control
- **No default credentials** — `Credentials::from_env()` now returns an error when `STATUS_PANEL_USERNAME` / `STATUS_PANEL_PASSWORD` are unset; no admin/admin backdoor
- **Container routes require auth** — `/restart/{name}`, `/stop/{name}`, `/pause/{name}` now enforce session authentication
- **SSL routes require auth** — `/enable_ssl`, `/disable_ssl` now enforce session authentication
- **AGENT_ID enforced** — `validate_agent_id` rejects requests when `AGENT_ID` env var is unset or empty

#### A02: Cryptographic Failures
- **Secure session cookies** — `Set-Cookie` now includes `Secure; SameSite=Strict; HttpOnly`

#### A03: Injection
- **Certbot command injection prevented** — email and domain values validated against shell metacharacters before `exec_in_container`
- **Daemon shell fallback validated** — unrecognised commands now pass through `CommandValidator` before execution
- New `security::validation` module with `is_safe_shell_value()`, `is_valid_domain()`, `is_valid_email()`, `is_safe_update_url()`

#### A04: Insecure Design
- **Session TTL** — `SessionStore` now tracks creation timestamps; `cleanup_expired(duration)` removes stale sessions

#### A05: Security Misconfiguration
- **Default bind address is 127.0.0.1** — server no longer binds `0.0.0.0` by default; explicit `--bind 0.0.0.0` required for all-interfaces

#### A07: Identification and Authentication Failures
- **Logout invalidates session** — `logout_handler` extracts cookie, calls `delete_session`, and sets `Max-Age=0`

#### A08: Software and Data Integrity Failures
- **HTTPS enforced for self-update** — `start_update_job` rejects HTTP URLs
- **SHA256 always computed** — hash is calculated on every download; warns if `UPDATE_EXPECTED_SHA256` is not set

### Added
- `status init` command — generates default `config.json` and `.env` template on first run
- Friendly error message when `config.json` is missing (replaces stack trace)
- 12 automated OWASP security tests (`tests/owasp_security.rs`)

### Fixed
- RUSTSEC-2026-0049 — upgraded `rustls-webpki` 0.103.8 → 0.103.10

## 0.1.6 — 2026-04-08
### Added — Kata Containers Runtime Support

#### Container Runtime Selection (`commands/stacker.rs`)
- `ContainerRuntime` enum (`runc`/`kata`) with serde support and Docker runtime name mapping
- `detect_kata_runtime()` — cached detection via `docker info` with 5s timeout and `OnceLock`
- `inject_runtime_into_compose()` — parses compose YAML and injects `runtime:` per-service
- `DeployAppCommand` and `DeployWithConfigsCommand` accept optional `runtime` field
- Graceful fallback: if Kata is requested but unavailable, deploys with runc and emits `kata_fallback` warning
- Effective runtime reported in deploy result body

#### Capabilities Discovery (`comms/local_api.rs`)
- `/capabilities` endpoint reports `"kata"` in features list when Kata runtime is detected on the host

#### Code Quality Fixes (PR #84 review)
- `runtime_compose_tests` gated with `#[cfg(all(test, feature = "docker"))]` for minimal builds
- Replaced blocking `std::path::Path::exists()` with `tokio::fs::try_exists()` in async deploy path
- Added proper error logging in `unlink_handler` for `try_exists` failures

#### Tests
- 14 new tests: enum behavior, serde deserialization, compose YAML injection (including edge cases), command parsing with runtime field

## 0.1.5 — 2026-03-26
### Added — Long Polling, Vault Integration, Compose Agent Sidecar

## 0.1.4 — 2026-03-13
### Added — CLI Improvements, Install Script & GitHub Releases

#### CI: GitHub Releases on Tags
- Added `v*` tag trigger to CI workflow
- New `create-release` job: downloads musl binary, generates SHA256 checksum, publishes GitHub Release via `softprops/action-gh-release@v2`
- Tag-triggered artifacts now use clean names without SHA suffix (e.g. `status-linux-x86_64-musl-v0.1.4`)

#### Install Script (`install.sh`)
- POSIX `sh` installer: `curl -sSfL .../install.sh | sh`
- Detects OS/arch (Linux x86_64 only initially)
- Queries GitHub API for latest release (no `jq` dependency)
- Supports `VERSION` env var to pin a specific version
- Supports `INSTALL_DIR` env var (default `/usr/local/bin`)
- Downloads musl binary, verifies SHA256 checksum, installs with `sudo` if needed

#### New CLI Subcommands (`src/main.rs`)
- `start <name>` — Start a stopped container (Docker)
- `health [name]` — Check container health for one or all containers (Docker)
- `logs <name> [-n lines]` — Fetch container logs with configurable line count (Docker)
- `metrics [--json]` — Print system metrics: CPU, memory, disk usage
- `update check` — Check for available updates against remote server
- `update apply [--version V]` — Download and verify an update
- `update rollback` — Rollback to the previous binary version

#### README
- Added "Quick Install" section with examples for latest install, version pinning, custom directory, and verification

## 2026-02-02
### Added - Container Exec & Server Resources Commands

#### New Stacker Commands (`commands/stacker.rs`)
- `ExecCommand` / `stacker.exec`: Execute commands inside running containers
  - Parameters: deployment_hash, app_code, command, timeout (1-120s)
  - **Security**: Blocks dangerous commands (rm -rf /, mkfs, dd if, shutdown, reboot, poweroff, halt, init 0/6, fork bombs)
  - Case-insensitive pattern matching for security blocks
  - Returns exit_code, stdout, stderr (output redacted for secrets)
  - Comprehensive test suite with 27 security tests

- `ServerResourcesCommand` / `stacker.server_resources`: Collect server metrics
  - Parameters: deployment_hash, include_disk, include_network, include_processes
  - Uses MetricsCollector for CPU, memory, disk, network, and process info
  - Returns structured JSON with system resource data

- `ListContainersCommand` / `stacker.list_containers`: List deployment containers
  - Parameters: deployment_hash, include_health, include_logs, log_lines (1-1000)
  - Returns container list with status, health info, and optional recent logs

#### Docker Module Updates (`agent/docker.rs`)
- Added `exec_in_container_with_output()`: Execute commands and capture stdout/stderr separately
  - Creates exec instance, starts with output capture
  - Waits for completion and inspects exit code
  - Returns structured (exit_code, stdout, stderr) tuple

#### Test Coverage
- `exec_command_security_tests`: 27 tests covering blocked commands, validation, timeout clamping
- `server_resources_command_tests`: 3 tests for parsing and validation
- `list_containers_command_tests`: 3 tests for parsing and log_lines clamping

## 2026-01-29
### Added - Unified Configuration Management Commands

#### New Stacker Commands (`commands/stacker.rs`)
- `FetchAllConfigs` / `stacker.fetch_all_configs`: Bulk fetch all app configs from Vault
  - Parameters: deployment_hash, app_codes (optional - fetch all if empty), apply, archive
  - Lists all available configs via Vault LIST operation
  - Optionally writes all configs to disk
  - Optionally creates tar.gz archive of all configs
  - Returns detailed summary with fetched/applied counts

- `DeployWithConfigs` / `stacker.deploy_with_configs`: Unified config+deploy operation
  - Parameters: deployment_hash, app_code, pull, force_recreate, apply_configs
  - Fetches docker-compose.yml from Vault (_compose key) and app-specific .env
  - Writes configs to disk before deployment
  - Delegates to existing deploy_app handler for container orchestration
  - Combines config and deploy results in single response

- `ConfigDiff` / `stacker.config_diff`: Detect configuration drift
  - Parameters: deployment_hash, app_codes (optional), include_diff
  - Compares SHA256 hashes of Vault configs vs deployed files
  - Reports status: synced, drifted, or missing for each app
  - Optionally includes line counts and content previews for drifted configs
  - Summary with total/synced/drifted/missing counts

#### Command Infrastructure
- Added normalize/validate/with_command_context for all new commands
- Integrated all new commands into execute_with_docker dispatch
- Added test cases for command parsing

## 2026-01-23
### Added - Vault Configuration Management

#### VaultClient Extensions (`security/vault_client.rs`)
- `AppConfig` struct: content, content_type, destination_path, file_mode, owner, group
- `fetch_app_config()`: Retrieve app configuration from Vault KV v2
- `store_app_config()`: Store app configuration in Vault
- `list_app_configs()`: List all app configurations for a deployment
- `delete_app_config()`: Remove app configuration from Vault
- `fetch_all_app_configs()`: Batch fetch all configs for a deployment
- Path template: `{prefix}/{deployment_hash}/apps/{app_name}/config`

#### New Stacker Commands (`commands/stacker.rs`)
- `FetchConfig` / `stacker.fetch_config`: Fetch app config from Vault
  - Parameters: deployment_hash, app_code, apply (optional - write to disk)
  - Returns config content, metadata, and destination path
- `ApplyConfig` / `stacker.apply_config`: Apply config to running container
  - Fetches config from Vault
  - Writes to specified destination path with file mode/owner settings
  - Optionally restarts container after config application
  - Supports `config_content` override to skip Vault fetch

#### Helper Functions
- `write_config_to_disk()`: Write config file with proper permissions (chmod, chown)

## 2026-01-22
### Added - Agent-Based App Deployment & Configuration Management

#### New Stacker Commands
- `stop` / `stacker.stop`: Gracefully stop a container with configurable timeout (1-300 seconds)
- `start` / `stacker.start`: Start a previously stopped container  
- `error_summary` / `stacker.error_summary`: Analyze container logs for error patterns
  - Categorizes errors (connection, timeout, memory, permission, database, network, auth)
  - Provides sample error messages (redacted for security)
  - Generates actionable recommendations based on error patterns

#### Docker Module Updates
- Added `docker::start()` function to start stopped containers
- Added `docker::stop_with_timeout()` for configurable graceful shutdown

#### Command Structs
- `StopCommand`: deployment_hash, app_code, timeout (default 30s)
- `StartCommand`: deployment_hash, app_code
- `ErrorSummaryCommand`: deployment_hash, app_code (optional), hours (1-168), redact

## Unreleased - 2026-01-09
- Added `health`, `logs`, and `restart` command handling with structured responses, log cursors, secret redaction, and Docker-backed execution paths.
- Expanded `CommandResult` metadata (deployment_hash, app_code, command_type, structured errors) to align `/api/v1/agent/commands/report` payloads with the Stacker integration schema.
- Known issue: containerized `status` binary fails to start on hosts with glibc versions older than 2.39; rebuild against the production base image or ship a musl-linked binary to restore compatibility.
- Changed: Docker builds now produce a statically linked musl binary (Dockerfile, Dockerfile.prod) to avoid glibc drift at runtime.
- Planned: align build and runtime images to avoid glibc drift; keep the musl-based build variant as the default container target.
- Planned: update CI to build and test using the production base image so linker/runtime errors are caught early.
- Planned: add a container startup smoke check to surface missing runtime dependencies before release.
