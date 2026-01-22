# Changelog

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

