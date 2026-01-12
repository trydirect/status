# Changelog

## Unreleased - 2026-01-09
- Added Stacker `health`, `logs`, and `restart` command handling with structured responses, log cursors, secret redaction, and Docker-backed execution paths.
- Expanded `CommandResult` metadata (deployment_hash, app_code, command_type, structured errors) to align `/api/v1/commands/report` payloads with the Stacker integration schema.
- Known issue: containerized `status` binary fails to start on hosts with glibc versions older than 2.39; rebuild against the production base image or ship a musl-linked binary to restore compatibility.
- Changed: Docker builds now produce a statically linked musl binary (Dockerfile, Dockerfile.prod) to avoid glibc drift at runtime.
- Planned: align build and runtime images to avoid glibc drift; keep the musl-based build variant as the default container target.
- Planned: update CI to build and test using the production base image so linker/runtime errors are caught early.
- Planned: add a container startup smoke check to surface missing runtime dependencies before release.
