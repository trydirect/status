---
goal: Project-Derived Remote Runtime Paths Across TryDirect Deployment Repositories
version: 1.0
date_created: 2026-05-27
last_updated: 2026-05-27
owner: Copilot
status: Planned
tags: [feature, deployment, multi-project, stacker, install, status, contracts]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

Implement project-derived remote runtime paths so multiple Stacker projects can safely share one server without overwriting the fixed `/home/trydirect/project` runtime directory. The implementation must derive the remote directory from a sanitized project identity, propagate that directory through Stacker server/CLI/agent payloads, update install-service normalization, update status-agent assumptions, and refresh shared contracts and documentation.

## 1. Requirements & Constraints

- **REQ-001**: WHEN a cloud or server deployment is created for a project with `project.identity`, THE SYSTEM SHALL use `/home/trydirect/<sanitized-project-identity>` as the project runtime directory.
- **REQ-002**: WHEN `project.identity` is absent and `name` is present, THE SYSTEM SHALL use `/home/trydirect/<sanitized-name>` as the project runtime directory.
- **REQ-003**: WHEN neither a usable identity nor name is available, THE SYSTEM SHALL preserve legacy fallback behavior by using `/home/trydirect/project`.
- **REQ-004**: THE SYSTEM SHALL derive `docker-compose.yml` and `.env` paths from one canonical remote runtime directory helper instead of duplicating string formatting.
- **REQ-005**: THE SYSTEM SHALL expose the resolved runtime directory, compose path, and env path consistently in CLI explain, MCP explain, deployment state, deployment plan, and config output surfaces.
- **REQ-006**: THE SYSTEM SHALL pass the resolved remote project directory to install-service so install-time file placement matches Stacker's advertised paths.
- **REQ-007**: THE SYSTEM SHALL update Status Panel agent code and tests so remote config drift/env matching accepts project-derived runtime paths.
- **REQ-008**: THE SYSTEM SHALL update shared AI/API contract fixtures so clients observe project-derived runtime paths where sample project identity/name is known.
- **REQ-009**: THE SYSTEM SHALL keep platform-managed services outside project directories; Status Panel and Nginx Proxy Manager paths remain `/home/trydirect/statuspanel` and `/home/trydirect/nginx_proxy_manager` unless a separate feature changes them.
- **SEC-001**: Path derivation SHALL use an allow-list sanitizer that prevents path traversal, absolute path injection, shell metacharacter injection, dot-directory names, and reserved Unix directory names.
- **SEC-002**: User-controlled project names SHALL never be concatenated into shell commands without argument-safe handling in `install` and deployment scripts.
- **SEC-003**: The migration SHALL NOT move or delete existing remote runtime directories automatically unless an explicit migration command or confirmed migration mode is introduced.
- **CON-001**: Current Stacker helpers in `src/helpers/env_path.rs` return fixed paths `/home/trydirect/project/.env` and `/home/trydirect/project/docker-compose.yml`.
- **CON-002**: Current install-service code in `/Users/vasilipascal/work/try.direct/install/app/Ansible.py` defaults `DEFAULT_REMOTE_PROJECT_DIR` to `/home/trydirect/project`.
- **CON-003**: Current Status Panel code and recovery documentation include `/home/trydirect/project` assumptions.
- **CON-004**: Current shared contracts in `/Users/vasilipascal/work/try.direct/config-ai-state/shared-fixtures/api-contracts/` hard-code fixed runtime paths.
- **GUD-001**: Prefer one canonical sanitizer implementation per language boundary and test it with the same fixture cases.
- **GUD-002**: Preserve backwards compatibility for existing deployments whose state reports `/home/trydirect/project` until they are redeployed or explicitly migrated.
- **PAT-001**: Use `project.identity` before `name` because identity is the stable server-side project key used by remote lookups.
- **PAT-002**: Use pure path helpers for path construction, with tests that do not require a live server or database.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Add canonical project-derived runtime path helpers in `stacker`.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | In `/Users/vasilipascal/work/try.direct/stacker/src/helpers/env_path.rs`, replace fixed-only helpers with `remote_runtime_project_dir(project_key: Option<&str>) -> String`, `remote_runtime_env_path_for_project(project_key: Option<&str>) -> String`, and `remote_runtime_compose_path_for_project(project_key: Option<&str>) -> String`. Keep legacy zero-argument wrappers only if needed for compatibility and make them call the new helpers with `None`. | | |
| TASK-002 | In `/Users/vasilipascal/work/try.direct/stacker/src/helpers/env_path.rs`, use the existing Rust sanitizer from `/Users/vasilipascal/work/try.direct/stacker/src/models/project.rs::sanitize_project_name` or extract a shared equivalent so path names use the same safe rules as project deploy directories. | | |
| TASK-003 | Add unit tests in `/Users/vasilipascal/work/try.direct/stacker/src/helpers/env_path.rs` for inputs `status-web`, `Status Web`, `../evil`, `/tmp/app`, `root`, empty string, and `None`. Expected fallback for `None` and empty string is `/home/trydirect/project`; expected sanitized names must not contain `/`, `..`, or whitespace. | | |
| TASK-004 | In `/Users/vasilipascal/work/try.direct/stacker/src/configuration.rs`, ensure `DeploymentSettings::deploy_dir(name)` either receives sanitized names only or sanitizes internally. Add or update tests proving `deploy_dir("../evil")` cannot escape `config_base_path`. | | |

### Implementation Phase 2

- GOAL-002: Thread the resolved project key through Stacker runtime rendering and state surfaces.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-005 | In `/Users/vasilipascal/work/try.direct/stacker/src/services/config_renderer.rs`, replace `remote_runtime_env_path()` calls that render project-level runtime env files with `remote_runtime_env_path_for_project(Some(project_key))`. Use `project.identity` when available, then `project.name`, then legacy fallback. | | |
| TASK-006 | In `/Users/vasilipascal/work/try.direct/stacker/src/services/deployment_state.rs`, populate `DeploymentRuntimeState.compose_path` and `DeploymentRuntimeState.env_path` from project-derived helpers when project metadata/name is available. Preserve fixed fallback only for old records without project identity/name. | | |
| TASK-007 | In `/Users/vasilipascal/work/try.direct/stacker/src/services/deploy_plan.rs`, replace hard-coded sample/runtime paths with helper-derived paths. Update tests to use a sample project key such as `status-web` and expect `/home/trydirect/status-web/...`. | | |
| TASK-008 | In `/Users/vasilipascal/work/try.direct/stacker/src/services/explain.rs`, update env/topology explanation outputs to use project-derived helper paths. Add tests for both project-derived paths and legacy fallback. | | |
| TASK-009 | In `/Users/vasilipascal/work/try.direct/stacker/src/console/commands/cli/explain.rs` and `/Users/vasilipascal/work/try.direct/stacker/src/console/commands/cli/config.rs`, pass the resolved config project key into runtime path helpers before printing `remote_runtime_env_file`, `runtimeEnvPath`, or `runtimeComposePath`. | | |
| TASK-010 | In `/Users/vasilipascal/work/try.direct/stacker/src/mcp/tools/explain.rs` and `/Users/vasilipascal/work/try.direct/stacker/src/mcp/tools/deployment.rs`, update default runtime path construction to use project-derived helpers when the MCP request can resolve project/deployment identity. Preserve legacy fallback when identity is unavailable. | | |

### Implementation Phase 3

- GOAL-003: Update Stacker deploy payloads so install-service receives the same remote project directory.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-011 | In `/Users/vasilipascal/work/try.direct/stacker/src/cli/install_runner.rs`, compute `remote_project_dir` from the resolved remote project name before creating install/deploy payloads. Use `project.identity` first, then `name`, then fallback. | | |
| TASK-012 | In `/Users/vasilipascal/work/try.direct/stacker/src/cli/stacker_client.rs`, include `remote_project_dir`, `runtime_compose_path`, and `runtime_env_path` in cloud/server deploy payload custom metadata if the install-service API currently accepts arbitrary custom fields. If not accepted, add a typed field in the request model before use. | | |
| TASK-013 | Add Rust tests in `/Users/vasilipascal/work/try.direct/stacker/src/cli/install_runner.rs` and `/Users/vasilipascal/work/try.direct/stacker/src/cli/stacker_client.rs` proving a project identity `status-web` sends `/home/trydirect/status-web` to install-service and still sends `/home/trydirect/project` when identity/name are absent. | | |
| TASK-014 | Update deployment lock and handoff rendering only if they display runtime paths. Do not write derived runtime paths into local `stacker.yml` unless a separate explicit persist flag is added. | | |

### Implementation Phase 4

- GOAL-004: Update `install` repository runtime placement.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-015 | In `/Users/vasilipascal/work/try.direct/install/app/Ansible.py`, keep `DEFAULT_REMOTE_PROJECT_DIR = "/home/trydirect/project"` as a fallback but add `resolve_remote_project_dir(payload: Dict[str, Any]) -> str` that reads `remote_project_dir`, validates it is under `/home/trydirect/`, and rejects `..`, empty path segments, and absolute paths outside the base. | | |
| TASK-016 | In `/Users/vasilipascal/work/try.direct/install/app/Ansible.py`, update `normalize_remote_config_destination` and every compose/env upload path caller to use `resolve_remote_project_dir(payload)` instead of the default fixed directory when Stacker provides `remote_project_dir`. | | |
| TASK-017 | In `/Users/vasilipascal/work/try.direct/install/tests/test_ssh_key_resolution.py` or a new install test file, add tests for `remote_project_dir=/home/trydirect/status-web`, missing `remote_project_dir`, malicious `remote_project_dir=/tmp/evil`, and malicious `remote_project_dir=/home/trydirect/../evil`. | | |
| TASK-018 | Run the install repository's Python test command documented in that repo. If no documented command exists, run the smallest existing pytest target that covers `Ansible.py` path normalization. | | |

### Implementation Phase 5

- GOAL-005: Update `status` repository agent assumptions and recovery documentation.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-019 | In `/Users/vasilipascal/work/try.direct/status/src/commands/stacker.rs`, replace fixed env path assumptions with logic that accepts project-derived `.env` destinations. Keep tests for the fixed legacy path and add tests for `/home/trydirect/status-web/.env`. | | |
| TASK-020 | In `/Users/vasilipascal/work/try.direct/status/docs/APP_DEPLOYMENT.md`, replace fixed path wording with `<remote_project_dir>` examples and state that default legacy deployments may still use `/home/trydirect/project`. | | |
| TASK-021 | In `/Users/vasilipascal/work/try.direct/status/web/docs/recover-paused-deployment.md`, update recovery commands to first discover `remote_project_dir` from deployment state or compose path before using `cd`. Keep `/home/trydirect/project` only as a legacy example. | | |
| TASK-022 | Run the status repository's Rust test target for `src/commands/stacker.rs` or the smallest documented test command that covers Stacker command config handling. | | |

### Implementation Phase 6

- GOAL-006: Update shared contracts, fixtures, and documentation.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-023 | In `/Users/vasilipascal/work/try.direct/config-ai-state/shared-fixtures/api-contracts/stacker-explain-topology.v1alpha1.json`, update `runtimeComposePath` and `runtimeEnvPath` to `/home/trydirect/status-web/docker-compose.yml` and `/home/trydirect/status-web/.env` if the fixture represents project `status-web`; otherwise add a `projectName`/`projectIdentity` fixture field before changing paths. | | |
| TASK-024 | In `/Users/vasilipascal/work/try.direct/config-ai-state/shared-fixtures/api-contracts/stacker-explain-env.v1alpha1.json`, update `runtimeEnvPath`, `runtimeComposePath`, and destination `path` to the project-derived path used by the fixture. | | |
| TASK-025 | In `/Users/vasilipascal/work/try.direct/config-ai-state/shared-fixtures/api-contracts/stacker-deployment-state.v1alpha1.offline.json` and `stacker-deployment-state.v1alpha1.online.json`, update `composePath` and `envPath` to project-derived paths and preserve schema field names. | | |
| TASK-026 | In `/Users/vasilipascal/work/try.direct/tools/docs/CustomStackMapper.md`, update examples from `/home/trydirect/project/docker-compose.yml` to `/home/trydirect/<sanitized-project>/docker-compose.yml` and describe `/home/trydirect/project` as legacy fallback only. | | |
| TASK-027 | In `/Users/vasilipascal/work/try.direct/stacker/README.md`, `/Users/vasilipascal/work/try.direct/stacker/docs/STACKER_YML_REFERENCE.md`, and `/Users/vasilipascal/work/try.direct/stacker/docs/APP_DEPLOYMENT.md`, document that remote runtime files now live under `/home/trydirect/<sanitized-project-identity-or-name>/`. | | |
| TASK-028 | Update Stacker contract fixtures in `/Users/vasilipascal/work/try.direct/stacker/tests/contracts/` and AI fixtures in `/Users/vasilipascal/work/try.direct/stacker/tests/fixtures/ai/` to match the new project-derived paths. | | |

### Implementation Phase 7

- GOAL-007: Validate end-to-end multi-project behavior and compatibility.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-029 | In `stacker`, run `SQLX_OFFLINE=true cargo test --offline --lib -- --color=always --test-threads=1 --nocapture` and `SQLX_OFFLINE=true cargo test --offline --bin stacker-cli -- --color=always --nocapture`. | | |
| TASK-030 | In `stacker`, run `SQLX_OFFLINE=true cargo build --offline` and `make style-check`. Run `make lint`; if it still fails with existing SQLx `E0282` errors, capture the log and verify no new runtime-path files are listed in the errors. | | |
| TASK-031 | In `install`, run the Python test command selected in TASK-018 and record the exact command and result in the implementation notes or pull request. | | |
| TASK-032 | In `status`, run the Rust test command selected in TASK-022 and record the exact command and result in the implementation notes or pull request. | | |
| TASK-033 | Perform a local dry-run or mocked payload test for two projects named `site-a` and `site-b` targeting one server. Verify generated runtime directories are `/home/trydirect/site-a` and `/home/trydirect/site-b`, with no writes to each other's `.env` or `docker-compose.yml` paths. | | |

## 3. Alternatives

- **ALT-001**: Keep `/home/trydirect/project` and document that one server supports only one normal project. Rejected because it contradicts multi-project server reuse and creates overwrite risk.
- **ALT-002**: Add a user-configurable `deploy.remote_dir` in `stacker.yml` and require users to set it manually. Rejected as the primary solution because safe defaults should isolate projects automatically; a future override can be added separately with strict validation.
- **ALT-003**: Use deployment hash as the remote directory name. Rejected for the default because it is less human-readable and makes direct SSH operations harder; deployment hash can remain a fallback for anonymous legacy records if needed.
- **ALT-004**: Update only Stacker docs and leave runtime code unchanged. Rejected because the bug is actual path collision risk, not documentation-only.

## 4. Dependencies

- **DEP-001**: `/Users/vasilipascal/work/try.direct/stacker` must be updated first because it owns project identity resolution, runtime path reporting, MCP surfaces, and deploy payload generation.
- **DEP-002**: `/Users/vasilipascal/work/try.direct/install` must be updated before production rollout because it writes files on the remote server.
- **DEP-003**: `/Users/vasilipascal/work/try.direct/status` must be updated before relying on project-derived env/config paths in agent operations and docs.
- **DEP-004**: `/Users/vasilipascal/work/try.direct/config-ai-state` shared fixtures must be updated after API output shapes and sample values are finalized.
- **DEP-005**: `/Users/vasilipascal/work/try.direct/tools` docs must be updated after install-service path semantics are finalized.
- **DEP-006**: Existing Stacker lint baseline has unrelated SQLx `E0282` failures; validation must distinguish those from new runtime path errors.

## 5. Files

- **FILE-001**: `/Users/vasilipascal/work/try.direct/stacker/src/helpers/env_path.rs` — canonical path helpers and sanitizer tests.
- **FILE-002**: `/Users/vasilipascal/work/try.direct/stacker/src/models/project.rs` — sanitizer reuse or deploy-dir hardening.
- **FILE-003**: `/Users/vasilipascal/work/try.direct/stacker/src/configuration.rs` — deployment base path/deploy_dir hardening.
- **FILE-004**: `/Users/vasilipascal/work/try.direct/stacker/src/services/config_renderer.rs` — runtime env destination paths.
- **FILE-005**: `/Users/vasilipascal/work/try.direct/stacker/src/services/deployment_state.rs` — deployment runtime path output.
- **FILE-006**: `/Users/vasilipascal/work/try.direct/stacker/src/services/deploy_plan.rs` — deployment plan runtime paths and samples.
- **FILE-007**: `/Users/vasilipascal/work/try.direct/stacker/src/services/explain.rs` — topology/env explanation paths.
- **FILE-008**: `/Users/vasilipascal/work/try.direct/stacker/src/console/commands/cli/explain.rs` — CLI explain paths.
- **FILE-009**: `/Users/vasilipascal/work/try.direct/stacker/src/console/commands/cli/config.rs` — CLI config output paths.
- **FILE-010**: `/Users/vasilipascal/work/try.direct/stacker/src/mcp/tools/explain.rs` — MCP explain paths.
- **FILE-011**: `/Users/vasilipascal/work/try.direct/stacker/src/mcp/tools/deployment.rs` — MCP deployment state paths.
- **FILE-012**: `/Users/vasilipascal/work/try.direct/stacker/src/cli/install_runner.rs` — deploy context payload runtime directory.
- **FILE-013**: `/Users/vasilipascal/work/try.direct/stacker/src/cli/stacker_client.rs` — cloud/server deploy payload metadata.
- **FILE-014**: `/Users/vasilipascal/work/try.direct/install/app/Ansible.py` — install-service remote project directory normalization.
- **FILE-015**: `/Users/vasilipascal/work/try.direct/install/tests/test_ssh_key_resolution.py` or new install test file — install-service path validation tests.
- **FILE-016**: `/Users/vasilipascal/work/try.direct/status/src/commands/stacker.rs` — status-agent env destination handling tests/logic.
- **FILE-017**: `/Users/vasilipascal/work/try.direct/status/docs/APP_DEPLOYMENT.md` — status documentation.
- **FILE-018**: `/Users/vasilipascal/work/try.direct/status/web/docs/recover-paused-deployment.md` — recovery documentation.
- **FILE-019**: `/Users/vasilipascal/work/try.direct/config-ai-state/shared-fixtures/api-contracts/*.json` — shared API fixtures.
- **FILE-020**: `/Users/vasilipascal/work/try.direct/tools/docs/CustomStackMapper.md` — tools documentation.
- **FILE-021**: `/Users/vasilipascal/work/try.direct/stacker/tests/contracts/*.json` — Stacker contract fixtures.
- **FILE-022**: `/Users/vasilipascal/work/try.direct/stacker/tests/fixtures/ai/*.json` — Stacker AI fixtures.
- **FILE-023**: `/Users/vasilipascal/work/try.direct/stacker/README.md` — Stacker overview documentation.
- **FILE-024**: `/Users/vasilipascal/work/try.direct/stacker/docs/STACKER_YML_REFERENCE.md` — Stacker config reference.
- **FILE-025**: `/Users/vasilipascal/work/try.direct/stacker/docs/APP_DEPLOYMENT.md` — Stacker deployment design documentation.

## 6. Testing

- **TEST-001**: Unit test Rust sanitizer/path helper outputs for safe names, malicious names, empty names, and legacy fallback.
- **TEST-002**: Unit test Stacker config rendering writes project-level `.env` to `/home/trydirect/status-web/.env` for project `status-web`.
- **TEST-003**: Unit test deployment state and explain outputs report `/home/trydirect/status-web/docker-compose.yml` and `/home/trydirect/status-web/.env`.
- **TEST-004**: Unit test Stacker deploy payload includes `remote_project_dir=/home/trydirect/status-web`.
- **TEST-005**: Unit test install-service rejects remote project directories outside `/home/trydirect`.
- **TEST-006**: Unit test install-service defaults to `/home/trydirect/project` when the new field is absent.
- **TEST-007**: Unit test Status Panel env config detection accepts `/home/trydirect/status-web/.env`.
- **TEST-008**: Contract tests compare updated `config-ai-state` fixtures and Stacker fixtures against runtime output.
- **TEST-009**: CLI tests verify `stacker explain` and `stacker config show` expose project-derived paths.
- **TEST-010**: Dry-run or mocked deploy test verifies two projects on one server resolve distinct runtime directories.

## 7. Risks & Assumptions

- **RISK-001**: Existing deployments already running in `/home/trydirect/project` may be orphaned if redeploy immediately switches to a new path without migration guidance.
- **RISK-002**: Install-service may ignore unknown payload fields; TASK-012 and TASK-015 must verify the API boundary before rollout.
- **RISK-003**: AI/MCP clients may have cached contract fixtures that expect fixed runtime paths.
- **RISK-004**: Some docs use `/home/trydirect/project` as an example path; updating all examples at once may obscure legacy recovery steps.
- **RISK-005**: If sanitizer behavior differs between Rust and Python, Stacker may advertise one path while install-service writes another.
- **ASSUMPTION-001**: `project.identity` is the preferred stable runtime directory key when present.
- **ASSUMPTION-002**: `/home/trydirect/project` must remain as legacy fallback for older deployments and missing identity/name cases.
- **ASSUMPTION-003**: Platform-managed Status Panel and Nginx Proxy Manager directories are outside this change.
- **ASSUMPTION-004**: No database migration is required if runtime paths are computed from project identity/name at render time and exposed in state responses.

## 8. Related Specifications / Further Reading

- `/Users/vasilipascal/work/try.direct/stacker/src/helpers/env_path.rs`
- `/Users/vasilipascal/work/try.direct/install/app/Ansible.py`
- `/Users/vasilipascal/work/try.direct/status/src/commands/stacker.rs`
- `/Users/vasilipascal/work/try.direct/config-ai-state/shared-fixtures/api-contracts/`
- `/Users/vasilipascal/work/try.direct/stacker/docs/APP_DEPLOYMENT.md`
- `/Users/vasilipascal/work/try.direct/status/docs/APP_DEPLOYMENT.md`
