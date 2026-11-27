# FEATURES

## Feature: native `backup` agent command (WS-1, bridge to the backup storage)

**Status:** agent side implemented (2026-11-26, this repo — see
[Implementation notes](#implementation-notes-agent-side) at the bottom).
**Owner:** status-panel agent. **Plan:** `config/PLAN-backups.md`.
**Contract (source of truth):** `config/shared-fixtures/api-contracts/backups-storage.json`
(`DumpPlan`, `RestorePlan`, `UploadBody`, `Auth`, `UploadTarget`, `DownloadTarget`, `BackupCommand`).
Both paths are in the `config` repo; the files currently live on its `docs/backups-cleanup`
branch and land at these paths once that merges.

### Goal

Give the Status Panel agent a first-class `backup` command that Stacker queues through
the existing command queue. The agent executes a dump/restore and streams the archive to
a **pluggable** backup-storage backend over its native HTTP client (reqwest). No shell
command strings, no embedded credentials.

This is the bridge that connects Stacker's backup orchestration (already merged:
`backup-core` builds typed plans, Stacker enqueues a `backup` command) to the
backup-storage upload API that was verified end-to-end.

### How it fits today

Stacker builds a plan and queues one command of `type: "backup"`:

```json
{
  "action": "dump",              // or "restore"
  "run_id": 123,                 // backup_run.id; correlate your report back to it
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
}
```

The plan is pure data. The agent interprets it generically so the backend stays
pluggable (a REST backup service today, a restic / S3 target tomorrow).

---

## What to build

### 1. Command plumbing (follow the existing pattern)

Line references below are current as of `dev@d15dbe4`; trust the function names when they drift.

- Add `Backup(BackupCommand)` to `StackerCommand` in `src/commands/stacker.rs`.
- Parse it in `parse_stacker_command` for `type: "backup" | "stacker.backup"` (mirror
  how `"exec"` is parsed at `src/commands/stacker.rs:2205`). Deserialize params into:
  ```rust
  struct BackupCommand { action: Dump|Restore, run_id: i32, plan: Plan }
  ```
  where `Plan` is an untagged/`action`-selected `DumpPlan | RestorePlan`.
  `run_id` is **required** — the contract types it as `integer (backup_run.id)` and it is
  the correlation key for the `backup_run` row; a command without it must be rejected.
- Dispatch in `execute_stacker_command` (near `StackerCommand::Exec(data) => handle_exec`,
  `src/commands/stacker.rs:3792`) to `handle_backup(agent_cmd, data)`.
- Reuse `base_result` (`src/commands/stacker.rs:3438`) for the `CommandResult` envelope and
  the existing report path in `src/agent/daemon.rs:execute_and_report`.

### 2. Execute the process (`argv`)

- Run `plan.argv` as a **child process** with `tokio::process::Command` (see
  `src/commands/executor.rs` for the existing child/stream handling and
  `src/commands/timeout.rs` for the timeout strategy).
- **Dump:** stream the child's `stdout` to the upload target. **Restore:** stream the
  download body into the child's `stdin` (use `-i`/interactive argv already in the plan).
- Do **not** run argv through a shell. The plan already carries `["docker","exec",...]` /
  `["docker","run",...]` as discrete args.
- Honour the command timeout; on timeout kill the child and report `status: "timeout"`.

### 3. Storage protocol (interpret `UploadTarget` / `DownloadTarget` generically)

Build the HTTP request from the plan's data, not from hardcoded values:

- **Body (`UploadBody`)**
  - `raw`: the archive stream is the request body.
  - `multipart { file_field, fields }`: `multipart/form-data` with the archive in
    `file_field` and literal `fields`.
  - **Stream, never buffer.** The archive can be many GB: `raw` pipes the child's stdout
    straight into the request body; for `multipart` use `reqwest::multipart::Part::stream`
    (its default `Part` buffers a part in memory). Decide Content-Length vs chunked
    encoding against the storage contract when implementing.
  - Field values and header values may reference env vars (`$AGENT_ID`, `$BACKUP_FILENAME`,
    …) — resolve them from your environment at run time. `$AGENT_ID` is **your own
    `agent_id`** (from registration, `src/agent/registration.rs:60`) — this is the
    `device_id` the storage uses to scope the archive. Do **not** use `deployment_hash`
    for this.
  - **Resolve only the declared allowlist:** `AGENT_ID`, `BACKUP_*` (see the environment
    table below), the env names the plan's own `Auth` block references (`*_env` fields),
    and `$BACKUP_FILENAME` (the archive filename the agent generates for this run).
    Any other `$VAR` found in a plan value must **fail the command** with a redacted
    error — the plan is data from the queue and unrestricted `$ENV` resolution is an
    exfiltration channel (a crafted plan could move `$VAULT_TOKEN` into a header sent to
    a plan-controlled `url`/`token_url`).
- **Auth (`Auth`)**
  - `none`.
  - `bearer { token_env }`: `Authorization: Bearer <value of $token_env>`.
  - `client_credentials { token_url, client_id_env, client_secret_env, scope? }`:
    `POST token_url` with `grant_type=client_credentials` (+ optional `scope`) using the
    client id/secret from env → `access_token` → `Authorization: Bearer <access_token>`.
    Cache the token per run; refresh on 401. (This is how the backup-storage service
    account authenticates.)
  - `basic { username_env, password_env }`: HTTP Basic from env.
- **Headers:** send `plan.upload.headers` on upload and `plan.download.headers` on
  restore (per `UploadTarget`/`DownloadTarget` in the contract; resolve `$ENV` in
  values). Reject any header name/value containing CR/LF (defence against header
  injection).

### 4. Report the result

Return a `CommandResult` (see `src/transport/mod.rs:21`) via the existing report path:

- `status`: `"success"` | `"failed"` | `"timeout"`.
- `result` (JSON), for a dump: `{ "run_id", "size_bytes", "checksum", "remote_file_id" }`.
  - `size_bytes`: bytes streamed.
  - `checksum`: SHA-256 of the archive (you already have `sha2`; `src/agent/backup.rs`
    `BackupSigner` shows the HMAC/hash style if useful).
  - `remote_file_id`: the file id the storage returns from the upload (e.g. the archive
    basename / `file_id` in the upload response — see the storage contract).
- `error`: a redacted message on failure (never include tokens/credentials). Do not
  invent a third redaction mechanism — run error/detail strings through `redact_message`
  (`src/commands/stacker.rs:3481`) and rely on the transport layer for bodies: `/wait`
  payloads are already logged as a summary only (`command_body_summary`,
  `src/transport/http_polling.rs:227`) and `report_result` bodies pass
  `redact_sensitive_values`/`is_sensitive_log_key` (`src/transport/http_polling.rs:186-206`).
- On a **failure mid-upload**, still report `size_bytes` streamed and any `remote_file_id`
  the storage returned, so Stacker/storage can clean the partial file up (the storage
  contract exposes `DELETE /upload/files/{file_id}`); mark the run `failed` either way.

Stacker keys the `backup_run` row off `run_id` and the reported `remote_file_id` for later
restore/retention.

### 5. Restore

For `action: "restore"`: GET `plan.download.url` (same `Auth` + `plan.download.headers`)
and stream the body into the restore process's `stdin`. Report success/bytes restored.
**Integrity note:** `DownloadTarget` carries no checksum and `backup_run.checksum` is not
in the plan, so the agent cannot verify the downloaded archive today — restore trusts the
download. Either pass the expected checksum in `RestorePlan` (contract change) or accept
this gap explicitly; do not silently claim verification.

---

## Non-negotiables

- **No secrets in logs or the command result.** Credentials are referenced by env-var
  *name* in the plan; resolve them into request headers/tokens only. Redact errors
  (see §4 for the existing helpers).
- **`$ENV` resolution is allowlisted.** Only the documented variables resolve (§3);
  anything else in a plan value fails the command. Never resolve arbitrary env names
  supplied by the plan.
- **No shell strings.** Execute `argv` directly (`tokio::process`), never `sh -c` on the
  host. (The plan may contain `sh -c '…'` as a single arg *inside* the target container —
  that is fine, it runs via `docker exec`.)
- **Generic:** do not special-case a particular storage vendor in the agent. Everything
  vendor-specific is already described by the plan (`UploadBody` / `Auth`).
- **Timeouts + cancellation** behave like other long-running commands (`executor.rs`).

## Environment the agent is expected to have

| Var | Meaning |
|---|---|
| `AGENT_ID` (or your registered `agent_id`) | `device_id` sent to storage |
| `BACKUP_CLIENT_ID` / `BACKUP_CLIENT_SECRET` | service-account creds for `client_credentials` |
| `BACKUP_TOKEN` | bearer token when `auth: bearer` |
| `$BACKUP_FILENAME` | not an env var — agent-derived: the archive filename generated for this run (e.g. `run-<run_id>-<utc timestamp>`), resolvable in headers/fields |

Provisioning of these (Vault → agent env) is handled on the Stacker side; the agent just
reads them from its environment.

## Testing

- Unit: parse a `backup` command (incl. rejecting a missing `run_id`); multipart body
  construction from `UploadBody`; auth header construction for each `Auth` variant;
  `$ENV` resolution incl. allowlist rejection of unknown vars; CR/LF rejection.
- Integration (mock the storage with `mockito`, the mock library this repo already uses;
  `wiremock` belongs to the stacker repo, not here): end-to-end
  dump streams to a mocked `POST /upload` and reports `size_bytes`/`checksum`/
  `remote_file_id`; `client_credentials` token exchange is exercised; restore streams a
  mocked download into the process.
- Add fixtures under the existing test layout; run `cargo test` / the repo's CI gate.

## Out of scope

- Scheduling (Stacker owns it).
- Retention/pruning of stored archives (Stacker + storage own it).
- Point-in-time restore (the storage keeps current state only).

---

## Implementation notes (agent side)

Implemented in `src/commands/backup.rs` (plan types mirroring the `backup-core`
wire format, `$ENV` allowlist, auth, streaming) and wired into
`src/commands/stacker.rs` (variant `Backup(BackupCommand)`, parse arm
`"backup" | "stacker.backup"`, dispatch on both the `docker` and `minimal`
paths). Tests: unit in `src/commands/backup.rs` (19), integration with mockito
in `tests/backup_command.rs` (7). Both feature configurations pass
`cargo test`, `cargo fmt --check` and `cargo clippy -- -D warnings`.

### Interop gaps found on the Stacker side (branch `feature/backup-agent-queue`)

1. **Restore commands are queued without `run_id`.** `restore_command_params`
   (`stacker/src/services/backup.rs:113-118`) builds
   `{"action":"restore","plan":…}` only, while the contract types
   `BackupCommand.run_id` as required. The agent rejects such commands (per §1
   above), so **restore will fail end-to-end until Stacker sends the id of the
   run being restored**. The report handler correlates `backup_run` through
   `command.parameters.run_id` (`stacker/src/routes/agent/report.rs:313-347`)
   and the BDD fixture expects "the run is marked 'restored'" — both need that
   id in the restore envelope too.
2. **`status: "timeout"` maps to *Completed* on Stacker** unless `errors` is
   non-empty: `stacker/src/routes/agent/report.rs:75-90` classifies only
   `"failed"` or a non-empty `errors` list as Failed. The agent therefore
   always fills `errors` on failed/timeout runs.
3. **The run lifecycle reads the failure message from `result.error`**
   (`stacker/src/routes/agent/report.rs:334`), not `CommandResult.error`, so
   the redacted message is placed in the result body as well.
4. `validate_command_result` passes `backup` results through unchanged
   (`stacker/src/forms/status_panel.rs:963`), so the result keys reach the
   lifecycle as defined in §4.

### Decisions taken while implementing

- **`$ENV` resolution covers header values and multipart field values only,
  never `argv`** — plans legitimately embed container-side scripts containing
  `$POSTGRES_DB` (`stacker/crates/backup-core/src/lib.rs:179`, in-container
  `sh -c`). URLs are passed through verbatim.
- **Timeout:** optional `timeout` (seconds) param on the command; fallback
  `COMMAND_TIMEOUT_SECS`; default 3600s (backups stream GB; the daemon's 300s
  shell default is too short), capped at 24h. On expiry the child gets
  SIGTERM → 5s grace → SIGKILL (executor.rs parity) and the run reports
  `status: "timeout"` with the bytes streamed so far.
- **`client_credentials`** sends form-encoded `grant_type`/`client_id`/
  `client_secret` (+`scope`) — mirroring the verified exchange in
  `stacker/src/services/storage.rs:47-79`. Token cached per run; on 401 the
  cache is dropped and the *download* leg retries once. The upload leg streams
  a child's stdout and cannot be replayed, so a 401 mid-upload fails the run
  with the partial stats.
- **Body encoding:** `raw` is sent as `application/octet-stream` with chunked
  transfer (size unknown upfront; the upload server supports chunked bodies).
  Both legs stream through `reqwest::Body::wrap_stream` /
  `reqwest::multipart::Part::stream` — the archive is never buffered.
- **`checksum`** is the lowercase hex SHA-256 of the archive bytes streamed.
- **`remote_file_id`** is parsed from the upload response JSON
  (`file_id`/`remote_file_id`/`id`/`file_name`/`filename`, incl. `item`/`data`
  wrappers) and falls back to the generated filename (the contract's "archive
  basename" form).
- **A non-zero exit of the dump process after a successful upload fails the
  run** and still reports `remote_file_id`, so the invalid archive can be
  deleted via `DELETE /upload/files/{file_id}`.
- **Restore integrity gap accepted explicitly**: the result carries
  `"integrity_verified": false` (no silent verification claim), per §5.
- **`$AGENT_ID`** resolves from the `AGENT_ID` environment variable (the
  registered `agent_id`, `src/agent/daemon.rs:87`); if unset, the command
  fails rather than substituting anything. `deployment_hash` is never used.
- **`$BACKUP_FILENAME`** is generated as `run-<run_id>-<UTC yyyymmddTHHMMSSZ>`.

---

## Feature: native `sandbox` agent command (WS-S, ephemeral containers for untrusted/AI code)

**Status:** to implement. **Owner:** status-panel agent. **Plan:** `config/PLAN-sandboxes.md`.
**Contract (source of truth):** `config/shared-fixtures/api-contracts/sandboxes.json`
(`SandboxCommand`, `resource`, `lifecycle`, `isolation`).

### Goal

Give the Status Panel agent a first-class `sandbox` command that Stacker queues
through the existing command queue. The agent runs short-lived, domain-less,
volume-less Docker containers for untrusted and AI-generated code:
`create -> exec/writeFile/readFile -> kill`, with CPU/RAM/PID limits and hard
isolation. Model is Dokploy's Sandboxes.

The sandbox lives wherever the agent is installed (user servers and TryDirect
hosts); the target server is chosen at create time (decision S1). The agent is
the only thing that touches Docker — Stacker just queues commands and tracks
state.

### How it fits today

Stacker enqueues one command of `type: "sandbox"` per operation. The payload is
`{action, sandboxId, ...}` where `action` selects the operation and the rest
carries the params Stacker built:

```json
{ "action": "create", "sandbox": { "id", "image", "runtime", "networkMode",
  "cpu", "memMb", "pidsLimit", "inactivityTimeoutSec", "maxLifetimeSec", ... } }
{ "action": "exec",  "sandboxId", "command", "timeoutSec", "maxOutputBytes" }
{ "action": "write_file", "sandboxId", "path", "contentBase64", "maxBytes" }
{ "action": "read_file",  "sandboxId", "path", "maxBytes" }
{ "action": "list_files", "sandboxId", "path" }
{ "action": "kill",   "sandboxId" }
```

Stacker marks the sandbox row (creating/running/killed/expired) and reaps it via
the lifecycle manager (inactivity + hard-lifetime). The agent owns the container.

---

## What to build

### 1. Command plumbing (follow the existing pattern)

- Add `Sandbox(SandboxCommand)` to `StackerCommand` in `src/commands/stacker.rs`.
- Parse it in `parse_stacker_command` for `type: "sandbox" | "stacker.sandbox"`
  (mirror how `"exec"` is parsed at `src/commands/stacker.rs:2205`). Deserialize
  `{action, sandboxId, ...}` into an action-tagged enum.
- Dispatch in `execute_stacker_command` to `handle_sandbox(agent_cmd, data)`
  (near `StackerCommand::Exec`, `src/commands/stacker.rs:3792`).
- Report via the existing `CommandResult` path (`src/agent/daemon.rs:
  execute_and_report`, `base_result` at `src/commands/stacker.rs:3438`).

### 2. `create` — run the container

- `docker run -d` the sandbox image with the contract's isolation (see §4).
- Name the container after `sandboxId` (or keep a `sandboxId -> container` map) so
  later exec/kill find it.
- Report the container id + `status: running`.

### 3. `exec` / file ops — run inside the container

- **exec:** `docker exec <container> sh -c <command>` with a per-call timeout
  (`timeoutSec`), capture `exitCode`, `stdout`, `stderr`. Cap collected output at
  `maxOutputBytes` (1 MiB). Kill the process on timeout.
- **write_file:** write `contentBase64` (base64) to `path` inside the container
  (cap `maxBytes`, 10 MiB). `docker exec ... sh -c 'cat > path'` piping the bytes,
  or `docker cp`.
- **read_file:** read `path`, return `{path, contentBase64}` (cap 10 MiB).
- **list_files:** list `path`, return `[{name, size, isDir}]`.
- **kill:** `docker rm -f` the container (idempotent — a missing container is a
  success).

### 4. Isolation (S3) — apply on `docker run`

- `--cap-drop=ALL --security-opt=no-new-privileges:true`.
- `--user=1000:1000` (non-root).
- `--pids-limit`, `--memory`, `--memory-swap` from the payload's `pidsLimit`/
  `memMb`.
- Network: `--network=<isolated>` by default (a dedicated bridge with **no
  access to project networks**); `none` allowed. Do not attach project networks.
- Runtime: `runc` (trusted) or `runsc` / gVisor (default for untrusted) via
  `--runtime=<runsc>` — register `runsc` once on the host (like kata).
- Env: the sandbox's env is write-only — never return it in any report.

### 5. Report the result

`CommandResult.result` (JSON):
- exec: `{ "exitCode", "stdout", "stderr", "sandboxId" }`.
- write_file: `{ "written": true, "path" }`.
- read_file: `{ "path", "contentBase64" }`.
- list_files: `{ "list": [{ "name", "size", "isDir" }] }`.
- create/kill: `{ "containerId", "status" }` / `{ "killed": true }`.
Errors: a redacted message (never env/secrets).

---

## Non-negotiables

- **No secrets in logs or results.** The sandbox env is write-only; never echo it.
- **Hard isolation** on every container (cap-drop all, no-new-privileges,
  non-root, isolated network, resource limits). Untrusted code must not reach
  project networks.
- **Timeouts + output caps**: per-call timeout on exec; 1 MiB exec output, 10 MiB
  file caps. Never unbounded.
- **Idempotent kill**: `kill` on an already-gone container succeeds.
- **Generic**: everything vendor/runtime-specific is in the payload (image,
  runtime, limits) — no sandbox-vendor special-casing.

## Environment / host prerequisites

| Thing | Meaning |
|---|---|
| `runsc` (gVisor) registered in Docker | `--runtime=runsc` works (one-time host setup, like kata) |
| `AGENT_ID` (your registered `agent_id`) | identifies the device if needed |
| Docker socket access | the agent already runs `docker` for containers |

## Testing

- Unit: parse a `sandbox` command; `docker run` argv assembly (isolation flags
  present: cap-drop, no-new-privileges, user 1000:1000, pids/mem limits, network);
  exec output capping; base64 file round-trip; kill idempotency.
- Integration (mock Docker or a test container): exec returns exitCode/stdout;
  write/read file round-trip; a killed sandbox is gone; env is never in a report.
- Fixtures: `config/shared-fixtures/features/sandboxes.feature` (6 acceptance
  scenarios) — wire them into `tests/features/` + `tests/steps/` where feasible.

## Out of scope

- Snapshot/pause (decision S2 — Dokploy has none either).
- Scheduling (Stacker owns the lifecycle manager).
- Multi-node placement (Stacker picks the server at create).
