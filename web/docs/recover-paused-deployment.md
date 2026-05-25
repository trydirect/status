# Recovering from a paused Stacker deployment

Cloud deployment is not always a single clean step. A provider can reject a
server type, an installer task can fail, or Docker Compose can stop because a
runtime file is missing. A paused deployment should be treated as recoverable:
Stacker has usually created the server, recorded its IP address, and authorized a
backup SSH key.

## 1. Confirm the deployment state

Start by asking Stacker what it knows:

```bash
stacker status
stacker status --watch
```

If an AI agent is connected through MCP, it should start with the same recovery
sequence programmatically:

```text
diagnose_deployment -> get_deployment_events -> get_deployment_state
get_docker_compose_yaml -> list_containers -> get_container_logs
get_error_summary -> get_container_health
```

The MCP diagnosis response also includes safe `stacker-cli` commands to suggest
to the user when local confirmation or SSH access is required.

Look for four things in the output:

- deployment ID and status;
- server name and IP address;
- the last installer message;
- the backup SSH command printed by deploy.

If deploy authorized a backup key, the output looks like this:

```text
✓ Local SSH backup key authorized
  Key: ~/.config/stacker/ssh/server-87_ed25519
  Connect: ssh -i ~/.config/stacker/ssh/server-87_ed25519 -p 22 root@178.105.162.176
```

That SSH command is the emergency path for inspecting or fixing the server.

## 2. Classify the failure

Most paused deployments fall into one of these groups:

| Symptom | Likely cause | First action |
|---|---|---|
| Unsupported location for server type | Cloud region and size are incompatible | Update `deploy.cloud.region` or `deploy.cloud.size`, then redeploy with `--force-new` |
| Docker Compose reports a missing env file | Config bundle and compose paths do not match | Check the deploy output for `Config file: source -> destination` mappings |
| Image pull fails | Image is private or tag does not exist | Push the image or configure registry credentials |
| `failed to read dockerfile: open Dockerfile: no such file or directory` | Compose could not pull the image and fell back to remote build, but only runtime files were staged | Push the exact image tag referenced by compose, then redeploy |
| Container starts then exits | Application runtime error | SSH in and inspect `docker compose logs` |
| Watch timeout but status is still `in_progress` | Installer is still running | Continue with `stacker status --watch` |

Do not immediately destroy the server. If the server exists and SSH works, you
can usually inspect the exact failure and decide whether to patch the server,
fix local config, or redeploy.

## 3. Connect with the backup SSH key

Use the exact command Stacker printed. For example:

```bash
ssh -i ~/.config/stacker/ssh/server-87_ed25519 -p 22 root@178.105.162.176
```

After connecting, inspect the deployed project directory:

```bash
cd /home/trydirect/project
ls -la
docker compose config
docker compose ps
docker compose logs --tail=100
```

If Docker Compose says an env file is missing, check whether the file exists
where the compose file expects it:

```bash
grep -n "env_file" docker-compose.yml
find /home/trydirect/project -maxdepth 3 -type f -name ".env" -o -name "*.env"
```

In the Status walkthrough, Stacker generated a correct local bundle
(`Config file: .env -> .env`) but the installer initially copied only
`docker-compose.yml` to `/home/trydirect/project`. The durable fix is to patch
the Stacker deploy handoff so non-compose config files are also sent through the
installer runtime-file contract, then redeploy. Avoid manual server writes unless
the user explicitly chooses a temporary emergency fix.

## 4. Apply a safe temporary fix when needed

Prefer fixing `stacker.yml`, compose, or the Stacker-generated config bundle and
redeploying. A manual server edit is only a temporary recovery step.

If the fix is a file placement issue, copy or create the file in the path Docker
Compose expects, then restart the stack:

```bash
cp /home/trydirect/project/.env /home/trydirect/project/docker/production/.env
docker compose up -d
docker compose ps
```

Use the real paths from `docker-compose.yml`; do not blindly copy this example.
If the missing file contains secrets, recreate it from the local source of truth
or Stacker secrets instead of typing values into shell history.

## 5. Ask AI for a targeted recommendation

If AI is configured for the project, give it the non-secret failure context:

- the failing task name;
- the sanitized Docker Compose error;
- the relevant `env_file`, `image`, or `ports` section;
- the `Config file: source -> destination` mapping from deploy output.

Do not paste cloud tokens, registry tokens, private SSH keys, or full `.env`
contents. The useful question is narrow:

```text
This Stacker deployment paused during Docker Compose.
Compose runs from /home/trydirect/project.
The error is: env file <path> not found.
The generated compose contains this env_file section: <sanitized snippet>.
The deploy output mapped config files as: <source -> destination>.
What should I change locally before redeploying?
```

## 6. Redeploy cleanly

After fixing local config, regenerate and resend the bundle:

```bash
stacker deploy --target cloud --env production --force-new
```

Use `--force-new` when the previous server was only partially provisioned or when
the cloud provider created resources with a bad shape. If the server is healthy
and the failure was only application-level, a normal redeploy may be enough.

## 7. Record what happened

After recovery, update the deployment notes with:

- the deployment ID;
- the paused status message;
- the root cause;
- the config change;
- whether a manual SSH fix was applied;
- the command that completed the recovery.

This turns a failed deploy into a repeatable runbook for the next user.
