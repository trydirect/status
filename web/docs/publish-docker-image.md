# How to tag and push your image to the registry

Use this guide only when you do not yet have CI/CD publishing images for you.
The main deployment story assumes the remote server can pull the image from a
registry.

## Manual publishing

Build the image locally:

```bash
docker build -t status-panel-web:0.1.0 .
```

Sign in to your registry:

```bash
docker login
```

Tag the image with the repository name your server will pull:

```bash
docker tag status-panel-web:0.1.0 trydirect/status-panel-web:0.1.0
```

Push it:

```bash
docker push trydirect/status-panel-web:0.1.0
```

Then reference the pushed image from both `stacker.yml` and
`docker-compose.yml`. The tag must match exactly; do not document `0.1.0` while
the compose file still points at `latest`.

```yaml
image:
  repository: trydirect/status-panel-web
  tag: 0.1.0
```

```yaml
services:
  status-panel-web:
    image: trydirect/status-panel-web:0.1.0
```

## Private registry credentials

If the image is private, the remote server needs Docker registry credentials
before it can pull the image.

These credentials are **deployment registry credentials**, not service-scoped
runtime secrets. Do not save them with a command like:

```bash
stacker secrets set STACKER_DOCKER_PASSWORD --scope service --service status-panel-web --body '<token>'
```

That would create a runtime secret for one service. It would not automatically
teach the deploy process how to authenticate to the image registry.

For this Status website example, use one of these patterns instead.
If Stacker sees an image that may need registry authentication and no
credentials are configured, `stacker deploy` prints these options before the
remote server tries to pull the image.

### Option A: export credentials for one deploy

Use this when you do not want to write credentials to any project file:

```bash
export STACKER_DOCKER_USERNAME='<registry-username>'
export STACKER_DOCKER_PASSWORD='<registry-token>'
export STACKER_DOCKER_REGISTRY='docker.io'

stacker deploy --target cloud --env production
```

Environment variables override `stacker.yml` values during deployment.

### Option B: keep placeholders in `stacker.yml` and values in `.env`

Use this when the project should remember which variables are required, while
the actual values stay out of Git.

Store the values in a local env file:

```bash
stacker secrets set STACKER_DOCKER_USERNAME='<registry-username>' --file .env
stacker secrets set STACKER_DOCKER_PASSWORD='<registry-token>' --file .env
stacker secrets set STACKER_DOCKER_REGISTRY='docker.io' --file .env
```

Then reference those variables from `stacker.yml`:

```yaml
env_file: .env

deploy:
  registry:
    username: "${STACKER_DOCKER_USERNAME}"
    password: "${STACKER_DOCKER_PASSWORD}"
    server: "${STACKER_DOCKER_REGISTRY}"
```

Add `.env` to `.gitignore` and commit only `.env.example` with empty
placeholders.

```dotenv
STACKER_DOCKER_USERNAME=
STACKER_DOCKER_PASSWORD=
STACKER_DOCKER_REGISTRY=docker.io
```

For Docker Hub, `server` can be omitted or set to `docker.io`. For GitHub
Container Registry, use `ghcr.io`.

During cloud/server deploy, Stacker passes these credentials to the installer so
the target server can run Docker authentication before pulling the private
image. For deployments managed by the Status Panel agent, Stacker can also reuse
trusted stored registry auth for later image refreshes.

Do not commit registry passwords, access tokens, or personal credentials to Git.

## Prefer CI/CD when available

Manual publishing is useful for the first walkthrough. For a real project, use
Stacker CI/CD or your existing CI/CD pipeline so every release builds, tags, and
pushes images repeatably.
