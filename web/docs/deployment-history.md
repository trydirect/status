# How we developed Status website

This is the story we want a new Stacker user to follow.

We finished a small Next.js website recently for Status Panel. It
works on our laptop, but our real goal is bigger: publish it on a server, point
a domain at it, protect it with the right firewall rules, add Nginx Proxy
Manager, install the Status Panel agent, create our first data pipe, and later
deploy more services without going back to raw SSH.

The examples below use custom subdomain `status.stacker.my`, `status-panel-web` app, and
`trydirect/status-panel-web:0.1.0` docker tag for our app. You can replace them with your real domain, project
name, registry, and image tag.

## 1. We have a working website locally, now what?

Our repository already has the website source code:

```text
status/web/
  package.json
  app/
  components/
  public/
  Dockerfile
```

Before Stacker enters the story, we make sure the website can run locally:

```bash
npm install
npm run build
docker build -t status-panel-web:0.1.0 .
docker run --rm -p 3100:3000 status-panel-web:0.1.0
```

We open `http://localhost:3100` and confirm that the Status website is alive.
The health endpoint should also respond:

```bash
curl -fsS http://127.0.0.1:3100/api/health
```

## 2. We log in, connect AI, and initialize Stacker

Now we invite Stacker into the project:

```bash
stacker login
```

If users want AI-assisted setup from the start, configure AI before init or use
the AI-aware init path. In this example, we use a local or private Ollama
endpoint:

```bash
curl -fsS http://192.168.100.245:11434/api/tags

stacker config setup ai \
  --provider ollama \
  --endpoint http://192.168.100.245:11434 \
  --model qwen2.5-coder \
  --timeout 0 \
  --task compose \
  --task troubleshoot \
  --task security
```

The endpoint and model are examples. Users should replace them with their own
Ollama host and installed model. For a local laptop setup, the endpoint may be
`http://127.0.0.1:11434`. Projects can also start with:

```bash
stacker init --with-ai
```

Without AI-assisted init, use the normal initialization command:

```bash
stacker init
```

In this project, `stacker init` is able to inspect the existing files without a
manual questionnaire. It finds `docker-compose.yml`, detects the
`status-panel-web` service, and creates the first Stacker files. A user should
expect a similar result, with their own project path and detected service names:

```text
✓ Created /path/to/your/project/stacker.yml
  Project: web (node)
  Services: status-panel-web
✓ Generated .stacker/Dockerfile

Next steps:
  stacker config validate   # Check configuration
  stacker deploy --target local --dry-run   # Preview deployment
  stacker deploy --target local   # Deploy locally
```

The generated baseline is intentionally conservative:

- Project name: `web`
- Main service: `status-panel-web`
- Container port mapping: `3000:3000`
- Deployment target: `local`
- Compose file: `docker-compose.yml`
- Proxy: disabled until we choose the public deployment path
- Status Panel: disabled until we enable the managed runtime

After init, we expect a `stacker.yml` that tells the story of the project, not
only the current Docker command. At this moment, the important generated parts
look like this:

```yaml
name: web
version: 0.1.0

app:
  type: node
  path: .

services:
  - name: status-panel-web
    image: trydirect/status-panel-web:0.1.0
    ports:
      - 3000:3000
    environment:
      NEXT_PUBLIC_SITE_URL: https://status.stacker.my
      NODE_ENV: production

proxy:
  type: none
  auto_detect: false
  domains: []

deploy:
  target: local
  compose_file: docker-compose.yml

monitoring:
  status_panel: false
```

Later, when we are ready for the public cloud/server story, we will evolve that
baseline toward a shape like this:

```yaml
name: status-panel-web

project:
  identity: status-panel-web

app:
  type: static
  path: .

image:
  repository: trydirect/status-panel-web
  tag: 0.1.0

proxy:
  type: nginx-proxy-manager
  domains:
    - domain: status.stacker.my
      upstream: http://status-panel-web:3000
      ssl: auto

monitoring:
  status_panel: true

deploy:
  target: cloud
  environment: production
```

Then we ask Stacker to validate what it understands:

```bash
stacker config validate
stacker config show
```

If validation finds empty structural fields left by an older generated config,
let Stacker clean them instead of hand-editing YAML:

```bash
stacker config fix
stacker config validate
```

## 3. We publish the image the server will pull

Cloud servers cannot pull an image that exists only on our laptop. Before the
first remote deploy, the exact image referenced by `docker-compose.yml` and
`stacker.yml` must be available in a registry.

For this walkthrough, the image reference is:

```text
trydirect/status-panel-web:0.1.0
```

So the minimum manual publish step is:

```bash
docker build -t status-panel-web:0.1.0 .
docker tag status-panel-web:0.1.0 trydirect/status-panel-web:0.1.0
docker login
docker push trydirect/status-panel-web:0.1.0
```

Do not continue to `stacker deploy --target cloud` until the push succeeds. If
the remote server cannot pull the image, Docker Compose falls back to the
`build:` section in `docker-compose.yml`; the remote server does not have the
local source tree or Dockerfile, so the deploy pauses with an error like
`failed to read dockerfile: open Dockerfile: no such file or directory`.

If you do not have CI/CD yet, follow
[How to tag and push your image to the registry](./publish-docker-image.md).

If you already use Stacker CI/CD, let that pipeline build and publish the image.
The deployment guide only needs the final image reference that the server can
pull.

For private images, Stacker deploy now prints registry-auth guidance when it
cannot resolve credentials. The manual options are documented in the registry
guide.

## 4. We deploy the first version

Now we let Stacker create or update the remote server:

```bash
stacker deploy --target cloud --env production --dry-run
stacker deploy --target cloud --env production
```

If we already have a saved cloud credential, we can select it directly:

```bash
stacker list clouds
stacker deploy --target cloud --env production --key htz-5 --dry-run
stacker deploy --target cloud --env production --key-id 5 --dry-run
```

`stacker list clouds` shows the saved credential names and IDs. Use `--key`
with the credential name, or `--key-id` with the numeric ID.

For Hetzner, pay close attention to the selected location and server type. A
known-good starting point for this walkthrough is:

```yaml
deploy:
  cloud:
    provider: hetzner
    region: nbg1
    size: cx23
```

An incompatible location/server-type combination can pause the deployment during
provisioning with provider errors such as unsupported location for server type.
If that happens, update `deploy.cloud.region` and `deploy.cloud.size`, then run
the deploy again with `--force-new`.

During the dry run, Stacker validates the payload and credentials. If
`docker-compose.yml` references `.env` and `.env` is missing, Stacker can create
it from `.env.example` with safe local permissions before bundling the config.
For cloud and server deploys, Stacker prints the config-bundle file mapping so
users can see which local files will be copied and where Docker Compose will
look for them:

```text
Config bundle: .stacker/deploy/production/config-bundle.tar.zst
  Config file: .env -> .env
```

For Hetzner cloud deploys, Stacker accepts familiar location aliases such as
`nbg1` in `stacker.yml` and normalizes them for the installer before provisioning.

In the live walkthrough, switching the server type to `cx23` changed the deploy
from a quick provisioning pause into a real installation run:

```text
Deployment #181 — in_progress: 178.105.162.176: APT packages updated
```

When Stacker provisions a cloud server, it also creates and authorizes a local
backup SSH key so the user has a break-glass connection path if later agent or
installer steps fail. The deploy output prints the key path and exact SSH
command, for example:

```text
✓ Local SSH backup key authorized
  Key: ~/.config/stacker/ssh/server-87_ed25519
  Connect: ssh -i ~/.config/stacker/ssh/server-87_ed25519 -p 22 root@178.105.162.176
```

Deployment can still pause after the server is reachable if a runtime file is
not copied where Docker Compose expects it. In this walkthrough, the next pause
showed that Compose could not find `.env`:

```text
env file /opt/stacker/deployments/production/files/.env not found
```

That means the generated remote compose file and the copied config-bundle files
must use the same destination contract. Stacker now prevents this class of error
locally by requiring config-bundle destinations to be project-relative and by
showing the file mapping before the deploy request is sent.

If a deployment pauses after the server exists, do not treat it as a dead end.
Use the backup SSH command from the deploy output and follow
[Recovering from a paused Stacker deployment](./recover-paused-deployment.md).

At this point Stacker should:

- create or reuse the server;
- install Docker and the required runtime pieces;
- pull `trydirect/status-panel-web:0.1.0`;
- start the Status website container;
- prepare managed services such as Nginx Proxy Manager when requested;
- install the Status Panel agent when monitoring is enabled.

After deployment, we check what Stacker knows:

```bash
stacker status
stacker agent status
```

If the Status Panel agent is not installed yet, we install it explicitly:

```bash
stacker agent install
stacker agent status
```

The Status Panel agent is important because it lets later commands run through
the Stacker control plane instead of requiring us to SSH into the server.

## 5. We open the cloud firewall deliberately

Our website needs public HTTP and HTTPS traffic. SSH may also be required for
maintenance, but we keep the firewall intentional:

```bash
stacker cloud firewall add --server-id 84 --public-ports 80/tcp,443/tcp
stacker cloud firewall list --server-id 84
```

During this walkthrough we also had to reach the Nginx Proxy Manager setup UI on
port `81`. That port is an admin interface, so it should be temporary:

```bash
stacker cloud firewall add --server-id 84 --public-ports 81/tcp
```

After the proxy provider setup is complete, close it again:

```bash
stacker cloud firewall remove --server-id 84 --public-ports 81/tcp
```

If this is a fresh server and we still need SSH access:

```bash
stacker cloud firewall add --server-id 84 --public-ports 22/tcp
```

The rule is simple: open only the ports the story needs.

## 6. We point the domain at the server

Before SSL can work, DNS must point to the server.

In the DNS provider, we create:

```text
status.stacker.my  A  <server-public-ip>
```

Then we wait until DNS resolves:

```bash
dig +short status.stacker.my
```

The result should be the public IP of the deployed server.

## 7. We configure Nginx Proxy Manager through Stacker

Now we connect the public domain to the website container.

For the Status website, traffic should go to the `status-panel-web` service on
port `3000`:

```bash
stacker agent configure-proxy status-panel-web \
  --deployment <current-deployment-hash> \
  --domain status.stacker.my \
  --port 3000 \
  --ssl \
  --json
```

In the live run, the deployment hash looked like this:

```bash
stacker agent configure-proxy status-panel-web \
  --deployment deployment_a631cf66-a224-440b-9871-12b63548671c \
  --domain status.stacker.my \
  --port 3000 \
  --ssl \
  --json
```

For remote deployments, this command delegates the route creation to the Status
Panel agent. The agent talks to Nginx Proxy Manager from inside the Docker
network, so the provider host must use the runtime Docker DNS name:

```text
http://nginx-proxy-manager:81
```

This is different from the logical Stacker service code. The stable split is:

```yaml
my.stacker.scope: "platform"
my.stacker.service: "nginx_proxy_manager"
my.stacker.dns: "nginx-proxy-manager"
```

Use `my.stacker.service` to identify the managed provider in Stacker state, and
use `my.stacker.dns` for agent-to-service traffic inside the Docker network.

If Nginx Proxy Manager shows the first-run setup form, complete setup first and
store the same credentials in the Status Panel provider credential source. The
planned Stacker UX should make this self-service:

```bash
stacker proxy provider doctor nginx-proxy-manager --server-id 84
stacker proxy provider setup nginx-proxy-manager \
  --server-id 84 \
  --host http://nginx-proxy-manager:81 \
  --identity you@example.com \
  --name "Your Name" \
  --password-stdin
```

Today, Stacker automates only part of this. When `proxy.type` requests Nginx
Proxy Manager, the deploy request includes the `nginx_proxy_manager` managed
feature so the install service can install the provider. The Status Panel agent
then reads provider credentials from Vault at a host-scoped
`npm_credentials` path. Stacker also checks that the agent advertises
`npm_credential_source=vault` before queuing `configure-proxy`.

The missing piece is post-install provider setup. Stacker does not yet complete
the Nginx Proxy Manager first-run admin form or rotate the host-scoped
credentials after setup. That is why this walkthrough needed one manual Vault
write after creating the admin user.

Until that UX exists, the safe manual path is:

1. Temporarily open `81/tcp` with `stacker cloud firewall add`.
2. Complete the Nginx Proxy Manager setup form.
3. Store the same credentials in Vault.
4. Close `81/tcp` with `stacker cloud firewall remove`.

If `configure-proxy` returns `npm_auth_failed`, the provider is reachable but
the stored credentials are wrong or setup is incomplete. If it returns
`npm_create_failed` but the host appears in Nginx Proxy Manager, treat that as a
partial success: the route was created, and SSL or response handling failed
afterward.

The live walkthrough hit that exact partial-success case. Nginx Proxy Manager
returned `Internal Error`, but the proxy host existed afterward. Stacker adopted
the existing host and reported the route as usable:

```json
{
  "message": "Proxy host exists after NPM create returned an error; adopted existing HTTP route, SSL certificate is pending or failed",
  "proxy_host_id": 2,
  "route_adopted": true,
  "route_usable": true,
  "ssl_enabled": false,
  "ssl_requested": true,
  "ssl_status": "pending_or_failed_http_only",
  "status": "success"
}
```

That is a successful HTTP route with SSL still unresolved. The next step is to
fix certificate issuance instead of recreating the proxy host.

To isolate SSL problems, retry once without SSL:

```bash
stacker agent configure-proxy status-panel-web \
  --deployment <current-deployment-hash> \
  --domain status.stacker.my \
  --port 3000 \
  --no-ssl \
  --json
```

If `--no-ssl` works, check DNS and make sure the cloud firewall allows public
HTTP and HTTPS:

```bash
dig +short status.stacker.my
stacker cloud firewall add --server-id 84 --public-ports 80/tcp,443/tcp
```

The planned provider-neutral command should wrap this flow:

```bash
stacker proxy route add status.stacker.my \
  --service status-panel-web \
  --port 3000 \
  --ssl
```

If proxy credentials need to be refreshed, reinstall the agent and managed
proxy setup:

```bash
stacker agent install
stacker agent configure-proxy status-panel-web \
  --deployment <current-deployment-hash> \
  --domain status.stacker.my \
  --port 3000 \
  --ssl \
  --json
```

Now the user should be able to open:

```text
https://status.stacker.my
```

## 8. We inspect logs and runtime state

The website is online, but we still want confidence:

```bash
stacker logs --service status-panel-web --tail 100
stacker agent logs status-panel-web --lines 100
stacker agent status
```

The first deploy is not finished when the page loads once. It is finished when
we can inspect, restart, and operate it through Stacker.

## 9. We create the first pipe

Now the Status website needs to talk to something else. For example, we can add
an SMTP companion app from the service catalog so the website can send a test
message without using a real mail provider.

There are three custom service paths:

- curated catalog services, such as `stacker service add smtp`;
- marketplace custom services, when a reviewed template is available;
- custom Docker Compose imports for internet-found projects, reviewed before
  they mutate `stacker.yml`.

```bash
stacker service add smtp
stacker config validate
```

Then deploy only that service through the service-oriented deploy command:

```bash
stacker service deploy smtp \
  --deployment deployment_a631cf66-a224-440b-9871-12b63548671c
stacker agent status
```

`stacker service deploy` validates that `smtp` exists in `stacker.yml`, then uses
the lower-level `stacker agent deploy-app smtp` remote app operation. The terms
are intentionally separate: `service` is the desired Compose/config object;
`deploy-app` is the agent command that applies one remote app code.

For project-scoped services, Stacker should stamp the rendered Compose service
with stable ownership labels:

```yaml
my.stacker.scope: "project"
my.stacker.service: "smtp"
my.stacker.dns: "smtp"
```

This keeps the logical service code (`smtp`) aligned with the runtime Docker DNS
name (`smtp`) and gives future container discovery a stable identity that does
not depend on parsing generated container names.

The `smtp` custom service publishes SMTP on host port `1025` and exposes a web UI
on host port `8025`. Inside the Docker network, pipe adapters should use the
service DNS name and container port:

```text
smtp:25
```

Do not configure a remote pipe target as `127.0.0.1:1025` unless the pipe runtime
is running on the host network. From inside the Status Panel agent container,
`127.0.0.1` means the agent container itself, not the project SMTP container or
the Docker host.

If a user wants a full mail-server project such as
`docker-mailserver/docker-mailserver`, the safe first step is review-only local
Compose import, not cloning or running remote code:

```bash
stacker service import mailserver \
  --from-compose ./docker-mailserver/compose.yaml \
  --service mailserver \
  --review
```

The review calls out images, ports, env keys, volumes, dependencies, unsupported
Compose fields, and risks such as host networking, privileged mode, Docker
socket mounts, absolute host paths, capabilities, and public mail ports. For
mail servers, confirm MX/SPF/DKIM/DMARC/PTR/rDNS, SMTP egress policy, persistent
mail volumes, and firewall ports before importing with `--yes`.

Before exporting anything to a remote deployment, we should prove the pipe story
locally first.

```bash
stacker target local
stacker deploy --target local

stacker pipe scan --containers status-panel-web \
  --capture-samples \
  --protocols html_forms

stacker pipe scan --containers smtp \
  --capture-samples \
  --protocols html_forms \
  --protocols rest
```

The local deploy succeeded and started both containers:

```text
status-panel-web   Up ...   0.0.0.0:3000->3000/tcp
web-smtp-1         Up ...   0.0.0.0:1025->1025/tcp, 0.0.0.0:8025->8025/tcp
```

We also confirmed the local contact page is reachable:

```bash
curl -fsS http://127.0.0.1:3000/contact
```

But the current local scanner still does not discover selectable operations for
this Next.js contact form, even after the local stack is running:

```text
{
  "app_code": "status-panel-web",
  "protocols_detected": [],
  "endpoints": [],
  "resources": [],
  "forms": []
}
```

And the local create flow fails exactly where it should if discovery is empty:

```bash
stacker pipe create status-panel-web smtp --manual
```

```text
No selectable HTTP endpoints or HTML forms were discovered for 'status-panel-web'.
Run `stacker pipe scan --containers status-panel-web` to inspect discovery results.
```

The local `smtp` service is not a clean HTTP target yet either. On this Apple
Silicon host the image reports an amd64/arm64 mismatch during local deploy, and
its HTTP UI on `:8025` resets connections instead of returning a selectable REST
or HTML-form surface.

So the correct story order is:

- either let `pipe create` reuse a narrower `html_forms` source scan for this
  workflow locally,
- or fix local `html_forms` discovery for this Next.js server-action form,
- or add a first-class mail/webhook target flow instead of treating `smtp` as a
  generic HTTP/form target.

After the local flow works, we can repeat the same idea remotely. In our remote
test, the narrower app probe already proved the form is discoverable there:

```bash
stacker pipe scan \
  --deployment deployment_a631cf66-a224-440b-9871-12b63548671c \
  --app status-panel-web \
  --capture-samples \
  --protocols html_forms
```

```text
App: status-panel-web
Protocols detected: html_forms

HTML Forms:
  #form_contact  POST
    fields: [$ACTION_REF_1, $ACTION_1:0, $ACTION_1:1, $ACTION_KEY, name, email, subject, message]
```

The `$ACTION_*` fields are Next.js Server Actions internals. The meaningful
user fields are `name`, `email`, `subject`, and `message`.

The remote pipe flow then becomes:

```bash
stacker pipe deploy \
  --deployment <current-deployment-hash> \
  status-panel-web-to-smtp-3

stacker pipe activate \
  --deployment <current-deployment-hash> \
  <remote-pipe-instance-id> \
  --trigger webhook
```

Then we test it:

```bash
stacker pipe trigger \
  --deployment <current-deployment-hash> \
  <remote-pipe-instance-id> \
  --data '{"name":"Stacker Pipe Test","email":"info@example.com","subject":"Status Panel pipe trigger test","message":"Status website is live"}'

stacker pipe history \
  --deployment <current-deployment-hash> \
  <remote-pipe-instance-id>
```

In the live run, the first manual trigger proved an important networking lesson.
The pipe was active, but SMTP delivery failed when the target adapter used
`127.0.0.1:1025`:

```text
smtp delivery failed: Connection error: Connection refused (os error 111)
```

After changing the pipe target adapter to `smtp:25`, we promoted a corrected
remote instance and activated it:

```text
remote_instance_id: 4922167c-7cb7-45c1-9c2b-6207c936d9bc
target_adapter: smtp://smtp:25
```

That corrected target also matches the intended project-scoped runtime labels:

```yaml
my.stacker.scope: "project"
my.stacker.service: "smtp"
my.stacker.dns: "smtp"
```

The next trigger completed successfully:

```json
{
  "type": "trigger_pipe",
  "status": "completed",
  "result": {
    "success": true,
    "target_response": {
      "adapter": "smtp",
      "delivered": true,
      "body": {
        "accepted_recipients": 1,
        "host": "smtp",
        "port": 25,
        "subject": "Status Panel pipe trigger test"
      }
    }
  }
}
```

This is the moment Stacker becomes more than deployment. It starts connecting
services, and the user can verify that a real message moved from the website
workflow into the SMTP companion service.

## 10. We deploy an additional service through the Status Panel agent

Later, the Status website needs Redis for caching. We do not want to rebuild the
whole server manually.

We add or define the service:

```bash
stacker service add redis
stacker config validate
```

Then we deploy the service through the agent:

```bash
stacker agent deploy-app --app redis --image redis --tag 7
stacker agent status
```

If the service needs secrets or environment variables, we use Stacker secrets
instead of hardcoding values:

```bash
stacker secrets set REDIS_PASSWORD --scope service --service redis --body '<strong-password>'
```

Then redeploy or restart the affected service as needed:

```bash
stacker agent restart redis
```

## 11. We keep configuration visible without leaking secrets

Before production changes, we compare environments:

```bash
stacker config inventory --env production --remote
stacker config diff --from local --to production --remote
stacker config check --env production --strict --remote
```

Secrets should appear as present or missing, never as plaintext values.

## 12. The final user journey

The user started with a website on a laptop. The Stacker journey led them
through:

1. Connecting AI early with `stacker init --with-ai` or `stacker config setup ai`.
2. Initializing the project with `stacker init`.
3. Publishing the Docker image to a registry.
4. Deploying to a cloud or server target.
5. Opening only the required firewall ports.
6. Pointing DNS at the server.
7. Configuring Nginx Proxy Manager and SSL.
8. Installing or refreshing the Status Panel agent.
9. Inspecting logs and runtime state.
10. Creating and activating the first pipe.
11. Deploying additional services through the agent.
12. Checking configuration and secrets before future releases.

That is the experience this guide should teach: Stacker is not only the command
that deploys the first container. It is the path from "we built a website" to
"we can operate and extend this service safely."
