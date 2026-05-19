# Status Panel Web

Next.js website for `status.stacker.my`. The app explains Status Panel
features, CLI usage, operating modes, Stacker deployment flow, and the future
Contact to Email Sender pipe scenario.

## Local development

```bash
npm install
npm run dev
```

If port `3000` is already in use, run:

```bash
npm run dev -- --hostname 127.0.0.1 --port 3001
```

## Validation

```bash
npm run lint
npm run build
docker build -t status-panel-web:test .
```

## Contact pipe configuration

The contact form validates on the server. It does not send email unless these
server-only environment variables are configured:

```bash
CONTACT_PIPE_URL=
CONTACT_PIPE_TOKEN=
CONTACT_TO_EMAIL=
```

Do not expose `CONTACT_PIPE_TOKEN` with a `NEXT_PUBLIC_` prefix.

## Deployment

Use `stacker.yml`, `docker-compose.yml`, and `Dockerfile` in this directory for
the Stacker deployment workflow. Record all deployment, MCP, Status Panel,
firewall, proxy, and pipe commands in `docs/deployment-history.md`.
