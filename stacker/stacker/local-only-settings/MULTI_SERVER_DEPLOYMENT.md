# Multi-Server Deployment (Current Workaround)

## Overview

Stacker currently uses a 1:1:1 model: one deployment → one agent → one server. True multi-server deployment of a single service is not yet supported. However, you can achieve a similar result today using multiple deployments.

## Workaround: Multiple Deployments Per Project

Create separate deployments under the same project, each targeting a different server:

```
Project: "my-app"
├── Deployment #1 (hash: abc...) → Server A → Agent A → openclaw
└── Deployment #2 (hash: def...) → Server B → Agent B → openclaw
```

### How to set up

1. Create your project with openclaw in the service catalog
2. Deploy to Server A with one `stacker.yml` config pointing to the first server:
   ```yaml
   deploy:
     target: server
     server:
       host: 203.0.113.10
       user: deploy
       ssh_key: ~/.ssh/deploy_key
   ```
3. Create a second deployment for Server B by updating the target and deploying again:
   ```yaml
   deploy:
     target: server
     server:
       host: 203.0.113.11
       user: deploy
       ssh_key: ~/.ssh/deploy_key
   ```

Each deployment gets its own:
- `deployment_hash`
- Status Panel agent instance
- Vault tokens and secrets
- Command queue
- Independent health monitoring

### Limitations

- Each deployment is **managed independently** — no unified status view across both servers
- Configuration changes must be applied to each deployment separately
- No built-in load balancing between the two instances; use an external reverse proxy or DNS-based routing
