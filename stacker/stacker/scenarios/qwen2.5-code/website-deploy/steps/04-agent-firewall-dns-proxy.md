This step is about making the remote deployment reachable and operable.

Required behavior:
1. Guide the user through `stacker agent install` without implying that local config is persisted by default.
2. Explain firewall openings and DNS records required for the application and proxy.
3. When reverse proxy configuration is needed, keep Nginx Proxy Manager runtime targeting in mind.
4. Prefer service DNS names for container-to-container traffic on the server instead of loopback addresses.

Guardrails:
- Do not claim that `stacker agent install` changes `stacker.yml` unless `--persist-config` is explicitly chosen.
- Nginx Proxy Manager runtime access should use `http://nginx-proxy-manager:81`.
- For remote service traffic, prefer names like `smtp:25` rather than `127.0.0.1`.
