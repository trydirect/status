export interface StatusFeature {
  label: string;
  title: string;
  description: string;
}

export interface CliExample {
  command: string;
  description: string;
}

export interface OperatingMode {
  label: string;
  name: string;
  description: string;
}

export interface DeploymentStep {
  title: string;
  description: string;
}

export const statusFeatures: StatusFeature[] = [
  {
    label: "Health",
    title: "Health checks and service status",
    description:
      "Inspect stack and container health with clear output for local operators, automation, and Stacker-driven verification.",
  },
  {
    label: "Metrics",
    title: "CPU, memory, disk, and network metrics",
    description:
      "Collect lightweight server telemetry through CLI or JSON API so deploys can be validated without extra agents.",
  },
  {
    label: "Docker",
    title: "Container management",
    description:
      "List, start, stop, restart, pause, inspect, and read logs for Docker containers from one statically linked binary.",
  },
  {
    label: "Commands",
    title: "Signed remote command execution",
    description:
      "Execute allowlisted commands with HMAC-SHA256 request signing, replay protection, scopes, rate limiting, and audit logs.",
  },
  {
    label: "Vault",
    title: "Vault-backed configuration",
    description:
      "Fetch, apply, and diff application configuration while keeping secrets out of source code and public responses.",
  },
  {
    label: "Update",
    title: "Self-update and rollback",
    description:
      "Check releases, download verified binaries over HTTPS, apply updates, and roll back when an upgrade does not behave.",
  },
];

export const cliExamples: CliExample[] = [
  {
    command: "status init",
    description: "Generate default config.json and .env files for a server.",
  },
  {
    command: "status serve --port 5000 --with-ui",
    description: "Start the JSON API and bundled Status Panel web dashboard.",
  },
  {
    command: "status health",
    description: "Check stack or container health from a terminal session.",
  },
  {
    command: "status metrics --json",
    description: "Return machine-readable CPU, memory, disk, and system metrics.",
  },
  {
    command: "status containers",
    description: "List running and stopped Docker containers on the host.",
  },
  {
    command: "status logs my-app -n 100",
    description: "Read recent logs for a named service or container.",
  },
  {
    command: "status restart my-app",
    description: "Restart a managed container after a verified operational action.",
  },
  {
    command: "status update check",
    description: "Check whether a newer Status Panel release is available.",
  },
];

export const operatingModes: OperatingMode[] = [
  {
    label: "Local",
    name: "CLI",
    description:
      "Run one command and exit for quick health, metrics, logs, and lifecycle checks.",
  },
  {
    label: "HTTP",
    name: "API server",
    description:
      "Expose a local JSON API for health, metrics, command execution, and update workflows.",
  },
  {
    label: "Dashboard",
    name: "API + UI",
    description:
      "Start the API with the bundled UI for direct server inspection and operations.",
  },
  {
    label: "Agent",
    name: "Daemon mode",
    description:
      "Long-poll Stacker for queued commands, execute locally, and report audited results.",
  },
  {
    label: "Stacker",
    name: "Managed deployment",
    description:
      "Use Status Panel as the server-side verifier for Stacker deploys, firewall changes, proxy publishing, and pipes.",
  },
];

export const deploymentSteps: DeploymentStep[] = [
  {
    title: "Build locally",
    description:
      "Develop the Next.js site under status/web, run npm run dev, then lint and build before deployment.",
  },
  {
    title: "Plan with Stacker CLI and MCP",
    description:
      "Use read-only plan and explain surfaces before applying any deploy, firewall, proxy, or pipe mutation.",
  },
  {
    title: "Deploy and verify",
    description:
      "Apply the web service through Stacker, then inspect Status Panel events, health, metrics, and logs.",
  },
  {
    title: "Open the firewall",
    description:
      "Configure only the required cloud firewall paths for SSH, HTTP, HTTPS, and agent connectivity.",
  },
  {
    title: "Publish with Nginx Proxy Manager",
    description:
      "Route status.stacker.my to the deployed Next.js container and attach SSL through NPM.",
  },
  {
    title: "Extend with pipes",
    description:
      "Later connect the Contact form to a Stacker pipe and SMTP email sender service without committing mail credentials.",
  },
];
