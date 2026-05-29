# DAG Pipes — Developer Manual

Build and run data pipelines that connect your deployed services. Route contact form submissions to Telegram, sync database changes to Slack, send confirmation emails — all with simple CLI commands or drag-and-drop.

## Guide Overview

| Part | For | What you'll learn |
|------|-----|------------------|
| **[Part 1: CLI Guide](./DAG_PIPES_PART1_CLI_GUIDE.md)** | Getting started | Create and run pipes using `stacker pipe` commands (includes local mode) |
| **[Part 2: Visual Editor](./DAG_PIPES_PART2_WEB_EDITOR.md)** | Visual builders | Drag-and-drop pipeline builder in your browser |
| **[Part 3: REST API Deep Dive](./DAG_PIPES_PART3_API_DEEP_DIVE.md)** | Automation & scripting | Full API reference, curl scripts, gRPC streaming |

> **💡 Local mode**: You can build and test pipes against local Docker containers without a cloud deployment. See the [Local Mode section in Part 1](./DAG_PIPES_PART1_CLI_GUIDE.md#local-mode-experimental) for setup and workflow.

## Examples in All Three Guides

Each guide walks through the same practical examples:

1. **Contact Form → Telegram + Slack** — forward form submissions to both channels simultaneously
2. **Contact Form → PostgreSQL CDC → Telegram** — database watches for new rows, sends notifications automatically
3. **Contact Form → Email + Slack** — send confirmation email + team notification

**Start with [Part 1](./DAG_PIPES_PART1_CLI_GUIDE.md)** — it takes 5 minutes and covers everything you need to get a pipe running.
