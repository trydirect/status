# Pipe Adapter Wishlist

This file collects **suggested next adapters** for the `crates/` workspace.

Current first-party adapters already present:

- `webhook`
- `smtp`
- `imap`
- `pop3`
- `mailhog`

The list below focuses on adapters that are likely to be useful for real Stacker
users wiring infrastructure, alerts, workflows, and service integrations.

## High priority

### Notifications and chat

- [ ] **Slack**
  - Incoming webhook target
  - Bot API target for richer messages, threads, and file uploads
- [ ] **Telegram**
  - Bot API target for alerts, approvals, and simple commands
- [ ] **Discord**
  - Webhook target for ops notifications and status feeds
- [ ] **Microsoft Teams**
  - Incoming webhook target for enterprise alerting

### Workflow and automation

- [ ] **Airflow**
  - Trigger DAG run target
  - Optional DAG status poll source
- [ ] **Zapier**
  - Catch Hook / Webhooks target adapter
- [ ] **Make.com**
  - Webhook target for low-code automation flows
- [ ] **n8n**
  - Webhook target for self-hosted workflow automation

### Queues and event transport

- [ ] **RabbitMQ / AMQP**
  - Queue publish target
  - Queue consume source
- [ ] **Kafka**
  - Topic publish target
  - Topic consume source
- [ ] **NATS**
  - Subject publish target
  - Subject subscribe source
- [ ] **Redis Streams**
  - Stream append target
  - Stream consumer source

## Medium priority

### Cloud messaging and serverless triggers

- [ ] **AWS SQS**
  - Queue send target
  - Queue poll source
- [ ] **AWS SNS**
  - Topic publish target
- [ ] **Google Pub/Sub**
  - Publish target
  - Subscription pull source
- [ ] **Azure Service Bus**
  - Queue/topic publish target
  - Queue/topic consume source

### Incident management

- [ ] **PagerDuty**
  - Events API target for incident creation and resolution
- [ ] **Opsgenie**
  - Alert target for escalation workflows
- [ ] **VictorOps / Splunk On-Call**
  - Alert target for on-call routing

### Developer platforms

- [ ] **GitHub**
  - Issue/comment target
  - Release/deployment webhook source
- [ ] **GitLab**
  - Issue/pipeline target
  - Webhook source
- [ ] **Jira**
  - Ticket create/update target

### Storage and documents

- [ ] **S3 / MinIO**
  - Object put target
  - Object event source
- [ ] **Google Drive**
  - File upload target
- [ ] **Dropbox**
  - File sync target

## Lower priority but highly useful

### Data platforms

- [ ] **PostgreSQL**
  - Insert/update target
  - Logical replication / CDC source
- [ ] **MySQL**
  - Insert/update target
  - Binlog source
- [ ] **Elasticsearch / OpenSearch**
  - Index target for logs, events, and search pipelines
- [ ] **ClickHouse**
  - Bulk ingest target for analytics

### Observability

- [ ] **Prometheus Alertmanager**
  - Alert target
- [ ] **Grafana OnCall**
  - Incident/notification target
- [ ] **Loki**
  - Log push target
- [ ] **OpenTelemetry**
  - Trace/event export target

### App and commerce services

- [ ] **Twilio**
  - SMS target
  - WhatsApp target
- [ ] **Stripe**
  - Webhook source
  - Event/action target where appropriate
- [ ] **Shopify**
  - Webhook source
  - Admin API target

## Platform-oriented adapters for Stacker use cases

- [ ] **Kubernetes**
  - Job target
  - CronJob target
  - Watch source for workload events
- [ ] **Docker Registry**
  - Image publish / tag notification target
- [ ] **HashiCorp Vault**
  - Secret read/write adapter beyond current direct product integrations
- [ ] **Terraform Cloud / HCP Terraform**
  - Run trigger target
  - Run status source

## Notes for implementation order

- Prefer adapters with **simple auth + high utility** first:
  1. Slack
  2. Telegram
  3. RabbitMQ
  4. Airflow
  5. Zapier / Make / n8n
- Keep a clean split between:
  - **source adapters**: poll, subscribe, receive, watch
  - **target adapters**: send, publish, trigger, upload
- Favor adapters that can be configured with:
  - URL
  - token or secret reference
  - retry policy
  - timeout
  - idempotency key or dedupe field
- Reuse the same normalized payload pattern where possible instead of creating
  one-off transport-specific shapes for every service.
