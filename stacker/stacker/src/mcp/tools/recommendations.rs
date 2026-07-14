use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};

/// Recommend complementary services for a stack based on the selected template(s).
///
/// Returns categorized recommendations (production vs development) with
/// suggested configurations (env vars, ports, volumes) tailored to the
/// deployment method (SSH/Ansible roles or Status Panel apps).
pub struct RecommendStackServicesTool;

/// A single service recommendation with its rationale and configuration.
#[derive(serde::Serialize, Clone)]
struct ServiceRecommendation {
    /// App/role code (e.g. "redis", "nginx", "traefik")
    code: String,
    /// Human-readable name
    name: String,
    /// Why this service is recommended
    reason: String,
    /// "required" | "recommended" | "optional"
    priority: String,
    /// "database" | "cache" | "proxy" | "monitoring" | "search" | "queue" | "mail" | "storage" | "security" | "devtool" | "runtime"
    category: String,
    /// Docker image (for Status Panel / docker-compose method)
    docker_image: String,
    /// Ansible role name (for SSH method); empty if not available
    ansible_role: String,
    /// Whether we have a local Ansible role for this
    has_local_role: bool,
    /// Whether we have a local app template for this
    has_local_app: bool,
    /// Suggested environment variables
    environment: Value,
    /// Suggested port mappings
    ports: Value,
    /// Suggested volume mounts
    volumes: Value,
    /// Additional notes / configuration tips
    notes: String,
}

/// Knowledge base: for a given "primary" app, which companion services make sense?
struct StackBlueprint {
    /// Which primary codes trigger this blueprint
    triggers: Vec<&'static str>,
    /// Production recommendations
    production: Vec<ServiceRecommendation>,
    /// Development-only extras
    development: Vec<ServiceRecommendation>,
}

fn build_blueprints() -> Vec<StackBlueprint> {
    vec![
        // ── WordPress ────────────────────────────────────────────────
        StackBlueprint {
            triggers: vec!["wordpress", "wordpress_prod", "wordpress_dev", "wordpress_woocommerce"],
            production: vec![
                ServiceRecommendation {
                    code: "mysql".into(),
                    name: "MySQL".into(),
                    reason: "WordPress requires a MySQL-compatible database".into(),
                    priority: "required".into(),
                    category: "database".into(),
                    docker_image: "mysql:8.0".into(),
                    ansible_role: "mysql".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({
                        "MYSQL_ROOT_PASSWORD": "changeme_root",
                        "MYSQL_DATABASE": "wordpress",
                        "MYSQL_USER": "wordpress",
                        "MYSQL_PASSWORD": "changeme_wp"
                    }),
                    ports: json!([{"host_port": "3306", "container_port": "3306"}]),
                    volumes: json!([{"host_path": "mysql_data", "container_path": "/var/lib/mysql"}]),
                    notes: "Change default passwords before deploying to production.".into(),
                },
                ServiceRecommendation {
                    code: "redis".into(),
                    name: "Redis".into(),
                    reason: "Object caching dramatically improves WordPress performance".into(),
                    priority: "recommended".into(),
                    category: "cache".into(),
                    docker_image: "redis:7-alpine".into(),
                    ansible_role: "redis".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([{"host_port": "6379", "container_port": "6379"}]),
                    volumes: json!([{"host_path": "redis_data", "container_path": "/data"}]),
                    notes: "Install WP Redis plugin for object cache. Set WP_REDIS_HOST=redis".into(),
                },
                ServiceRecommendation {
                    code: "traefik".into(),
                    name: "Traefik".into(),
                    reason: "Reverse proxy with automatic SSL certificate management".into(),
                    priority: "recommended".into(),
                    category: "proxy".into(),
                    docker_image: "traefik:v3.0".into(),
                    ansible_role: "traefik".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "80", "container_port": "80"},
                        {"host_port": "443", "container_port": "443"}
                    ]),
                    volumes: json!([
                        {"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock"},
                        {"host_path": "traefik_certs", "container_path": "/letsencrypt"}
                    ]),
                    notes: "Handles SSL termination and routing for all services.".into(),
                },
                ServiceRecommendation {
                    code: "telegraf".into(),
                    name: "Telegraf".into(),
                    reason: "System and container metrics collection for monitoring".into(),
                    priority: "optional".into(),
                    category: "monitoring".into(),
                    docker_image: "telegraf:1.30-alpine".into(),
                    ansible_role: "telegraf".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([]),
                    volumes: json!([
                        {"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock:ro"}
                    ]),
                    notes: "Feeds metrics to InfluxDB or TryDirect monitoring dashboard.".into(),
                },
            ],
            development: vec![
                ServiceRecommendation {
                    code: "phpmyadmin".into(),
                    name: "phpMyAdmin".into(),
                    reason: "Web-based database management for development".into(),
                    priority: "recommended".into(),
                    category: "devtool".into(),
                    docker_image: "phpmyadmin:latest".into(),
                    ansible_role: "phpmyadmin".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({"PMA_HOST": "mysql", "PMA_PORT": "3306"}),
                    ports: json!([{"host_port": "8080", "container_port": "80"}]),
                    volumes: json!([]),
                    notes: "Remove in production. Accessible at port 8080.".into(),
                },
                ServiceRecommendation {
                    code: "mailhog".into(),
                    name: "MailHog".into(),
                    reason: "Catches all outgoing emails for development testing".into(),
                    priority: "optional".into(),
                    category: "mail".into(),
                    docker_image: "mailhog/mailhog:latest".into(),
                    ansible_role: "mailhog".into(),
                    has_local_role: true,
                    has_local_app: false,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "1025", "container_port": "1025"},
                        {"host_port": "8025", "container_port": "8025"}
                    ]),
                    volumes: json!([]),
                    notes: "SMTP on 1025, web UI on 8025. Configure WordPress SMTP plugin to use mailhog:1025.".into(),
                },
            ],
        },

        // ── Django ───────────────────────────────────────────────────
        StackBlueprint {
            triggers: vec!["django"],
            production: vec![
                ServiceRecommendation {
                    code: "postgres".into(),
                    name: "PostgreSQL".into(),
                    reason: "Django's preferred production database".into(),
                    priority: "required".into(),
                    category: "database".into(),
                    docker_image: "postgres:16-alpine".into(),
                    ansible_role: "postgres".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({
                        "POSTGRES_DB": "django_db",
                        "POSTGRES_USER": "django",
                        "POSTGRES_PASSWORD": "changeme"
                    }),
                    ports: json!([{"host_port": "5432", "container_port": "5432"}]),
                    volumes: json!([{"host_path": "postgres_data", "container_path": "/var/lib/postgresql/data"}]),
                    notes: "Set DATABASE_URL=postgres://django:changeme@postgres:5432/django_db in Django.".into(),
                },
                ServiceRecommendation {
                    code: "redis".into(),
                    name: "Redis".into(),
                    reason: "Cache backend and Celery broker for async tasks".into(),
                    priority: "recommended".into(),
                    category: "cache".into(),
                    docker_image: "redis:7-alpine".into(),
                    ansible_role: "redis".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([{"host_port": "6379", "container_port": "6379"}]),
                    volumes: json!([{"host_path": "redis_data", "container_path": "/data"}]),
                    notes: "Use as Django cache (django-redis) and Celery broker (CELERY_BROKER_URL=redis://redis:6379/0).".into(),
                },
                ServiceRecommendation {
                    code: "nginx".into(),
                    name: "Nginx".into(),
                    reason: "Reverse proxy and static file server for Django".into(),
                    priority: "recommended".into(),
                    category: "proxy".into(),
                    docker_image: "nginx:1.25-alpine".into(),
                    ansible_role: "".into(),
                    has_local_role: false,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "80", "container_port": "80"},
                        {"host_port": "443", "container_port": "443"}
                    ]),
                    volumes: json!([
                        {"host_path": "static_files", "container_path": "/usr/share/nginx/html/static"},
                        {"host_path": "media_files", "container_path": "/usr/share/nginx/html/media"}
                    ]),
                    notes: "Serves static/media files and proxies to gunicorn.".into(),
                },
                ServiceRecommendation {
                    code: "rabbitmq".into(),
                    name: "RabbitMQ".into(),
                    reason: "Message broker for Celery task queue (alternative to Redis)".into(),
                    priority: "optional".into(),
                    category: "queue".into(),
                    docker_image: "rabbitmq:3-management-alpine".into(),
                    ansible_role: "rabbitmq".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({
                        "RABBITMQ_DEFAULT_USER": "django",
                        "RABBITMQ_DEFAULT_PASS": "changeme"
                    }),
                    ports: json!([
                        {"host_port": "5672", "container_port": "5672"},
                        {"host_port": "15672", "container_port": "15672"}
                    ]),
                    volumes: json!([{"host_path": "rabbitmq_data", "container_path": "/var/lib/rabbitmq"}]),
                    notes: "Management UI on port 15672. Use if you need advanced routing beyond Redis pub/sub.".into(),
                },
                ServiceRecommendation {
                    code: "telegraf".into(),
                    name: "Telegraf".into(),
                    reason: "Metrics collection for monitoring".into(),
                    priority: "optional".into(),
                    category: "monitoring".into(),
                    docker_image: "telegraf:1.30-alpine".into(),
                    ansible_role: "telegraf".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([]),
                    volumes: json!([{"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock:ro"}]),
                    notes: "Feeds metrics to InfluxDB or TryDirect monitoring.".into(),
                },
            ],
            development: vec![
                ServiceRecommendation {
                    code: "mailhog".into(),
                    name: "MailHog".into(),
                    reason: "Email testing without sending real emails".into(),
                    priority: "recommended".into(),
                    category: "mail".into(),
                    docker_image: "mailhog/mailhog:latest".into(),
                    ansible_role: "mailhog".into(),
                    has_local_role: true,
                    has_local_app: false,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "1025", "container_port": "1025"},
                        {"host_port": "8025", "container_port": "8025"}
                    ]),
                    volumes: json!([]),
                    notes: "Configure Django EMAIL_HOST=mailhog, EMAIL_PORT=1025.".into(),
                },
            ],
        },

        // ── Flask / FastAPI ──────────────────────────────────────────
        StackBlueprint {
            triggers: vec!["flask", "fastapi"],
            production: vec![
                ServiceRecommendation {
                    code: "postgres".into(),
                    name: "PostgreSQL".into(),
                    reason: "Reliable production database for Python web apps".into(),
                    priority: "recommended".into(),
                    category: "database".into(),
                    docker_image: "postgres:16-alpine".into(),
                    ansible_role: "postgres".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({
                        "POSTGRES_DB": "app_db",
                        "POSTGRES_USER": "app",
                        "POSTGRES_PASSWORD": "changeme"
                    }),
                    ports: json!([{"host_port": "5432", "container_port": "5432"}]),
                    volumes: json!([{"host_path": "postgres_data", "container_path": "/var/lib/postgresql/data"}]),
                    notes: "Set DATABASE_URL in your app environment.".into(),
                },
                ServiceRecommendation {
                    code: "redis".into(),
                    name: "Redis".into(),
                    reason: "Caching, session storage, and task queue support".into(),
                    priority: "recommended".into(),
                    category: "cache".into(),
                    docker_image: "redis:7-alpine".into(),
                    ansible_role: "redis".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([{"host_port": "6379", "container_port": "6379"}]),
                    volumes: json!([{"host_path": "redis_data", "container_path": "/data"}]),
                    notes: "Use as cache layer or Celery/ARQ broker.".into(),
                },
                ServiceRecommendation {
                    code: "traefik".into(),
                    name: "Traefik".into(),
                    reason: "Reverse proxy with automatic SSL".into(),
                    priority: "recommended".into(),
                    category: "proxy".into(),
                    docker_image: "traefik:v3.0".into(),
                    ansible_role: "traefik".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "80", "container_port": "80"},
                        {"host_port": "443", "container_port": "443"}
                    ]),
                    volumes: json!([
                        {"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock"},
                        {"host_path": "traefik_certs", "container_path": "/letsencrypt"}
                    ]),
                    notes: "Auto-discovers containers via Docker labels.".into(),
                },
            ],
            development: vec![
                ServiceRecommendation {
                    code: "mailhog".into(),
                    name: "MailHog".into(),
                    reason: "Email testing".into(),
                    priority: "optional".into(),
                    category: "mail".into(),
                    docker_image: "mailhog/mailhog:latest".into(),
                    ansible_role: "mailhog".into(),
                    has_local_role: true,
                    has_local_app: false,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "1025", "container_port": "1025"},
                        {"host_port": "8025", "container_port": "8025"}
                    ]),
                    volumes: json!([]),
                    notes: "".into(),
                },
            ],
        },

        // ── Node.js / Next.js / Express ──────────────────────────────
        StackBlueprint {
            triggers: vec!["nodejs", "nextjs", "express"],
            production: vec![
                ServiceRecommendation {
                    code: "postgres".into(),
                    name: "PostgreSQL".into(),
                    reason: "Reliable relational database for Node.js apps".into(),
                    priority: "recommended".into(),
                    category: "database".into(),
                    docker_image: "postgres:16-alpine".into(),
                    ansible_role: "postgres".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({
                        "POSTGRES_DB": "app_db",
                        "POSTGRES_USER": "app",
                        "POSTGRES_PASSWORD": "changeme"
                    }),
                    ports: json!([{"host_port": "5432", "container_port": "5432"}]),
                    volumes: json!([{"host_path": "postgres_data", "container_path": "/var/lib/postgresql/data"}]),
                    notes: "Or use MongoDB if your app uses Mongoose/document model.".into(),
                },
                ServiceRecommendation {
                    code: "redis".into(),
                    name: "Redis".into(),
                    reason: "Session store, caching, and BullMQ job queue".into(),
                    priority: "recommended".into(),
                    category: "cache".into(),
                    docker_image: "redis:7-alpine".into(),
                    ansible_role: "redis".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([{"host_port": "6379", "container_port": "6379"}]),
                    volumes: json!([{"host_path": "redis_data", "container_path": "/data"}]),
                    notes: "Excellent for connect-redis sessions and BullMQ job processing.".into(),
                },
                ServiceRecommendation {
                    code: "traefik".into(),
                    name: "Traefik".into(),
                    reason: "Reverse proxy with automatic HTTPS".into(),
                    priority: "recommended".into(),
                    category: "proxy".into(),
                    docker_image: "traefik:v3.0".into(),
                    ansible_role: "traefik".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "80", "container_port": "80"},
                        {"host_port": "443", "container_port": "443"}
                    ]),
                    volumes: json!([
                        {"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock"},
                        {"host_path": "traefik_certs", "container_path": "/letsencrypt"}
                    ]),
                    notes: "".into(),
                },
            ],
            development: vec![
                ServiceRecommendation {
                    code: "mailhog".into(),
                    name: "MailHog".into(),
                    reason: "Email testing".into(),
                    priority: "optional".into(),
                    category: "mail".into(),
                    docker_image: "mailhog/mailhog:latest".into(),
                    ansible_role: "mailhog".into(),
                    has_local_role: true,
                    has_local_app: false,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "1025", "container_port": "1025"},
                        {"host_port": "8025", "container_port": "8025"}
                    ]),
                    volumes: json!([]),
                    notes: "".into(),
                },
            ],
        },

        // ── Laravel / PHP ────────────────────────────────────────────
        StackBlueprint {
            triggers: vec!["laravel", "LAMP", "magento", "symfony", "pimcore6_prod", "pimcore6_dev"],
            production: vec![
                ServiceRecommendation {
                    code: "mysql".into(),
                    name: "MySQL".into(),
                    reason: "Primary database for PHP/Laravel applications".into(),
                    priority: "required".into(),
                    category: "database".into(),
                    docker_image: "mysql:8.0".into(),
                    ansible_role: "mysql".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({
                        "MYSQL_ROOT_PASSWORD": "changeme_root",
                        "MYSQL_DATABASE": "laravel",
                        "MYSQL_USER": "laravel",
                        "MYSQL_PASSWORD": "changeme"
                    }),
                    ports: json!([{"host_port": "3306", "container_port": "3306"}]),
                    volumes: json!([{"host_path": "mysql_data", "container_path": "/var/lib/mysql"}]),
                    notes: "Set DB_HOST=mysql, DB_DATABASE=laravel in .env".into(),
                },
                ServiceRecommendation {
                    code: "redis".into(),
                    name: "Redis".into(),
                    reason: "Cache, session driver, and queue worker backend".into(),
                    priority: "recommended".into(),
                    category: "cache".into(),
                    docker_image: "redis:7-alpine".into(),
                    ansible_role: "redis".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([{"host_port": "6379", "container_port": "6379"}]),
                    volumes: json!([{"host_path": "redis_data", "container_path": "/data"}]),
                    notes: "Set CACHE_DRIVER=redis, SESSION_DRIVER=redis, QUEUE_CONNECTION=redis in Laravel.".into(),
                },
                ServiceRecommendation {
                    code: "traefik".into(),
                    name: "Traefik".into(),
                    reason: "Reverse proxy with SSL termination".into(),
                    priority: "recommended".into(),
                    category: "proxy".into(),
                    docker_image: "traefik:v3.0".into(),
                    ansible_role: "traefik".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "80", "container_port": "80"},
                        {"host_port": "443", "container_port": "443"}
                    ]),
                    volumes: json!([
                        {"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock"},
                        {"host_path": "traefik_certs", "container_path": "/letsencrypt"}
                    ]),
                    notes: "".into(),
                },
            ],
            development: vec![
                ServiceRecommendation {
                    code: "phpmyadmin".into(),
                    name: "phpMyAdmin".into(),
                    reason: "Web database manager for development".into(),
                    priority: "recommended".into(),
                    category: "devtool".into(),
                    docker_image: "phpmyadmin:latest".into(),
                    ansible_role: "phpmyadmin".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({"PMA_HOST": "mysql"}),
                    ports: json!([{"host_port": "8080", "container_port": "80"}]),
                    volumes: json!([]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "mailhog".into(),
                    name: "MailHog".into(),
                    reason: "Catch outgoing emails in development".into(),
                    priority: "recommended".into(),
                    category: "mail".into(),
                    docker_image: "mailhog/mailhog:latest".into(),
                    ansible_role: "mailhog".into(),
                    has_local_role: true,
                    has_local_app: false,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "1025", "container_port": "1025"},
                        {"host_port": "8025", "container_port": "8025"}
                    ]),
                    volumes: json!([]),
                    notes: "Set MAIL_HOST=mailhog, MAIL_PORT=1025 in .env".into(),
                },
            ],
        },

        // ── Ruby on Rails ────────────────────────────────────────────
        StackBlueprint {
            triggers: vec!["ror_restful"],
            production: vec![
                ServiceRecommendation {
                    code: "postgres".into(),
                    name: "PostgreSQL".into(),
                    reason: "Rails default production database".into(),
                    priority: "required".into(),
                    category: "database".into(),
                    docker_image: "postgres:16-alpine".into(),
                    ansible_role: "postgres".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({
                        "POSTGRES_DB": "rails_production",
                        "POSTGRES_USER": "rails",
                        "POSTGRES_PASSWORD": "changeme"
                    }),
                    ports: json!([{"host_port": "5432", "container_port": "5432"}]),
                    volumes: json!([{"host_path": "postgres_data", "container_path": "/var/lib/postgresql/data"}]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "redis".into(),
                    name: "Redis".into(),
                    reason: "Action Cable, Sidekiq, and cache store".into(),
                    priority: "recommended".into(),
                    category: "cache".into(),
                    docker_image: "redis:7-alpine".into(),
                    ansible_role: "redis".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([{"host_port": "6379", "container_port": "6379"}]),
                    volumes: json!([{"host_path": "redis_data", "container_path": "/data"}]),
                    notes: "Set REDIS_URL=redis://redis:6379/0".into(),
                },
                ServiceRecommendation {
                    code: "traefik".into(),
                    name: "Traefik".into(),
                    reason: "Reverse proxy with SSL".into(),
                    priority: "recommended".into(),
                    category: "proxy".into(),
                    docker_image: "traefik:v3.0".into(),
                    ansible_role: "traefik".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "80", "container_port": "80"},
                        {"host_port": "443", "container_port": "443"}
                    ]),
                    volumes: json!([
                        {"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock"},
                        {"host_path": "traefik_certs", "container_path": "/letsencrypt"}
                    ]),
                    notes: "".into(),
                },
            ],
            development: vec![
                ServiceRecommendation {
                    code: "mailhog".into(),
                    name: "MailHog".into(),
                    reason: "Email testing in development".into(),
                    priority: "optional".into(),
                    category: "mail".into(),
                    docker_image: "mailhog/mailhog:latest".into(),
                    ansible_role: "mailhog".into(),
                    has_local_role: true,
                    has_local_app: false,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "1025", "container_port": "1025"},
                        {"host_port": "8025", "container_port": "8025"}
                    ]),
                    volumes: json!([]),
                    notes: "".into(),
                },
            ],
        },

        // ── AI / ML Stacks ───────────────────────────────────────────
        StackBlueprint {
            triggers: vec!["openwebui", "langflow", "flowise", "litellm", "ai-workbench", "dify", "tensorflow"],
            production: vec![
                ServiceRecommendation {
                    code: "postgres".into(),
                    name: "PostgreSQL".into(),
                    reason: "Persistent storage for AI/ML metadata and configurations".into(),
                    priority: "recommended".into(),
                    category: "database".into(),
                    docker_image: "postgres:16-alpine".into(),
                    ansible_role: "postgres".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({
                        "POSTGRES_DB": "ai_db",
                        "POSTGRES_USER": "ai",
                        "POSTGRES_PASSWORD": "changeme"
                    }),
                    ports: json!([{"host_port": "5432", "container_port": "5432"}]),
                    volumes: json!([{"host_path": "postgres_data", "container_path": "/var/lib/postgresql/data"}]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "qdrant".into(),
                    name: "Qdrant".into(),
                    reason: "Vector database for RAG, embeddings, and semantic search".into(),
                    priority: "recommended".into(),
                    category: "database".into(),
                    docker_image: "qdrant/qdrant:latest".into(),
                    ansible_role: "qdrant".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "6333", "container_port": "6333"},
                        {"host_port": "6334", "container_port": "6334"}
                    ]),
                    volumes: json!([{"host_path": "qdrant_data", "container_path": "/qdrant/storage"}]),
                    notes: "REST API on 6333, gRPC on 6334. Essential for RAG workflows.".into(),
                },
                ServiceRecommendation {
                    code: "redis".into(),
                    name: "Redis".into(),
                    reason: "Caching layer for LLM responses and session management".into(),
                    priority: "recommended".into(),
                    category: "cache".into(),
                    docker_image: "redis:7-alpine".into(),
                    ansible_role: "redis".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([{"host_port": "6379", "container_port": "6379"}]),
                    volumes: json!([{"host_path": "redis_data", "container_path": "/data"}]),
                    notes: "Cache LLM responses to reduce API costs.".into(),
                },
                ServiceRecommendation {
                    code: "traefik".into(),
                    name: "Traefik".into(),
                    reason: "Reverse proxy for secure HTTPS access".into(),
                    priority: "recommended".into(),
                    category: "proxy".into(),
                    docker_image: "traefik:v3.0".into(),
                    ansible_role: "traefik".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "80", "container_port": "80"},
                        {"host_port": "443", "container_port": "443"}
                    ]),
                    volumes: json!([
                        {"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock"},
                        {"host_path": "traefik_certs", "container_path": "/letsencrypt"}
                    ]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "minio".into(),
                    name: "MinIO".into(),
                    reason: "S3-compatible object storage for models, datasets, and artifacts".into(),
                    priority: "optional".into(),
                    category: "storage".into(),
                    docker_image: "minio/minio:latest".into(),
                    ansible_role: "minio".into(),
                    has_local_role: true,
                    has_local_app: false,
                    environment: json!({
                        "MINIO_ROOT_USER": "minioadmin",
                        "MINIO_ROOT_PASSWORD": "minioadmin"
                    }),
                    ports: json!([
                        {"host_port": "9000", "container_port": "9000"},
                        {"host_port": "9001", "container_port": "9001"}
                    ]),
                    volumes: json!([{"host_path": "minio_data", "container_path": "/data"}]),
                    notes: "API on 9000, console on 9001.".into(),
                },
            ],
            development: vec![],
        },

        // ── ELK / Monitoring ─────────────────────────────────────────
        StackBlueprint {
            triggers: vec!["elk", "elk_wazuh", "ewazuh", "wazuh", "zabbix"],
            production: vec![
                ServiceRecommendation {
                    code: "traefik".into(),
                    name: "Traefik".into(),
                    reason: "Reverse proxy for dashboard access".into(),
                    priority: "recommended".into(),
                    category: "proxy".into(),
                    docker_image: "traefik:v3.0".into(),
                    ansible_role: "traefik".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "80", "container_port": "80"},
                        {"host_port": "443", "container_port": "443"}
                    ]),
                    volumes: json!([
                        {"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock"},
                        {"host_path": "traefik_certs", "container_path": "/letsencrypt"}
                    ]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "telegraf".into(),
                    name: "Telegraf".into(),
                    reason: "System metrics collection agent".into(),
                    priority: "recommended".into(),
                    category: "monitoring".into(),
                    docker_image: "telegraf:1.30-alpine".into(),
                    ansible_role: "telegraf".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([]),
                    volumes: json!([{"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock:ro"}]),
                    notes: "".into(),
                },
            ],
            development: vec![],
        },

        // ── GitLab ───────────────────────────────────────────────────
        StackBlueprint {
            triggers: vec!["gitlab_server"],
            production: vec![
                ServiceRecommendation {
                    code: "postgres".into(),
                    name: "PostgreSQL".into(),
                    reason: "GitLab's required database backend".into(),
                    priority: "required".into(),
                    category: "database".into(),
                    docker_image: "postgres:16-alpine".into(),
                    ansible_role: "postgres".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({
                        "POSTGRES_DB": "gitlabhq_production",
                        "POSTGRES_USER": "gitlab",
                        "POSTGRES_PASSWORD": "changeme"
                    }),
                    ports: json!([{"host_port": "5432", "container_port": "5432"}]),
                    volumes: json!([{"host_path": "postgres_data", "container_path": "/var/lib/postgresql/data"}]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "redis".into(),
                    name: "Redis".into(),
                    reason: "Required by GitLab for caching and background jobs".into(),
                    priority: "required".into(),
                    category: "cache".into(),
                    docker_image: "redis:7-alpine".into(),
                    ansible_role: "redis".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([{"host_port": "6379", "container_port": "6379"}]),
                    volumes: json!([{"host_path": "redis_data", "container_path": "/data"}]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "traefik".into(),
                    name: "Traefik".into(),
                    reason: "SSL termination and routing".into(),
                    priority: "recommended".into(),
                    category: "proxy".into(),
                    docker_image: "traefik:v3.0".into(),
                    ansible_role: "traefik".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "80", "container_port": "80"},
                        {"host_port": "443", "container_port": "443"}
                    ]),
                    volumes: json!([
                        {"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock"},
                        {"host_path": "traefik_certs", "container_path": "/letsencrypt"}
                    ]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "minio".into(),
                    name: "MinIO".into(),
                    reason: "Object storage for Git LFS, artifacts, uploads".into(),
                    priority: "optional".into(),
                    category: "storage".into(),
                    docker_image: "minio/minio:latest".into(),
                    ansible_role: "minio".into(),
                    has_local_role: true,
                    has_local_app: false,
                    environment: json!({
                        "MINIO_ROOT_USER": "minioadmin",
                        "MINIO_ROOT_PASSWORD": "minioadmin"
                    }),
                    ports: json!([
                        {"host_port": "9000", "container_port": "9000"},
                        {"host_port": "9001", "container_port": "9001"}
                    ]),
                    volumes: json!([{"host_path": "minio_data", "container_path": "/data"}]),
                    notes: "Replaces local file storage for scalability.".into(),
                },
            ],
            development: vec![],
        },

        // ── Mautic (Marketing Automation) ────────────────────────────
        StackBlueprint {
            triggers: vec!["mautic"],
            production: vec![
                ServiceRecommendation {
                    code: "mysql".into(),
                    name: "MySQL".into(),
                    reason: "Mautic's primary database".into(),
                    priority: "required".into(),
                    category: "database".into(),
                    docker_image: "mysql:8.0".into(),
                    ansible_role: "mysql".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({
                        "MYSQL_ROOT_PASSWORD": "changeme_root",
                        "MYSQL_DATABASE": "mautic",
                        "MYSQL_USER": "mautic",
                        "MYSQL_PASSWORD": "changeme"
                    }),
                    ports: json!([{"host_port": "3306", "container_port": "3306"}]),
                    volumes: json!([{"host_path": "mysql_data", "container_path": "/var/lib/mysql"}]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "rabbitmq".into(),
                    name: "RabbitMQ".into(),
                    reason: "Message queue for Mautic campaign processing".into(),
                    priority: "recommended".into(),
                    category: "queue".into(),
                    docker_image: "rabbitmq:3-management-alpine".into(),
                    ansible_role: "rabbitmq".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({
                        "RABBITMQ_DEFAULT_USER": "mautic",
                        "RABBITMQ_DEFAULT_PASS": "changeme"
                    }),
                    ports: json!([
                        {"host_port": "5672", "container_port": "5672"},
                        {"host_port": "15672", "container_port": "15672"}
                    ]),
                    volumes: json!([{"host_path": "rabbitmq_data", "container_path": "/var/lib/rabbitmq"}]),
                    notes: "Processes email campaigns asynchronously.".into(),
                },
                ServiceRecommendation {
                    code: "traefik".into(),
                    name: "Traefik".into(),
                    reason: "Reverse proxy with SSL".into(),
                    priority: "recommended".into(),
                    category: "proxy".into(),
                    docker_image: "traefik:v3.0".into(),
                    ansible_role: "traefik".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "80", "container_port": "80"},
                        {"host_port": "443", "container_port": "443"}
                    ]),
                    volumes: json!([
                        {"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock"},
                        {"host_path": "traefik_certs", "container_path": "/letsencrypt"}
                    ]),
                    notes: "".into(),
                },
            ],
            development: vec![
                ServiceRecommendation {
                    code: "mailhog".into(),
                    name: "MailHog".into(),
                    reason: "Catch test campaign emails in development".into(),
                    priority: "recommended".into(),
                    category: "mail".into(),
                    docker_image: "mailhog/mailhog:latest".into(),
                    ansible_role: "mailhog".into(),
                    has_local_role: true,
                    has_local_app: false,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "1025", "container_port": "1025"},
                        {"host_port": "8025", "container_port": "8025"}
                    ]),
                    volumes: json!([]),
                    notes: "Prevents sending real campaign emails during testing.".into(),
                },
            ],
        },

        // ── MongoDB-based stacks ─────────────────────────────────────
        StackBlueprint {
            triggers: vec!["mongodb", "rocketchat", "wekan"],
            production: vec![
                ServiceRecommendation {
                    code: "mongodb".into(),
                    name: "MongoDB".into(),
                    reason: "Document database required by this application".into(),
                    priority: "required".into(),
                    category: "database".into(),
                    docker_image: "mongo:7".into(),
                    ansible_role: "mongodb".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({
                        "MONGO_INITDB_ROOT_USERNAME": "admin",
                        "MONGO_INITDB_ROOT_PASSWORD": "changeme"
                    }),
                    ports: json!([{"host_port": "27017", "container_port": "27017"}]),
                    volumes: json!([{"host_path": "mongodb_data", "container_path": "/data/db"}]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "traefik".into(),
                    name: "Traefik".into(),
                    reason: "Reverse proxy with SSL".into(),
                    priority: "recommended".into(),
                    category: "proxy".into(),
                    docker_image: "traefik:v3.0".into(),
                    ansible_role: "traefik".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "80", "container_port": "80"},
                        {"host_port": "443", "container_port": "443"}
                    ]),
                    volumes: json!([
                        {"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock"},
                        {"host_path": "traefik_certs", "container_path": "/letsencrypt"}
                    ]),
                    notes: "".into(),
                },
            ],
            development: vec![],
        },

        // ── E-Commerce (WooCommerce, OroCommerce, Sylius, Oscar) ────
        StackBlueprint {
            triggers: vec!["wordpress_woocommerce", "orocommerce", "sylius", "oscar"],
            production: vec![
                ServiceRecommendation {
                    code: "redis".into(),
                    name: "Redis".into(),
                    reason: "Session & cache for e-commerce performance".into(),
                    priority: "recommended".into(),
                    category: "cache".into(),
                    docker_image: "redis:7-alpine".into(),
                    ansible_role: "redis".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([{"host_port": "6379", "container_port": "6379"}]),
                    volumes: json!([{"host_path": "redis_data", "container_path": "/data"}]),
                    notes: "Dramatically improves page load for product catalogs.".into(),
                },
                ServiceRecommendation {
                    code: "elasticsearch".into(),
                    name: "Elasticsearch".into(),
                    reason: "Full-text product search".into(),
                    priority: "optional".into(),
                    category: "search".into(),
                    docker_image: "elasticsearch:8.12.0".into(),
                    ansible_role: "".into(),
                    has_local_role: false,
                    has_local_app: false,
                    environment: json!({
                        "discovery.type": "single-node",
                        "xpack.security.enabled": "false",
                        "ES_JAVA_OPTS": "-Xms512m -Xmx512m"
                    }),
                    ports: json!([{"host_port": "9200", "container_port": "9200"}]),
                    volumes: json!([{"host_path": "es_data", "container_path": "/usr/share/elasticsearch/data"}]),
                    notes: "From Docker Hub. Needs 2GB+ RAM. Improves product search dramatically.".into(),
                },
            ],
            development: vec![],
        },

        // ── CRM / Project Management ─────────────────────────────────
        StackBlueprint {
            triggers: vec!["orocrm", "suitecrm", "redmine", "taiga"],
            production: vec![
                ServiceRecommendation {
                    code: "postgres".into(),
                    name: "PostgreSQL".into(),
                    reason: "Primary database".into(),
                    priority: "required".into(),
                    category: "database".into(),
                    docker_image: "postgres:16-alpine".into(),
                    ansible_role: "postgres".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({
                        "POSTGRES_DB": "app_db",
                        "POSTGRES_USER": "app",
                        "POSTGRES_PASSWORD": "changeme"
                    }),
                    ports: json!([{"host_port": "5432", "container_port": "5432"}]),
                    volumes: json!([{"host_path": "postgres_data", "container_path": "/var/lib/postgresql/data"}]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "redis".into(),
                    name: "Redis".into(),
                    reason: "Caching and session storage".into(),
                    priority: "recommended".into(),
                    category: "cache".into(),
                    docker_image: "redis:7-alpine".into(),
                    ansible_role: "redis".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([{"host_port": "6379", "container_port": "6379"}]),
                    volumes: json!([{"host_path": "redis_data", "container_path": "/data"}]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "traefik".into(),
                    name: "Traefik".into(),
                    reason: "Reverse proxy with SSL".into(),
                    priority: "recommended".into(),
                    category: "proxy".into(),
                    docker_image: "traefik:v3.0".into(),
                    ansible_role: "traefik".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "80", "container_port": "80"},
                        {"host_port": "443", "container_port": "443"}
                    ]),
                    volumes: json!([
                        {"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock"},
                        {"host_path": "traefik_certs", "container_path": "/letsencrypt"}
                    ]),
                    notes: "".into(),
                },
            ],
            development: vec![],
        },

        // ── Container Management (Portainer, Dockge, Komodo) ─────────
        StackBlueprint {
            triggers: vec!["portainer", "portainer-ce", "dockge", "komodo"],
            production: vec![
                ServiceRecommendation {
                    code: "traefik".into(),
                    name: "Traefik".into(),
                    reason: "Secure HTTPS access to management dashboard".into(),
                    priority: "recommended".into(),
                    category: "proxy".into(),
                    docker_image: "traefik:v3.0".into(),
                    ansible_role: "traefik".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "80", "container_port": "80"},
                        {"host_port": "443", "container_port": "443"}
                    ]),
                    volumes: json!([
                        {"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock"},
                        {"host_path": "traefik_certs", "container_path": "/letsencrypt"}
                    ]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "telegraf".into(),
                    name: "Telegraf".into(),
                    reason: "Metrics collection to complement container management".into(),
                    priority: "optional".into(),
                    category: "monitoring".into(),
                    docker_image: "telegraf:1.30-alpine".into(),
                    ansible_role: "telegraf".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([]),
                    volumes: json!([{"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock:ro"}]),
                    notes: "".into(),
                },
            ],
            development: vec![],
        },

        // ── Go (Gin) ────────────────────────────────────────────────
        StackBlueprint {
            triggers: vec!["gin"],
            production: vec![
                ServiceRecommendation {
                    code: "postgres".into(),
                    name: "PostgreSQL".into(),
                    reason: "Popular database choice for Go services".into(),
                    priority: "recommended".into(),
                    category: "database".into(),
                    docker_image: "postgres:16-alpine".into(),
                    ansible_role: "postgres".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({
                        "POSTGRES_DB": "app_db",
                        "POSTGRES_USER": "app",
                        "POSTGRES_PASSWORD": "changeme"
                    }),
                    ports: json!([{"host_port": "5432", "container_port": "5432"}]),
                    volumes: json!([{"host_path": "postgres_data", "container_path": "/var/lib/postgresql/data"}]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "redis".into(),
                    name: "Redis".into(),
                    reason: "Caching and session storage".into(),
                    priority: "recommended".into(),
                    category: "cache".into(),
                    docker_image: "redis:7-alpine".into(),
                    ansible_role: "redis".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([{"host_port": "6379", "container_port": "6379"}]),
                    volumes: json!([{"host_path": "redis_data", "container_path": "/data"}]),
                    notes: "".into(),
                },
                ServiceRecommendation {
                    code: "traefik".into(),
                    name: "Traefik".into(),
                    reason: "Reverse proxy".into(),
                    priority: "recommended".into(),
                    category: "proxy".into(),
                    docker_image: "traefik:v3.0".into(),
                    ansible_role: "traefik".into(),
                    has_local_role: true,
                    has_local_app: true,
                    environment: json!({}),
                    ports: json!([
                        {"host_port": "80", "container_port": "80"},
                        {"host_port": "443", "container_port": "443"}
                    ]),
                    volumes: json!([
                        {"host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock"},
                        {"host_path": "traefik_certs", "container_path": "/letsencrypt"}
                    ]),
                    notes: "".into(),
                },
            ],
            development: vec![],
        },
    ]
}

#[async_trait]
impl ToolHandler for RecommendStackServicesTool {
    async fn execute(&self, args: Value, _context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            /// App/role codes currently in the stack (e.g. ["wordpress", "mysql"])
            current_services: Vec<String>,
            /// "production" or "development"
            #[serde(default = "default_stack_type")]
            stack_type: String,
            /// "ssh" or "status_panel"
            #[serde(default = "default_deployment_method")]
            deployment_method: String,
        }

        fn default_stack_type() -> String {
            "production".into()
        }
        fn default_deployment_method() -> String {
            "ssh".into()
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let current_codes: Vec<String> = params
            .current_services
            .iter()
            .map(|s| s.to_lowercase().trim().to_string())
            .collect();

        let blueprints = build_blueprints();
        let is_prod = params.stack_type.to_lowercase() != "development";
        let is_ssh = params.deployment_method.to_lowercase() == "ssh";

        // Collect matching production recommendations
        let mut prod_recs: Vec<ServiceRecommendation> = Vec::new();
        let mut dev_recs: Vec<ServiceRecommendation> = Vec::new();
        let mut matched_templates: Vec<String> = Vec::new();

        for bp in &blueprints {
            let matches: Vec<&str> = bp
                .triggers
                .iter()
                .filter(|t| current_codes.iter().any(|c| c == *t))
                .copied()
                .collect();

            if matches.is_empty() {
                continue;
            }

            matched_templates.extend(matches.iter().map(|s| s.to_string()));

            // Add production recommendations
            for rec in &bp.production {
                if !current_codes.contains(&rec.code.to_lowercase())
                    && !prod_recs.iter().any(|r| r.code == rec.code)
                {
                    prod_recs.push(rec.clone());
                }
            }

            // Add development recommendations (if requested)
            if !is_prod {
                for rec in &bp.development {
                    if !current_codes.contains(&rec.code.to_lowercase())
                        && !dev_recs.iter().any(|r| r.code == rec.code)
                        && !prod_recs.iter().any(|r| r.code == rec.code)
                    {
                        dev_recs.push(rec.clone());
                    }
                }
            }
        }

        // Sort: required first, then recommended, then optional
        let priority_order = |p: &str| match p {
            "required" => 0,
            "recommended" => 1,
            "optional" => 2,
            _ => 3,
        };
        prod_recs.sort_by_key(|r| priority_order(&r.priority));
        dev_recs.sort_by_key(|r| priority_order(&r.priority));

        // Filter based on deployment method
        let filter_for_method = |recs: &[ServiceRecommendation]| -> Vec<Value> {
            recs.iter()
                .map(|r| {
                    let mut rec = json!({
                        "code": r.code,
                        "name": r.name,
                        "reason": r.reason,
                        "priority": r.priority,
                        "category": r.category,
                        "docker_image": r.docker_image,
                        "has_local_role": r.has_local_role,
                        "has_local_app": r.has_local_app,
                        "environment": r.environment,
                        "ports": r.ports,
                        "volumes": r.volumes,
                    });
                    if !r.notes.is_empty() {
                        rec["notes"] = json!(r.notes);
                    }
                    if is_ssh && r.has_local_role {
                        rec["ansible_role"] = json!(r.ansible_role);
                        rec["install_method"] = json!("ansible_role");
                    } else {
                        rec["install_method"] = json!("docker_compose");
                    }
                    rec
                })
                .collect()
        };

        let production_json = filter_for_method(&prod_recs);
        let development_json = filter_for_method(&dev_recs);

        let total = production_json.len() + development_json.len();
        let summary = if matched_templates.is_empty() {
            "No matching blueprints found for the current services. You can still add services manually via the template selector or Docker Hub search.".to_string()
        } else {
            format!(
                "Found {} recommendation(s) for stack containing [{}]. {} for production{}.",
                total,
                matched_templates.join(", "),
                production_json.len(),
                if !development_json.is_empty() {
                    format!(", {} for development", development_json.len())
                } else {
                    String::new()
                }
            )
        };

        let result = json!({
            "matched_templates": matched_templates,
            "stack_type": params.stack_type,
            "deployment_method": params.deployment_method,
            "summary": summary,
            "production": production_json,
            "development": development_json,
            "instructions": "Present these recommendations to the user grouped by purpose. For each service, explain why it's needed and show the suggested configuration. Ask the user which services to add, then use create_project_app to add each selected service with the suggested configuration."
        });

        tracing::info!(
            "Recommended {} services for stack with [{}]",
            total,
            current_codes.join(", ")
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "recommend_stack_services".to_string(),
            description: "Get AI-powered service recommendations for a stack based on the selected template(s). Returns categorized suggestions (production vs development) with configurations (env vars, ports, volumes) tailored to the deployment method (SSH/Ansible or Status Panel). Use this when a user selects a template to suggest complementary services.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "current_services": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Array of app/role codes currently in the stack (e.g. [\"wordpress\", \"mysql\"])"
                    },
                    "stack_type": {
                        "type": "string",
                        "enum": ["production", "development"],
                        "description": "Whether this is a production or development stack (default: production)"
                    },
                    "deployment_method": {
                        "type": "string",
                        "enum": ["ssh", "status_panel"],
                        "description": "Deployment method: 'ssh' for Ansible roles, 'status_panel' for Docker Compose (default: ssh)"
                    }
                },
                "required": ["current_services"]
            }),
        }
    }
}
