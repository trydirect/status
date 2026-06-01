//! Service catalog — resolves service names to `ServiceDefinition` templates.
//!
//! Two sources:
//! 1. **Hardcoded blueprints** — curated set extracted from MCP recommendations.
//!    Works offline, no authentication needed.
//! 2. **Marketplace API** — fetches from the Stacker server when authenticated.
//!    Falls back to hardcoded if the API is unreachable.

use std::collections::HashMap;

use crate::cli::config_parser::ServiceDefinition;
use crate::cli::error::CliError;
use crate::cli::stacker_client::StackerClient;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CatalogEntry — a service template with metadata
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
pub struct CatalogEntry {
    pub code: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub service: ServiceDefinition,
    /// Services that are commonly added alongside this one
    pub related: Vec<String>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ServiceCatalog
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct ServiceCatalog {
    client: Option<StackerClient>,
}

impl ServiceCatalog {
    /// Create a catalog with optional server API access.
    pub fn new(client: Option<StackerClient>) -> Self {
        Self { client }
    }

    /// Create a catalog that only uses hardcoded blueprints (offline).
    pub fn offline() -> Self {
        Self { client: None }
    }

    /// Resolve a service name (or alias) to a `ServiceDefinition`.
    /// Tries marketplace API first (if client available), falls back to hardcoded.
    pub async fn resolve(&self, service_name: &str) -> Result<CatalogEntry, CliError> {
        let canonical = Self::resolve_alias(service_name);

        // Try marketplace API if we have a client
        if let Some(client) = &self.client {
            if let Ok(Some(entry)) = self.try_marketplace(client, &canonical).await {
                return Ok(entry);
            }
            // Fall through to hardcoded on failure
        }

        // Hardcoded catalog lookup
        self.lookup_hardcoded(&canonical).ok_or_else(|| {
            CliError::ConfigValidation(format!(
                "Unknown service '{}'. Run `stacker service list` to see available services.",
                service_name
            ))
        })
    }

    /// List all available services from the hardcoded catalog.
    pub fn list_available(&self) -> Vec<CatalogEntry> {
        build_hardcoded_catalog()
    }

    /// Try fetching a service template from the marketplace API.
    async fn try_marketplace(
        &self,
        client: &StackerClient,
        slug: &str,
    ) -> Result<Option<CatalogEntry>, CliError> {
        match client.get_marketplace_template(slug).await {
            Ok(Some(template)) => {
                // Extract service definition from the template's stack_definition
                if let Some(stack_def) = &template.stack_definition {
                    if let Some(services) = stack_def.get("services") {
                        if let Some(first_svc) = services.as_array().and_then(|arr| arr.first()) {
                            let service = ServiceDefinition {
                                name: first_svc["name"].as_str().unwrap_or(slug).to_string(),
                                image: first_svc["image"].as_str().unwrap_or("").to_string(),
                                ports: first_svc["ports"]
                                    .as_array()
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                                environment: first_svc["environment"]
                                    .as_object()
                                    .map(|obj| {
                                        obj.iter()
                                            .filter_map(|(k, v)| {
                                                v.as_str().map(|s| (k.clone(), s.to_string()))
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                                volumes: first_svc["volumes"]
                                    .as_array()
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                                depends_on: Vec::new(),
                            };

                            return Ok(Some(CatalogEntry {
                                code: slug.to_string(),
                                name: template.name,
                                category: template
                                    .category_code
                                    .unwrap_or_else(|| "service".to_string()),
                                description: template.description.unwrap_or_default(),
                                service,
                                related: vec![],
                            }));
                        }
                    }
                }
                Ok(None)
            }
            Ok(None) => Ok(None),
            Err(_) => Ok(None), // Silently fall back to hardcoded
        }
    }

    /// Look up a service in the hardcoded catalog.
    fn lookup_hardcoded(&self, code: &str) -> Option<CatalogEntry> {
        let catalog = build_hardcoded_catalog();
        catalog.into_iter().find(|e| e.code == code)
    }

    /// Resolve common aliases to canonical service names.
    pub fn resolve_alias(name: &str) -> String {
        let lower = name.to_lowercase().trim().to_string();
        match lower.as_str() {
            "wp" | "wordpress" => "wordpress".to_string(),
            "pg" | "postgresql" | "postgres" => "postgres".to_string(),
            "my" | "mysql" => "mysql".to_string(),
            "maria" | "mariadb" => "mariadb".to_string(),
            "mongo" | "mongodb" => "mongodb".to_string(),
            "es" | "elastic" | "elasticsearch" => "elasticsearch".to_string(),
            "mq" | "rabbit" | "rabbitmq" => "rabbitmq".to_string(),
            "npm" | "nginx-proxy-manager" => "nginx_proxy_manager".to_string(),
            "pma" | "phpmyadmin" => "phpmyadmin".to_string(),
            "mail" | "mailer" | "smtp" => "smtp".to_string(),
            "mh" | "mailhog" => "mailhog".to_string(),
            "rc" | "rocketchat" | "rocket.chat" | "rocket-chat" => "rocketchat".to_string(),
            "mm" | "mattermost" => "mattermost".to_string(),
            "gl" | "gitlab" | "gitlab-ce" | "gitlab_ce" => "gitlab_ce".to_string(),
            "wg" | "wireguard" => "wireguard".to_string(),
            "vpn" | "openvpn" => "openvpn".to_string(),
            "n8n" => "n8n".to_string(),
            "dify" => "dify".to_string(),
            "ollama" => "ollama".to_string(),
            "owui" | "openwebui" | "open-webui" => "openwebui".to_string(),
            "vault" => "vault".to_string(),
            "dk" | "dockge" => "dockge".to_string(),
            "od" | "odoo" => "odoo".to_string(),
            "sc" | "suitecrm" => "suitecrm".to_string(),
            "rm" | "redmine" => "redmine".to_string(),
            "op" | "openproject" => "openproject".to_string(),
            "jk" | "jenkins" => "jenkins".to_string(),
            "af" | "airflow" => "airflow".to_string(),
            "fa" | "fastapi" => "fastapi".to_string(),
            "fl" | "flask" => "flask".to_string(),
            "dj" | "django" => "django".to_string(),
            "lv" | "laravel" => "laravel".to_string(),
            "sf" | "symfony" => "symfony".to_string(),
            "gin" => "gin".to_string(),
            "ror" | "rails" | "rorrestful" => "rorrestful".to_string(),
            "wz" | "wazuh" => "wazuh".to_string(),
            "f2b" | "fail2ban" => "fail2ban".to_string(),
            "nd" | "netdata" => "netdata".to_string(),
            "pr" | "postgrest" => "postgrest".to_string(),
            "oc" | "openclaw" | "open-claw" => "openclaw".to_string(),
            _ => lower.replace('-', "_"),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Hardcoded service catalog
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn build_hardcoded_catalog() -> Vec<CatalogEntry> {
    vec![
        // ── Databases ────────────────────────────────────
        CatalogEntry {
            code: "postgres".into(),
            name: "PostgreSQL".into(),
            category: "database".into(),
            description: "Reliable open-source relational database".into(),
            service: ServiceDefinition {
                name: "postgres".into(),
                image: "postgres:16-alpine".into(),
                ports: vec!["5432:5432".into()],
                environment: HashMap::from([
                    ("POSTGRES_DB".into(), "app_db".into()),
                    ("POSTGRES_USER".into(), "app".into()),
                    ("POSTGRES_PASSWORD".into(), "changeme".into()),
                ]),
                volumes: vec!["postgres_data:/var/lib/postgresql/data".into()],
                depends_on: vec![],
            },
            related: vec!["redis".into()],
        },
        CatalogEntry {
            code: "mysql".into(),
            name: "MySQL".into(),
            category: "database".into(),
            description: "Popular open-source relational database".into(),
            service: ServiceDefinition {
                name: "mysql".into(),
                image: "mysql:8.0".into(),
                ports: vec!["3306:3306".into()],
                environment: HashMap::from([
                    ("MYSQL_ROOT_PASSWORD".into(), "changeme_root".into()),
                    ("MYSQL_DATABASE".into(), "app_db".into()),
                    ("MYSQL_USER".into(), "app".into()),
                    ("MYSQL_PASSWORD".into(), "changeme".into()),
                ]),
                volumes: vec!["mysql_data:/var/lib/mysql".into()],
                depends_on: vec![],
            },
            related: vec!["redis".into(), "phpmyadmin".into()],
        },
        CatalogEntry {
            code: "mongodb".into(),
            name: "MongoDB".into(),
            category: "database".into(),
            description: "Document-oriented NoSQL database".into(),
            service: ServiceDefinition {
                name: "mongodb".into(),
                image: "mongo:7".into(),
                ports: vec!["27017:27017".into()],
                environment: HashMap::from([
                    ("MONGO_INITDB_ROOT_USERNAME".into(), "admin".into()),
                    ("MONGO_INITDB_ROOT_PASSWORD".into(), "changeme".into()),
                ]),
                volumes: vec!["mongo_data:/data/db".into()],
                depends_on: vec![],
            },
            related: vec![],
        },
        // ── Cache ────────────────────────────────────────
        CatalogEntry {
            code: "redis".into(),
            name: "Redis".into(),
            category: "cache".into(),
            description: "In-memory data store for caching and message broker".into(),
            service: ServiceDefinition {
                name: "redis".into(),
                image: "redis:7-alpine".into(),
                ports: vec!["6379:6379".into()],
                environment: HashMap::new(),
                volumes: vec!["redis_data:/data".into()],
                depends_on: vec![],
            },
            related: vec![],
        },
        CatalogEntry {
            code: "memcached".into(),
            name: "Memcached".into(),
            category: "cache".into(),
            description: "High-performance distributed memory caching system".into(),
            service: ServiceDefinition {
                name: "memcached".into(),
                image: "memcached:1.6-alpine".into(),
                ports: vec!["11211:11211".into()],
                environment: HashMap::new(),
                volumes: vec![],
                depends_on: vec![],
            },
            related: vec![],
        },
        // ── Message Queues ───────────────────────────────
        CatalogEntry {
            code: "rabbitmq".into(),
            name: "RabbitMQ".into(),
            category: "queue".into(),
            description: "Advanced message broker with management UI".into(),
            service: ServiceDefinition {
                name: "rabbitmq".into(),
                image: "rabbitmq:3-management-alpine".into(),
                ports: vec!["5672:5672".into(), "15672:15672".into()],
                environment: HashMap::from([
                    ("RABBITMQ_DEFAULT_USER".into(), "app".into()),
                    ("RABBITMQ_DEFAULT_PASS".into(), "changeme".into()),
                ]),
                volumes: vec!["rabbitmq_data:/var/lib/rabbitmq".into()],
                depends_on: vec![],
            },
            related: vec![],
        },
        // ── Proxies ──────────────────────────────────────
        CatalogEntry {
            code: "traefik".into(),
            name: "Traefik".into(),
            category: "proxy".into(),
            description: "Cloud-native reverse proxy with automatic SSL".into(),
            service: ServiceDefinition {
                name: "traefik".into(),
                image: "traefik:v3.0".into(),
                ports: vec!["80:80".into(), "443:443".into()],
                environment: HashMap::new(),
                volumes: vec![
                    "/var/run/docker.sock:/var/run/docker.sock".into(),
                    "traefik_certs:/letsencrypt".into(),
                ],
                depends_on: vec![],
            },
            related: vec![],
        },
        CatalogEntry {
            code: "nginx".into(),
            name: "Nginx".into(),
            category: "proxy".into(),
            description: "High-performance web server and reverse proxy".into(),
            service: ServiceDefinition {
                name: "nginx".into(),
                image: "nginx:1.25-alpine".into(),
                ports: vec!["80:80".into(), "443:443".into()],
                environment: HashMap::new(),
                volumes: vec![],
                depends_on: vec![],
            },
            related: vec![],
        },
        CatalogEntry {
            code: "nginx_proxy_manager".into(),
            name: "Nginx Proxy Manager".into(),
            category: "proxy".into(),
            description: "Web UI for managing Nginx reverse proxy with SSL".into(),
            service: ServiceDefinition {
                name: "nginx_proxy_manager".into(),
                image: "jc21/nginx-proxy-manager:latest".into(),
                ports: vec!["80:80".into(), "443:443".into(), "81:81".into()],
                environment: HashMap::new(),
                volumes: vec![
                    "npm_data:/data".into(),
                    "npm_letsencrypt:/etc/letsencrypt".into(),
                ],
                depends_on: vec![],
            },
            related: vec![],
        },
        // ── Web Applications ─────────────────────────────
        CatalogEntry {
            code: "wordpress".into(),
            name: "WordPress".into(),
            category: "web".into(),
            description: "Popular CMS and blogging platform".into(),
            service: ServiceDefinition {
                name: "wordpress".into(),
                image: "wordpress:latest".into(),
                ports: vec!["8080:80".into()],
                environment: HashMap::from([
                    ("WORDPRESS_DB_HOST".into(), "mysql".into()),
                    ("WORDPRESS_DB_USER".into(), "wordpress".into()),
                    ("WORDPRESS_DB_PASSWORD".into(), "changeme".into()),
                    ("WORDPRESS_DB_NAME".into(), "wordpress".into()),
                ]),
                volumes: vec!["wordpress_data:/var/www/html".into()],
                depends_on: vec!["mysql".into()],
            },
            related: vec!["mysql".into(), "redis".into(), "traefik".into()],
        },
        // ── Search ───────────────────────────────────────
        CatalogEntry {
            code: "elasticsearch".into(),
            name: "Elasticsearch".into(),
            category: "search".into(),
            description: "Distributed search and analytics engine".into(),
            service: ServiceDefinition {
                name: "elasticsearch".into(),
                image: "elasticsearch:8.12.0".into(),
                ports: vec!["9200:9200".into()],
                environment: HashMap::from([
                    ("discovery.type".into(), "single-node".into()),
                    ("xpack.security.enabled".into(), "false".into()),
                    ("ES_JAVA_OPTS".into(), "-Xms512m -Xmx512m".into()),
                ]),
                volumes: vec!["es_data:/usr/share/elasticsearch/data".into()],
                depends_on: vec![],
            },
            related: vec!["kibana".into()],
        },
        CatalogEntry {
            code: "kibana".into(),
            name: "Kibana".into(),
            category: "search".into(),
            description: "Visualization dashboard for Elasticsearch".into(),
            service: ServiceDefinition {
                name: "kibana".into(),
                image: "kibana:8.12.0".into(),
                ports: vec!["5601:5601".into()],
                environment: HashMap::from([(
                    "ELASTICSEARCH_HOSTS".into(),
                    "http://elasticsearch:9200".into(),
                )]),
                volumes: vec![],
                depends_on: vec!["elasticsearch".into()],
            },
            related: vec!["elasticsearch".into()],
        },
        // ── Vector Databases ─────────────────────────────
        CatalogEntry {
            code: "qdrant".into(),
            name: "Qdrant".into(),
            category: "database".into(),
            description: "Vector similarity search engine for AI applications".into(),
            service: ServiceDefinition {
                name: "qdrant".into(),
                image: "qdrant/qdrant:latest".into(),
                ports: vec!["6333:6333".into(), "6334:6334".into()],
                environment: HashMap::new(),
                volumes: vec!["qdrant_data:/qdrant/storage".into()],
                depends_on: vec![],
            },
            related: vec![],
        },
        // ── Monitoring ───────────────────────────────────
        CatalogEntry {
            code: "telegraf".into(),
            name: "Telegraf".into(),
            category: "monitoring".into(),
            description: "Agent for collecting and reporting metrics".into(),
            service: ServiceDefinition {
                name: "telegraf".into(),
                image: "telegraf:1.30-alpine".into(),
                ports: vec![],
                environment: HashMap::new(),
                volumes: vec!["/var/run/docker.sock:/var/run/docker.sock:ro".into()],
                depends_on: vec![],
            },
            related: vec![],
        },
        // ── Dev Tools ────────────────────────────────────
        CatalogEntry {
            code: "phpmyadmin".into(),
            name: "phpMyAdmin".into(),
            category: "devtool".into(),
            description: "Web-based MySQL database management (development)".into(),
            service: ServiceDefinition {
                name: "phpmyadmin".into(),
                image: "phpmyadmin:latest".into(),
                ports: vec!["8081:80".into()],
                environment: HashMap::from([
                    ("PMA_HOST".into(), "mysql".into()),
                    ("PMA_PORT".into(), "3306".into()),
                ]),
                volumes: vec![],
                depends_on: vec!["mysql".into()],
            },
            related: vec!["mysql".into()],
        },
        CatalogEntry {
            code: "smtp".into(),
            name: "SMTP Test Server".into(),
            category: "mail".into(),
            description: "Attachable SMTP companion app for local delivery and relay testing"
                .into(),
            service: ServiceDefinition {
                name: "smtp".into(),
                image: "trydirect/smtp".into(),
                ports: vec!["1025:25".into()],
                environment: HashMap::from([
                    (
                        "RELAY_NETWORKS".into(),
                        ":127.0.0.0/8:10.0.0.0/8:172.16.0.0/12:192.168.0.0/16".into(),
                    ),
                    ("PORT".into(), "25".into()),
                ]),
                volumes: vec!["smtp_data:/data".into()],
                depends_on: vec![],
            },
            related: vec![],
        },
        CatalogEntry {
            code: "mailhog".into(),
            name: "MailHog".into(),
            category: "devtool".into(),
            description: "Email testing tool — catches all outgoing mail (development)".into(),
            service: ServiceDefinition {
                name: "mailhog".into(),
                image: "mailhog/mailhog:latest".into(),
                ports: vec!["1025:1025".into(), "8025:8025".into()],
                environment: HashMap::new(),
                volumes: vec![],
                depends_on: vec![],
            },
            related: vec![],
        },
        // ── Storage ──────────────────────────────────────
        CatalogEntry {
            code: "minio".into(),
            name: "MinIO".into(),
            category: "storage".into(),
            description: "S3-compatible object storage".into(),
            service: ServiceDefinition {
                name: "minio".into(),
                image: "minio/minio:latest".into(),
                ports: vec!["9000:9000".into(), "9001:9001".into()],
                environment: HashMap::from([
                    ("MINIO_ROOT_USER".into(), "admin".into()),
                    ("MINIO_ROOT_PASSWORD".into(), "changeme123".into()),
                ]),
                volumes: vec!["minio_data:/data".into()],
                depends_on: vec![],
            },
            related: vec![],
        },
        // ── Container Management ─────────────────────────
        CatalogEntry {
            code: "portainer".into(),
            name: "Portainer".into(),
            category: "devtool".into(),
            description: "Docker container management web UI".into(),
            service: ServiceDefinition {
                name: "portainer".into(),
                image: "portainer/portainer-ce:latest".into(),
                ports: vec!["9443:9443".into()],
                environment: HashMap::new(),
                volumes: vec![
                    "/var/run/docker.sock:/var/run/docker.sock".into(),
                    "portainer_data:/data".into(),
                ],
                depends_on: vec![],
            },
            related: vec![],
        },
        // ── AI Assistants ─────────────────────────────
        CatalogEntry {
            code: "openclaw".into(),
            name: "OpenClaw".into(),
            category: "ai".into(),
            description: "Personal AI assistant with multi-channel gateway".into(),
            service: ServiceDefinition {
                name: "openclaw".into(),
                image: "ghcr.io/openclaw/openclaw:latest".into(),
                ports: vec!["18789:18789".into()],
                environment: HashMap::from([("OPENCLAW_GATEWAY_BIND".into(), "lan".into())]),
                volumes: vec![
                    "openclaw_config:/home/node/.openclaw".into(),
                    "openclaw_workspace:/home/node/.openclaw/workspace".into(),
                ],
                depends_on: vec![],
            },
            related: vec![],
        },
    ]
}

/// Generate a compact summary of the hardcoded catalog for AI system prompts.
pub fn catalog_summary_for_ai() -> String {
    let catalog = build_hardcoded_catalog();
    let mut lines: Vec<String> = vec![
        "## Available service templates (use `add_service` tool to add to stacker.yml)".to_string(),
        "| Code | Name | Category | Default Image |".to_string(),
        "|------|------|----------|---------------|".to_string(),
    ];
    for entry in &catalog {
        lines.push(format!(
            "| {} | {} | {} | {} |",
            entry.code, entry.name, entry.category, entry.service.image
        ));
    }
    lines.push(String::new());
    lines.push("Common aliases: wp→wordpress, pg→postgres, my→mysql, mongo→mongodb, es→elasticsearch, mq→rabbitmq, pma→phpmyadmin, smtp→smtp, mail→smtp, mh→mailhog".to_string());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_alias_wordpress() {
        assert_eq!(ServiceCatalog::resolve_alias("wp"), "wordpress");
        assert_eq!(ServiceCatalog::resolve_alias("WordPress"), "wordpress");
    }

    #[test]
    fn test_resolve_alias_postgres() {
        assert_eq!(ServiceCatalog::resolve_alias("pg"), "postgres");
        assert_eq!(ServiceCatalog::resolve_alias("postgresql"), "postgres");
        assert_eq!(ServiceCatalog::resolve_alias("PostgreSQL"), "postgres");
    }

    #[test]
    fn test_resolve_alias_passthrough() {
        assert_eq!(ServiceCatalog::resolve_alias("redis"), "redis");
        assert_eq!(ServiceCatalog::resolve_alias("traefik"), "traefik");
    }

    #[test]
    fn test_resolve_alias_hyphen_to_underscore() {
        assert_eq!(
            ServiceCatalog::resolve_alias("nginx-proxy-manager"),
            "nginx_proxy_manager"
        );
    }

    #[test]
    fn test_resolve_alias_smtp_companion() {
        assert_eq!(ServiceCatalog::resolve_alias("smtp"), "smtp");
        assert_eq!(ServiceCatalog::resolve_alias("mail"), "smtp");
        assert_eq!(ServiceCatalog::resolve_alias("mailer"), "smtp");
    }

    #[test]
    fn test_hardcoded_catalog_not_empty() {
        let catalog = build_hardcoded_catalog();
        assert!(
            catalog.len() > 10,
            "Expected at least 10 services in catalog"
        );
    }

    #[test]
    fn test_lookup_hardcoded_postgres() {
        let cat = ServiceCatalog::offline();
        let entry = cat.lookup_hardcoded("postgres");
        assert!(entry.is_some());
        let e = entry.unwrap();
        assert_eq!(e.service.image, "postgres:16-alpine");
        assert!(e.service.ports.contains(&"5432:5432".to_string()));
    }

    #[test]
    fn test_lookup_hardcoded_smtp_companion() {
        let cat = ServiceCatalog::offline();
        let entry = cat.lookup_hardcoded("smtp").expect("smtp service exists");

        assert_eq!(entry.category, "mail");
        assert_eq!(entry.service.name, "smtp");
        assert_eq!(entry.service.image, "trydirect/smtp");
        assert!(entry.service.ports.contains(&"1025:25".to_string()));
        assert_eq!(
            entry.service.environment.get("PORT").map(String::as_str),
            Some("25")
        );
        assert_eq!(
            entry
                .service
                .environment
                .get("RELAY_NETWORKS")
                .map(String::as_str),
            Some(":127.0.0.0/8:10.0.0.0/8:172.16.0.0/12:192.168.0.0/16")
        );
    }

    #[test]
    fn test_lookup_hardcoded_unknown() {
        let cat = ServiceCatalog::offline();
        assert!(cat.lookup_hardcoded("nonexistent_service").is_none());
    }

    #[test]
    fn test_catalog_summary_for_ai_contains_key_services() {
        let summary = catalog_summary_for_ai();
        assert!(summary.contains("postgres"));
        assert!(summary.contains("wordpress"));
        assert!(summary.contains("redis"));
        assert!(summary.contains("smtp"));
        assert!(summary.contains("add_service"));
    }
}
