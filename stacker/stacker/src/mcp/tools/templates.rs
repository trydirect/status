use async_trait::async_trait;
use serde_json::{json, Value};

use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use serde::Deserialize;

/// Suggest appropriate resource limits for an application type
pub struct SuggestResourcesTool;

#[async_trait]
impl ToolHandler for SuggestResourcesTool {
    async fn execute(&self, args: Value, _context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            app_type: String,
            #[serde(default)]
            expected_traffic: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Heuristic-based recommendations
        let (base_cpu, base_ram, base_storage) = match params.app_type.to_lowercase().as_str() {
            "wordpress" | "cms" => (1.0, 2.0, 20.0),
            "nodejs" | "express" | "nextjs" => (1.0, 1.0, 10.0),
            "django" | "flask" | "python" => (2.0, 2.0, 15.0),
            "react" | "vue" | "frontend" => (1.0, 1.0, 5.0),
            "mysql" | "mariadb" => (2.0, 4.0, 50.0),
            "postgresql" | "postgres" => (2.0, 4.0, 100.0),
            "redis" | "memcached" | "cache" => (1.0, 1.0, 5.0),
            "mongodb" | "nosql" => (2.0, 4.0, 100.0),
            "nginx" | "apache" | "traefik" | "proxy" => (0.5, 0.5, 2.0),
            "rabbitmq" | "kafka" | "queue" => (2.0, 4.0, 20.0),
            "elasticsearch" | "search" => (4.0, 8.0, 200.0),
            _ => (1.0, 1.0, 10.0), // Default
        };

        // Multiplier for traffic level
        let multiplier = match params.expected_traffic.as_deref() {
            Some("high") => 3.0,
            Some("medium") => 1.5,
            Some("low") | None | Some("") => 1.0,
            _ => 1.0,
        };

        let final_cpu = ((base_cpu as f64) * multiplier).ceil() as i32;
        let final_ram = ((base_ram as f64) * multiplier).ceil() as i32;
        let final_storage = (base_storage * multiplier).ceil() as i32;

        let traffic_label = params
            .expected_traffic
            .clone()
            .unwrap_or_else(|| "low".to_string());

        let result = json!({
            "app_type": params.app_type,
            "expected_traffic": traffic_label,
            "recommendations": {
                "cpu": final_cpu,
                "cpu_unit": "cores",
                "ram": final_ram,
                "ram_unit": "GB",
                "storage": final_storage,
                "storage_unit": "GB"
            },
            "summary": format!(
                "For {} with {} traffic: {} cores, {} GB RAM, {} GB storage",
                params.app_type, traffic_label, final_cpu, final_ram, final_storage
            ),
            "notes": match params.app_type.to_lowercase().as_str() {
                "wordpress" => "Recommended setup includes WordPress + MySQL. Add MySQL with 4GB RAM and 50GB storage.",
                "nodejs" => "Lightweight runtime. Add database separately if needed.",
                "postgresql" => "Database server. Allocate adequate storage for backups.",
                "mysql" => "Database server. Consider replication for HA.",
                _ => "Adjust resources based on your workload."
            }
        });

        tracing::info!(
            "Suggested resources for {} with {} traffic",
            params.app_type,
            traffic_label
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "suggest_resources".to_string(),
            description: "Get AI-powered resource recommendations (CPU, RAM, storage) for an application type and expected traffic level".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "app_type": {
                        "type": "string",
                        "description": "Application type (e.g., 'wordpress', 'nodejs', 'postgresql', 'django')"
                    },
                    "expected_traffic": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                        "description": "Expected traffic level (optional, default: low)"
                    }
                },
                "required": ["app_type"]
            }),
        }
    }
}

/// List available templates/stack configurations
pub struct ListTemplatesTool;

#[async_trait]
impl ToolHandler for ListTemplatesTool {
    async fn execute(&self, args: Value, _context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            category: Option<String>,
            #[serde(default)]
            search: Option<String>,
        }

        let params: Args = serde_json::from_value(args).unwrap_or(Args {
            category: None,
            search: None,
        });

        // For now, return curated list of popular templates
        // In Phase 3, this will query the database for public ratings
        let templates = vec![
            json!({
                "id": "wordpress-mysql",
                "name": "WordPress with MySQL",
                "description": "Complete WordPress blog/site with MySQL database",
                "category": "cms",
                "services": ["wordpress", "mysql"],
                "rating": 4.8,
                "downloads": 1250
            }),
            json!({
                "id": "nodejs-express",
                "name": "Node.js Express API",
                "description": "RESTful API server with Express.js",
                "category": "api",
                "services": ["nodejs"],
                "rating": 4.6,
                "downloads": 850
            }),
            json!({
                "id": "nextjs-postgres",
                "name": "Next.js Full Stack",
                "description": "Next.js frontend + PostgreSQL database",
                "category": "web",
                "services": ["nextjs", "postgresql"],
                "rating": 4.7,
                "downloads": 920
            }),
            json!({
                "id": "django-postgres",
                "name": "Django Web Application",
                "description": "Django web framework with PostgreSQL",
                "category": "web",
                "services": ["django", "postgresql"],
                "rating": 4.5,
                "downloads": 680
            }),
            json!({
                "id": "lamp-stack",
                "name": "LAMP Stack",
                "description": "Linux + Apache + MySQL + PHP",
                "category": "web",
                "services": ["apache", "php", "mysql"],
                "rating": 4.4,
                "downloads": 560
            }),
            json!({
                "id": "elasticsearch-kibana",
                "name": "ELK Stack",
                "description": "Elasticsearch + Logstash + Kibana for logging",
                "category": "infrastructure",
                "services": ["elasticsearch", "kibana"],
                "rating": 4.7,
                "downloads": 730
            }),
        ];

        // Filter by category if provided
        let filtered = if let Some(cat) = params.category {
            templates
                .into_iter()
                .filter(|t| {
                    t["category"]
                        .as_str()
                        .unwrap_or("")
                        .eq_ignore_ascii_case(&cat)
                })
                .collect::<Vec<_>>()
        } else {
            templates
        };

        // Filter by search term if provided
        let final_list = if let Some(search) = params.search {
            filtered
                .into_iter()
                .filter(|t| {
                    let name = t["name"].as_str().unwrap_or("");
                    let desc = t["description"].as_str().unwrap_or("");
                    name.to_lowercase().contains(&search.to_lowercase())
                        || desc.to_lowercase().contains(&search.to_lowercase())
                })
                .collect()
        } else {
            filtered
        };

        let result = json!({
            "count": final_list.len(),
            "templates": final_list
        });

        tracing::info!("Listed {} templates", final_list.len());

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_templates".to_string(),
            description: "Browse available stack templates (WordPress, Node.js, Django, etc.) with ratings and descriptions".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "enum": ["cms", "api", "web", "database", "infrastructure"],
                        "description": "Filter by template category (optional)"
                    },
                    "search": {
                        "type": "string",
                        "description": "Search templates by name or description (optional)"
                    }
                },
                "required": []
            }),
        }
    }
}

/// Validate domain name format
pub struct ValidateDomainTool;

#[async_trait]
impl ToolHandler for ValidateDomainTool {
    async fn execute(&self, args: Value, _context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            domain: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Simple domain validation regex
        let domain_regex =
            regex::Regex::new(r"^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$").unwrap();

        let is_valid = domain_regex.is_match(&params.domain.to_lowercase());

        let result = json!({
            "domain": params.domain,
            "valid": is_valid,
            "message": if is_valid {
                "Domain format is valid"
            } else {
                "Invalid domain format"
            }
        });

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "validate_domain".to_string(),
            description: "Validate domain name format".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name to validate (e.g., 'example.com')"
                    }
                },
                "required": ["domain"]
            }),
        }
    }
}
