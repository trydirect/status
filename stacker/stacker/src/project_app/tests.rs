use crate::helpers::project::builder::generate_single_app_compose;

use super::mapping::{ProjectAppContext, ProjectAppPostArgs};
use super::{
    is_nginx_proxy_manager_identity, is_platform_managed_app_code,
    is_platform_managed_app_identity, project_app_from_post,
};
use serde_json::json;

/// Example payload from the user's request
fn example_deploy_app_payload() -> serde_json::Value {
    json!({
        "deployment_id": 13513,
        "app_code": "telegraf",
        "parameters": {
            "env": {
                "ansible_telegraf_influx_token": "FFolbg71mZjhKisMpAxYD5eEfxPtW3HRpTZHtv3XEYZRgzi3VGOxgLDhCYEvovMppvYuqSsbSTI8UFZqFwOx5Q==",
                "ansible_telegraf_influx_bucket": "srv_localhost",
                "ansible_telegraf_influx_org": "telegraf_org_4",
                "telegraf_flush_interval": "10s",
                "telegraf_interval": "10s",
                "telegraf_role": "server"
            },
            "ports": [
                {"port": null, "protocol": ["8200"]}
            ],
            "config_files": [
                {
                    "name": "telegraf.conf",
                    "content": "# Telegraf configuration\n[agent]\n  interval = \"10s\"",
                    "variables": {}
                },
                {
                    "name": "compose",
                    "content": "services:\n  telegraf:\n    image: telegraf:latest\n    container_name: telegraf",
                    "variables": {}
                }
            ]
        }
    })
}

#[test]
fn platform_managed_app_code_normalizes_common_variants() {
    assert!(is_platform_managed_app_code("nginx_proxy_manager"));
    assert!(is_platform_managed_app_code("nginx-proxy-manager"));
    assert!(is_platform_managed_app_code("/statuspanel"));
    assert!(!is_platform_managed_app_code("coolify"));
}

#[test]
fn platform_managed_app_identity_matches_name_or_image() {
    assert!(is_platform_managed_app_identity(
        "nginx_proxy_manager",
        None
    ));
    assert!(is_platform_managed_app_identity(
        "proxy",
        Some("jc21/nginx-proxy-manager:latest")
    ));
    assert!(is_nginx_proxy_manager_identity(
        "proxy",
        Some("jc21/nginx-proxy-manager:latest")
    ));
    assert!(is_nginx_proxy_manager_identity("npm", None));
    assert!(!is_platform_managed_app_identity(
        "postgres",
        Some("postgres:16-alpine")
    ));
}

#[test]
fn test_project_app_post_args_from_params() {
    let payload = example_deploy_app_payload();
    let params = payload.get("parameters").unwrap();

    let args = ProjectAppPostArgs::from(params);

    // Check environment is extracted
    assert!(args.environment.is_some());
    let env = args.environment.as_ref().unwrap();
    assert_eq!(
        env.get("telegraf_role").and_then(|v| v.as_str()),
        Some("server")
    );
    assert_eq!(
        env.get("telegraf_interval").and_then(|v| v.as_str()),
        Some("10s")
    );

    // Check ports are extracted
    assert!(args.ports.is_some());
    let ports = args.ports.as_ref().unwrap().as_array().unwrap();
    assert_eq!(ports.len(), 1);

    // Check compose_content is extracted from config_files
    assert!(args.compose_content.is_some());
    let compose = args.compose_content.as_ref().unwrap();
    assert!(compose.contains("telegraf:latest"));

    // Check non-compose config files are preserved
    assert!(args.config_files.is_some());
    let config_files = args.config_files.as_ref().unwrap().as_array().unwrap();
    assert_eq!(config_files.len(), 1);
    assert_eq!(
        config_files[0].get("name").and_then(|v| v.as_str()),
        Some("telegraf.conf")
    );
}

#[test]
fn test_project_app_from_post_basic() {
    let payload = example_deploy_app_payload();
    let params = payload.get("parameters").unwrap();
    let app_code = "telegraf";
    let project_id = 42;

    let (app, compose_content) = project_app_from_post(app_code, project_id, params);

    // Check basic fields
    assert_eq!(app.project_id, project_id);
    assert_eq!(app.code, "telegraf");
    assert_eq!(app.name, "telegraf"); // Defaults to app_code

    // Check environment is set
    assert!(app.environment.is_some());
    let env = app.environment.as_ref().unwrap();
    assert_eq!(
        env.get("telegraf_role").and_then(|v| v.as_str()),
        Some("server")
    );

    // Check ports are set
    assert!(app.ports.is_some());

    // Check enabled defaults to true
    assert_eq!(app.enabled, Some(true));

    // Check compose_content is returned separately
    assert!(compose_content.is_some());
    assert!(compose_content
        .as_ref()
        .unwrap()
        .contains("telegraf:latest"));

    // Check config_files are stored in labels
    assert!(app.labels.is_some());
    let labels = app.labels.as_ref().unwrap();
    assert!(labels.get("config_files").is_some());
}

#[test]
fn test_project_app_from_post_with_all_fields() {
    let params = json!({
        "name": "My Telegraf App",
        "image": "telegraf:1.28",
        "env": {"KEY": "value"},
        "ports": [{"host": 8080, "container": 80}],
        "volumes": ["/data:/app/data"],
        "domain": "telegraf.example.com",
        "ssl_enabled": true,
        "resources": {"cpu_limit": "1", "memory_limit": "512m"},
        "restart_policy": "always",
        "command": "/bin/sh -c 'telegraf'",
        "entrypoint": "/entrypoint.sh",
        "networks": ["default_network"],
        "depends_on": ["influxdb"],
        "healthcheck": {"test": ["CMD", "curl", "-f", "http://localhost"]},
        "labels": {"app": "telegraf"},
        "enabled": false,
        "deploy_order": 5,
        "config_files": [
            {"name": "docker-compose.yml", "content": "version: '3'", "variables": {}}
        ]
    });

    let (app, compose_content) = project_app_from_post("telegraf", 100, &params);

    assert_eq!(app.name, "My Telegraf App");
    assert_eq!(app.image, "telegraf:1.28");
    assert_eq!(app.domain, Some("telegraf.example.com".to_string()));
    assert_eq!(app.ssl_enabled, Some(true));
    assert_eq!(app.restart_policy, Some("always".to_string()));
    assert_eq!(app.command, Some("/bin/sh -c 'telegraf'".to_string()));
    assert_eq!(app.entrypoint, Some("/entrypoint.sh".to_string()));
    assert_eq!(app.enabled, Some(false));
    assert_eq!(app.deploy_order, Some(5));

    // docker-compose.yml should be extracted as compose_content
    assert!(compose_content.is_some());
    assert_eq!(compose_content.as_ref().unwrap(), "version: '3'");
}

#[test]
fn test_compose_extraction_from_different_names() {
    // Test "compose" name
    let params1 = json!({
        "config_files": [{"name": "compose", "content": "compose-content"}]
    });
    let args1 = ProjectAppPostArgs::from(&params1);
    assert_eq!(args1.compose_content, Some("compose-content".to_string()));

    // Test "docker-compose.yml" name
    let params2 = json!({
        "config_files": [{"name": "docker-compose.yml", "content": "docker-compose-content"}]
    });
    let args2 = ProjectAppPostArgs::from(&params2);
    assert_eq!(
        args2.compose_content,
        Some("docker-compose-content".to_string())
    );

    // Test "docker-compose.yaml" name
    let params3 = json!({
        "config_files": [{"name": "docker-compose.yaml", "content": "yaml-content"}]
    });
    let args3 = ProjectAppPostArgs::from(&params3);
    assert_eq!(args3.compose_content, Some("yaml-content".to_string()));
}

#[test]
fn test_non_compose_files_preserved() {
    let params = json!({
        "config_files": [
            {"name": "telegraf.conf", "content": "telegraf config"},
            {"name": "nginx.conf", "content": "nginx config"},
            {"name": "compose", "content": "compose content"}
        ]
    });

    let args = ProjectAppPostArgs::from(&params);

    // Compose is extracted
    assert_eq!(args.compose_content, Some("compose content".to_string()));

    // Other files are preserved
    let config_files = args.config_files.unwrap();
    let files = config_files.as_array().unwrap();
    assert_eq!(files.len(), 2);

    let names: Vec<&str> = files
        .iter()
        .filter_map(|f| f.get("name").and_then(|n| n.as_str()))
        .collect();
    assert!(names.contains(&"telegraf.conf"));
    assert!(names.contains(&"nginx.conf"));
    assert!(!names.contains(&"compose"));
}

#[test]
fn test_empty_params() {
    let params = json!({});
    let (app, compose_content) = project_app_from_post("myapp", 1, &params);

    assert_eq!(app.code, "myapp");
    assert_eq!(app.name, "myapp"); // Defaults to app_code
    assert_eq!(app.image, ""); // Empty default
    assert_eq!(app.enabled, Some(true)); // Default enabled
    assert!(compose_content.is_none());
}

#[test]
fn test_into_project_app_preserves_context() {
    let args = ProjectAppPostArgs {
        name: Some("Custom Name".to_string()),
        image: Some("nginx:latest".to_string()),
        environment: Some(json!({"FOO": "bar"})),
        ..Default::default()
    };

    let ctx = ProjectAppContext {
        app_code: "nginx",
        project_id: 999,
    };

    let app = args.into_project_app(ctx);

    assert_eq!(app.project_id, 999);
    assert_eq!(app.code, "nginx");
    assert_eq!(app.name, "Custom Name");
    assert_eq!(app.image, "nginx:latest");
}

#[test]
fn test_extract_compose_from_config_files_for_vault() {
    // This tests the extraction logic used in store_configs_to_vault_from_params

    // Helper to extract compose the same way as store_configs_to_vault_from_params
    fn extract_compose(params: &serde_json::Value) -> Option<String> {
        params
            .get("config_files")
            .and_then(|v| v.as_array())
            .and_then(|files| {
                files.iter().find_map(|file| {
                    let file_name = file.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    if super::is_compose_filename(file_name) {
                        file.get("content")
                            .and_then(|c| c.as_str())
                            .map(|s| s.to_string())
                    } else {
                        None
                    }
                })
            })
    }

    // Test with "compose" name
    let params1 = json!({
        "app_code": "telegraf",
        "config_files": [
            {"name": "telegraf.conf", "content": "config content"},
            {"name": "compose", "content": "services:\n  telegraf:\n    image: telegraf:latest"}
        ]
    });
    let compose1 = extract_compose(&params1);
    assert!(compose1.is_some());
    assert!(compose1.unwrap().contains("telegraf:latest"));

    // Test with "docker-compose.yml" name
    let params2 = json!({
        "app_code": "nginx",
        "config_files": [
            {"name": "docker-compose.yml", "content": "version: '3'\nservices:\n  nginx:\n    image: nginx:alpine"}
        ]
    });
    let compose2 = extract_compose(&params2);
    assert!(compose2.is_some());
    assert!(compose2.unwrap().contains("nginx:alpine"));

    // Test with no compose file
    let params3 = json!({
        "app_code": "myapp",
        "config_files": [
            {"name": "app.conf", "content": "some config"}
        ]
    });
    let compose3 = extract_compose(&params3);
    assert!(compose3.is_none());

    // Test with empty config_files
    let params4 = json!({
        "app_code": "myapp",
        "config_files": []
    });
    let compose4 = extract_compose(&params4);
    assert!(compose4.is_none());

    // Test with no config_files key
    let params5 = json!({
        "app_code": "myapp"
    });
    let compose5 = extract_compose(&params5);
    assert!(compose5.is_none());
}

#[test]
fn test_generate_single_app_compose() {
    // Test with full parameters
    let params = json!({
        "image": "nginx:latest",
        "restart_policy": "always",
        "env": {
            "ENV_VAR1": "value1",
            "ENV_VAR2": "value2"
        },
        "ports": [
            {"host": 80, "container": 80},
            {"host": 443, "container": 443}
        ],
        "volumes": [
            {"source": "/data/nginx", "target": "/usr/share/nginx/html"}
        ],
        "networks": ["my_network"],
        "depends_on": ["postgres"],
        "labels": {
            "traefik.enable": "true"
        }
    });

    let compose = generate_single_app_compose("nginx", &params);
    assert!(compose.is_ok());
    let content = compose.unwrap();

    // Verify key elements (using docker_compose_types serialization format)
    assert!(content.contains("image: nginx:latest"));
    assert!(content.contains("restart: always"));
    assert!(content.contains("ENV_VAR1"));
    assert!(content.contains("value1"));
    assert!(content.contains("80:80"));
    assert!(content.contains("443:443"));
    assert!(content.contains("/data/nginx:/usr/share/nginx/html"));
    assert!(content.contains("my_network"));
    assert!(content.contains("postgres"));
    assert!(content.contains("traefik.enable"));

    // Test with minimal parameters (just image)
    let minimal_params = json!({
        "image": "redis:alpine"
    });
    let minimal_compose = generate_single_app_compose("redis", &minimal_params);
    assert!(minimal_compose.is_ok());
    let minimal_content = minimal_compose.unwrap();
    assert!(minimal_content.contains("image: redis:alpine"));
    assert!(minimal_content.contains("restart: unless-stopped")); // default
    assert!(minimal_content.contains("trydirect_network")); // default network

    // Test with no image - should return Err
    let no_image_params = json!({
        "env": {"KEY": "value"}
    });
    let no_image_compose = generate_single_app_compose("app", &no_image_params);
    assert!(no_image_compose.is_err());

    // Test with string-style ports
    let string_ports_params = json!({
        "image": "app:latest",
        "ports": ["8080:80", "9000:9000"]
    });
    let string_ports_compose = generate_single_app_compose("app", &string_ports_params);
    assert!(string_ports_compose.is_ok());
    let string_ports_content = string_ports_compose.unwrap();
    assert!(string_ports_content.contains("8080:80"));
    assert!(string_ports_content.contains("9000:9000"));

    // Test with array-style environment variables
    let array_env_params = json!({
        "image": "app:latest",
        "env": ["KEY1=val1", "KEY2=val2"]
    });
    let array_env_compose = generate_single_app_compose("app", &array_env_params);
    assert!(array_env_compose.is_ok());
    let array_env_content = array_env_compose.unwrap();
    assert!(array_env_content.contains("KEY1"));
    assert!(array_env_content.contains("val1"));
    assert!(array_env_content.contains("KEY2"));
    assert!(array_env_content.contains("val2"));

    // Test with string-style volumes
    let string_vol_params = json!({
        "image": "app:latest",
        "volumes": ["/host/path:/container/path", "named_vol:/data"]
    });
    let string_vol_compose = generate_single_app_compose("app", &string_vol_params);
    assert!(string_vol_compose.is_ok());
    let string_vol_content = string_vol_compose.unwrap();
    assert!(string_vol_content.contains("/host/path:/container/path"));
    assert!(string_vol_content.contains("named_vol:/data"));
}

// =========================================================================
// Config File Storage and Enrichment Tests
// =========================================================================

#[test]
fn test_config_files_extraction_for_bundling() {
    // Simulates the logic in store_configs_to_vault_from_params that extracts
    // non-compose config files for bundling
    fn extract_config_files(params: &serde_json::Value) -> Vec<(String, String)> {
        let mut configs = Vec::new();

        if let Some(files) = params.get("config_files").and_then(|v| v.as_array()) {
            for file in files {
                let file_name = file.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let content = file.get("content").and_then(|c| c.as_str()).unwrap_or("");

                // Skip compose files
                if super::is_compose_filename(file_name) {
                    continue;
                }

                if !content.is_empty() {
                    configs.push((file_name.to_string(), content.to_string()));
                }
            }
        }

        configs
    }

    let params = json!({
        "app_code": "komodo",
        "config_files": [
            {"name": "komodo.env", "content": "ADMIN_EMAIL=test@example.com"},
            {"name": ".env", "content": "SECRET_KEY=abc123"},
            {"name": "docker-compose.yml", "content": "services:\n  komodo:"},
            {"name": "config.toml", "content": "[server]\nport = 8080"}
        ]
    });

    let configs = extract_config_files(&params);

    // Should have 3 non-compose configs
    assert_eq!(configs.len(), 3);

    let names: Vec<&str> = configs.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"komodo.env"));
    assert!(names.contains(&".env"));
    assert!(names.contains(&"config.toml"));
    assert!(!names.contains(&"docker-compose.yml"));
}

#[test]
fn test_config_bundle_json_creation() {
    // Test that config files can be bundled into a JSON array format
    // similar to what store_configs_to_vault_from_params does
    let app_configs: Vec<(&str, &str, &str)> = vec![
        (
            "telegraf.conf",
            "[agent]\n  interval = \"10s\"",
            "/home/trydirect/hash123/config/telegraf.conf",
        ),
        (
            "nginx.conf",
            "server { listen 80; }",
            "/home/trydirect/hash123/config/nginx.conf",
        ),
    ];

    let configs_json: Vec<serde_json::Value> = app_configs
        .iter()
        .map(|(name, content, dest)| {
            json!({
                "name": name,
                "content": content,
                "content_type": "text/plain",
                "destination_path": dest,
                "file_mode": "0644",
                "owner": null,
                "group": null,
            })
        })
        .collect();

    let bundle_json = serde_json::to_string(&configs_json).unwrap();

    // Verify structure
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&bundle_json).unwrap();
    assert_eq!(parsed.len(), 2);

    // Verify all fields present
    for config in &parsed {
        assert!(config.get("name").is_some());
        assert!(config.get("content").is_some());
        assert!(config.get("destination_path").is_some());
        assert!(config.get("file_mode").is_some());
    }
}

#[test]
fn test_config_files_merge_with_existing() {
    // Test that existing config_files are preserved when merging with Vault configs
    fn merge_config_files(
        existing: Option<&Vec<serde_json::Value>>,
        vault_configs: Vec<serde_json::Value>,
    ) -> Vec<serde_json::Value> {
        let mut config_files: Vec<serde_json::Value> = Vec::new();

        if let Some(existing_configs) = existing {
            config_files.extend(existing_configs.iter().cloned());
        }

        config_files.extend(vault_configs);
        config_files
    }

    let existing = vec![json!({"name": "custom.conf", "content": "custom config"})];

    let vault_configs = vec![
        json!({"name": "telegraf.env", "content": "INFLUX_TOKEN=xxx"}),
        json!({"name": "app.conf", "content": "config from vault"}),
    ];

    let merged = merge_config_files(Some(&existing), vault_configs);

    assert_eq!(merged.len(), 3);

    let names: Vec<&str> = merged
        .iter()
        .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
        .collect();
    assert!(names.contains(&"custom.conf"));
    assert!(names.contains(&"telegraf.env"));
    assert!(names.contains(&"app.conf"));
}

#[test]
fn test_env_file_destination_path_format() {
    // Verify .env files have correct destination paths
    let deployment_hash = "abc123xyz";
    let app_code = "komodo";

    // Expected format from config_renderer.rs
    let env_dest_path = format!("/home/trydirect/{}/{}.env", deployment_hash, app_code);

    assert_eq!(env_dest_path, "/home/trydirect/abc123xyz/komodo.env");

    // Alternative format for deployment-level .env
    let global_env_path = format!("/home/trydirect/{}/.env", deployment_hash);
    assert_eq!(global_env_path, "/home/trydirect/abc123xyz/.env");
}

#[test]
fn test_vault_key_generation() {
    // Test that correct Vault keys are generated for different config types
    let app_code = "komodo";

    // Compose key
    let compose_key = app_code.to_string();
    assert_eq!(compose_key, "komodo");

    // Env key
    let env_key = format!("{}_env", app_code);
    assert_eq!(env_key, "komodo_env");

    // Configs bundle key
    let configs_key = format!("{}_configs", app_code);
    assert_eq!(configs_key, "komodo_configs");

    // Legacy single config key
    let config_key = format!("{}_config", app_code);
    assert_eq!(config_key, "komodo_config");
}

#[test]
fn test_config_content_types() {
    use super::vault::detect_content_type;

    assert_eq!(detect_content_type("config.json"), "application/json");
    assert_eq!(detect_content_type("docker-compose.yml"), "text/yaml");
    assert_eq!(detect_content_type("config.yaml"), "text/yaml");
    assert_eq!(detect_content_type("config.toml"), "text/toml");
    assert_eq!(detect_content_type("nginx.conf"), "text/plain");
    assert_eq!(detect_content_type("app.env"), "text/plain");
    assert_eq!(detect_content_type(".env"), "text/plain");
    assert_eq!(detect_content_type("unknown"), "text/plain");
}

#[test]
fn test_multiple_env_files_in_bundle() {
    // Test handling of multiple .env-like files (app.env, .env.j2, etc.)
    let config_files = vec![
        json!({
            "name": "komodo.env",
            "content": "ADMIN_EMAIL=admin@test.com\nSECRET_KEY=abc",
            "destination_path": "/home/trydirect/hash123/komodo.env"
        }),
        json!({
            "name": ".env",
            "content": "DATABASE_URL=postgres://...",
            "destination_path": "/home/trydirect/hash123/.env"
        }),
        json!({
            "name": "custom.env.j2",
            "content": "{{ variable }}",
            "destination_path": "/home/trydirect/hash123/custom.env"
        }),
    ];

    // All should be valid config files
    assert_eq!(config_files.len(), 3);

    // Each should have required fields
    for config in &config_files {
        assert!(config.get("name").is_some());
        assert!(config.get("content").is_some());
        assert!(config.get("destination_path").is_some());
    }
}

#[test]
fn test_env_generation_from_params_env() {
    // Test that .env content can be generated from params.env object
    // This mimics the logic in store_configs_to_vault_from_params
    fn generate_env_from_params(params: &serde_json::Value) -> Option<String> {
        params
            .get("env")
            .and_then(|v| v.as_object())
            .and_then(|env_obj| {
                if env_obj.is_empty() {
                    return None;
                }
                let env_lines: Vec<String> = env_obj
                    .iter()
                    .map(|(k, v)| {
                        let val = match v {
                            serde_json::Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        format!("{}={}", k, val)
                    })
                    .collect();
                Some(env_lines.join("\n"))
            })
    }

    // Test with string values
    let params1 = json!({
        "app_code": "komodo",
        "env": {
            "DATABASE_URL": "postgres://localhost:5432/db",
            "SECRET_KEY": "abc123",
            "DEBUG": "false"
        }
    });
    let env1 = generate_env_from_params(&params1);
    assert!(env1.is_some());
    let content1 = env1.unwrap();
    assert!(content1.contains("DATABASE_URL=postgres://localhost:5432/db"));
    assert!(content1.contains("SECRET_KEY=abc123"));
    assert!(content1.contains("DEBUG=false"));

    // Test with non-string values (numbers, bools)
    let params2 = json!({
        "app_code": "app",
        "env": {
            "PORT": 8080,
            "DEBUG": true
        }
    });
    let env2 = generate_env_from_params(&params2);
    assert!(env2.is_some());
    let content2 = env2.unwrap();
    assert!(content2.contains("PORT=8080"));
    assert!(content2.contains("DEBUG=true"));

    // Test with empty env
    let params3 = json!({
        "app_code": "app",
        "env": {}
    });
    let env3 = generate_env_from_params(&params3);
    assert!(env3.is_none());

    // Test with missing env
    let params4 = json!({
        "app_code": "app"
    });
    let env4 = generate_env_from_params(&params4);
    assert!(env4.is_none());
}

#[test]
fn test_env_file_extraction_from_config_files() {
    // Test that .env files are properly extracted from config_files
    // This mimics the logic in store_configs_to_vault_from_params
    fn extract_env_from_config_files(params: &serde_json::Value) -> Option<String> {
        params
            .get("config_files")
            .and_then(|v| v.as_array())
            .and_then(|files| {
                files.iter().find_map(|file| {
                    let file_name = file.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    if file_name == ".env" || file_name == "env" {
                        file.get("content")
                            .and_then(|c| c.as_str())
                            .map(|s| s.to_string())
                    } else {
                        None
                    }
                })
            })
    }

    // Test with .env file in config_files
    let params1 = json!({
        "app_code": "komodo",
        "config_files": [
            {"name": ".env", "content": "SECRET=xyz\nDEBUG=true"},
            {"name": "compose", "content": "services: ..."}
        ]
    });
    let env1 = extract_env_from_config_files(&params1);
    assert!(env1.is_some());
    assert!(env1.unwrap().contains("SECRET=xyz"));

    // Test with "env" name variant
    let params2 = json!({
        "app_code": "app",
        "config_files": [
            {"name": "env", "content": "VAR=value"}
        ]
    });
    let env2 = extract_env_from_config_files(&params2);
    assert!(env2.is_some());

    // Test without .env file
    let params3 = json!({
        "app_code": "app",
        "config_files": [
            {"name": "config.toml", "content": "[server]"}
        ]
    });
    let env3 = extract_env_from_config_files(&params3);
    assert!(env3.is_none());
}
/// Test: .env config file content is parsed into project_app.environment
/// This is the CRITICAL fix for the bug where user-edited .env files were not saved
#[test]
fn test_env_config_file_parsed_into_environment() {
    // User data from the bug report - env is empty but .env config file has content
    let params = json!({
        "env": {},  // Empty - user didn't use the form fields
        "config_files": [
            {
                "name": ".env",
                "content": "# Core config\nKOMODO_FIRST_SERVER: http://periphery:8120\nKOMODO_DATABASE_ADDRESS: ferretdb\nKOMODO_ENABLE_NEW_USERS: true\nKOMODO_LOCAL_AUTH: true\nKOMODO_JWT_SECRET: a_random_secret",
                "variables": {}
            },
            {
                "name": "compose",
                "content": "services:\n  core:\n    image: trydirect/komodo-core:unstable",
                "variables": {}
            }
        ]
    });

    let (app, compose_content) = project_app_from_post("komodo", 1, &params);

    // Environment should be populated from .env config file
    assert!(
        app.environment.is_some(),
        "environment should be parsed from .env file"
    );
    let env = app.environment.as_ref().unwrap();

    // Check individual vars were parsed (YAML-like KEY: value format)
    assert_eq!(
        env.get("KOMODO_FIRST_SERVER").and_then(|v| v.as_str()),
        Some("http://periphery:8120"),
        "KOMODO_FIRST_SERVER should be parsed"
    );
    assert_eq!(
        env.get("KOMODO_DATABASE_ADDRESS").and_then(|v| v.as_str()),
        Some("ferretdb"),
        "KOMODO_DATABASE_ADDRESS should be parsed"
    );
    assert_eq!(
        env.get("KOMODO_JWT_SECRET").and_then(|v| v.as_str()),
        Some("a_random_secret"),
        "KOMODO_JWT_SECRET should be parsed"
    );

    // Compose content should also be extracted
    assert!(compose_content.is_some());
    assert!(compose_content.as_ref().unwrap().contains("komodo-core"));
}

/// Test: Standard KEY=value .env format
#[test]
fn test_env_config_file_standard_format() {
    let params = json!({
        "env": {},
        "config_files": [
            {
                "name": ".env",
                "content": "# Database\nDB_HOST=localhost\nDB_PORT=5432\nDB_PASSWORD=secret123\nDEBUG=true",
                "variables": {}
            }
        ]
    });

    let (app, _) = project_app_from_post("myapp", 1, &params);

    assert!(app.environment.is_some());
    let env = app.environment.as_ref().unwrap();

    assert_eq!(
        env.get("DB_HOST").and_then(|v| v.as_str()),
        Some("localhost")
    );
    assert_eq!(env.get("DB_PORT").and_then(|v| v.as_str()), Some("5432"));
    assert_eq!(
        env.get("DB_PASSWORD").and_then(|v| v.as_str()),
        Some("secret123")
    );
    assert_eq!(env.get("DEBUG").and_then(|v| v.as_str()), Some("true"));
}

/// Test: params.env takes precedence over .env config file
#[test]
fn test_params_env_takes_precedence() {
    let params = json!({
        "env": {
            "MY_VAR": "from_form"
        },
        "config_files": [
            {
                "name": ".env",
                "content": "MY_VAR=from_file\nOTHER_VAR=value",
                "variables": {}
            }
        ]
    });

    let (app, _) = project_app_from_post("myapp", 1, &params);

    assert!(app.environment.is_some());
    let env = app.environment.as_ref().unwrap();

    // Form values take precedence
    assert_eq!(
        env.get("MY_VAR").and_then(|v| v.as_str()),
        Some("from_form")
    );
    // Other vars from file should NOT be included (form env is used entirely)
    assert!(env.get("OTHER_VAR").is_none());
}

/// Test: Empty .env file doesn't set environment
#[test]
fn test_empty_env_file_ignored() {
    let params = json!({
        "env": {},
        "config_files": [
            {
                "name": ".env",
                "content": "# Just comments\n\n",
                "variables": {}
            }
        ]
    });

    let (app, _) = project_app_from_post("myapp", 1, &params);

    // No environment should be set since .env file only has comments
    assert!(
        app.environment.is_none()
            || app
                .environment
                .as_ref()
                .map(|e| e.as_object().map(|o| o.is_empty()).unwrap_or(true))
                .unwrap_or(true),
        "empty .env file should not set environment"
    );
}

/// Test: Custom config files (telegraf.conf, etc.) are preserved in project_app.labels
#[test]
fn test_custom_config_files_saved_to_labels() {
    let params = json!({
        "env": {},
        "config_files": [
            {
                "name": "telegraf.conf",
                "content": "[agent]\n  interval = \"10s\"\n  flush_interval = \"10s\"",
                "variables": {},
                "destination_path": "/etc/telegraf/telegraf.conf"
            },
            {
                "name": "nginx.conf",
                "content": "server {\n  listen 80;\n  server_name example.com;\n}",
                "variables": {}
            },
            {
                "name": ".env",
                "content": "DB_HOST=localhost\nDB_PORT=5432",
                "variables": {}
            },
            {
                "name": "compose",
                "content": "services:\n  app:\n    image: myapp:latest",
                "variables": {}
            }
        ]
    });

    let (app, compose_content) = project_app_from_post("myapp", 1, &params);

    // Compose should be extracted
    assert!(compose_content.is_some());
    assert!(compose_content.as_ref().unwrap().contains("myapp:latest"));

    // Environment should be parsed from .env
    assert!(app.environment.is_some());
    let env = app.environment.as_ref().unwrap();
    assert_eq!(
        env.get("DB_HOST").and_then(|v| v.as_str()),
        Some("localhost")
    );

    // Config files should be stored in labels (excluding compose, including .env and others)
    assert!(app.labels.is_some(), "labels should be set");
    let labels = app.labels.as_ref().unwrap();
    let config_files = labels
        .get("config_files")
        .expect("config_files should be in labels");
    let files = config_files
        .as_array()
        .expect("config_files should be an array");

    // Should have 3 files: telegraf.conf, nginx.conf, .env (compose is extracted separately)
    assert_eq!(files.len(), 3, "should have 3 config files in labels");

    let file_names: Vec<&str> = files
        .iter()
        .filter_map(|f| f.get("name").and_then(|n| n.as_str()))
        .collect();

    assert!(
        file_names.contains(&"telegraf.conf"),
        "telegraf.conf should be preserved"
    );
    assert!(
        file_names.contains(&"nginx.conf"),
        "nginx.conf should be preserved"
    );
    assert!(file_names.contains(&".env"), ".env should be preserved");
    assert!(
        !file_names.contains(&"compose"),
        "compose should NOT be in config_files"
    );

    // Verify content is preserved
    let telegraf_file = files
        .iter()
        .find(|f| f.get("name").and_then(|n| n.as_str()) == Some("telegraf.conf"))
        .unwrap();
    let telegraf_content = telegraf_file
        .get("content")
        .and_then(|c| c.as_str())
        .unwrap();
    assert!(
        telegraf_content.contains("interval = \"10s\""),
        "telegraf.conf content should be preserved"
    );
}
