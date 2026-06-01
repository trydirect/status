use crate::db;
use crate::forms::project::{replace_id_with_name, App as ProjectFormApp, ProjectForm};
use crate::models;
use docker_compose_types as dctypes;
use indexmap::IndexMap;
use serde_json::{json, Map, Value};
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};

use super::is_platform_managed_app_code;

fn non_empty_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn app_environment_json(app: &ProjectFormApp) -> Option<Value> {
    let mut environment = Map::new();

    for env_var in app
        .environment
        .environment
        .as_ref()
        .into_iter()
        .flatten()
        .filter(|env_var| !env_var.key.trim().is_empty())
    {
        environment.insert(env_var.key.clone(), Value::String(env_var.value.clone()));
    }

    if environment.is_empty() {
        None
    } else {
        Some(Value::Object(environment))
    }
}

fn app_networks_json(
    app: &ProjectFormApp,
    all_networks: &Vec<crate::forms::project::Network>,
) -> Option<Value> {
    let networks = dctypes::Networks::try_from(&app.network).unwrap_or_default();
    let network_names = replace_id_with_name(networks, all_networks)
        .into_iter()
        .filter(|name| !name.trim().is_empty())
        .collect::<Vec<_>>();

    if network_names.is_empty() {
        None
    } else {
        Some(json!(network_names))
    }
}

fn build_project_app(
    project_id: i32,
    deploy_order: i32,
    app: &ProjectFormApp,
    all_networks: &Vec<crate::forms::project::Network>,
) -> models::ProjectApp {
    let mut project_app = models::ProjectApp::new(
        project_id,
        app.code.clone(),
        app.name.clone(),
        app.docker_image.to_string(),
    );

    project_app.environment = app_environment_json(app);
    project_app.ports = app
        .shared_ports
        .as_ref()
        .filter(|ports| !ports.is_empty())
        .map(|ports| json!(ports));
    project_app.volumes = app
        .volumes
        .as_ref()
        .filter(|volumes| !volumes.is_empty())
        .map(|volumes| json!(volumes));
    project_app.domain = non_empty_string(app.domain.as_deref());
    project_app.ssl_enabled = Some(false);
    project_app.restart_policy = non_empty_string(Some(&app.restart));
    project_app.command = non_empty_string(app.command.as_deref());
    project_app.entrypoint = non_empty_string(app.entrypoint.as_deref());
    project_app.networks = app_networks_json(app, all_networks);
    project_app.enabled = Some(true);
    project_app.deploy_order = Some(deploy_order);

    project_app
}

pub(crate) fn project_level_apps_from_form(
    project_id: i32,
    form: &ProjectForm,
) -> Vec<models::ProjectApp> {
    let all_networks = form.custom.networks.networks.clone().unwrap_or_default();
    let mut desired_apps: IndexMap<String, models::ProjectApp> = IndexMap::new();
    let mut deploy_order = 0;

    for web in &form.custom.web {
        if is_platform_managed_app_code(&web.app.code) {
            continue;
        }
        deploy_order += 1;
        desired_apps.insert(
            web.app.code.clone(),
            build_project_app(project_id, deploy_order, &web.app, &all_networks),
        );
    }

    if let Some(services) = &form.custom.service {
        for service in services {
            if is_platform_managed_app_code(&service.app.code) {
                continue;
            }
            deploy_order += 1;
            desired_apps.insert(
                service.app.code.clone(),
                build_project_app(project_id, deploy_order, &service.app, &all_networks),
            );
        }
    }

    if let Some(features) = &form.custom.feature {
        for feature in features {
            if is_platform_managed_app_code(&feature.app.code) {
                continue;
            }
            deploy_order += 1;
            desired_apps.insert(
                feature.app.code.clone(),
                build_project_app(project_id, deploy_order, &feature.app, &all_networks),
            );
        }
    }

    desired_apps.into_values().collect()
}

pub(crate) async fn sync_project_level_apps_from_form(
    pool: &PgPool,
    project_id: i32,
    form: &ProjectForm,
) -> Result<(), String> {
    let desired_apps = project_level_apps_from_form(project_id, form);
    let desired_codes = desired_apps
        .iter()
        .map(|app| app.code.clone())
        .collect::<HashSet<_>>();

    let existing_project_level = db::project_app::fetch_by_project(pool, project_id)
        .await?
        .into_iter()
        .filter(|app| app.deployment_id.is_none())
        .collect::<Vec<_>>();

    let mut existing_by_code = existing_project_level
        .iter()
        .map(|app| (app.code.clone(), app.id))
        .collect::<HashMap<_, _>>();

    for mut desired_app in desired_apps {
        if let Some(existing_id) = existing_by_code.remove(&desired_app.code) {
            desired_app.id = existing_id;
            desired_app.deployment_id = None;
            db::project_app::update(pool, &desired_app).await?;
        } else {
            db::project_app::insert(pool, &desired_app).await?;
        }
    }

    for stale_app in existing_project_level
        .into_iter()
        .filter(|app| !desired_codes.contains(&app.code))
    {
        db::project_app::delete(pool, stale_app.id).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::project_level_apps_from_form;
    use crate::forms::project::ProjectForm;
    use serde_json::json;

    #[test]
    fn project_level_apps_from_form_includes_all_custom_apps() {
        let form: ProjectForm = serde_json::from_value(json!({
            "custom": {
                "custom_stack_code": "sync-project",
                "project_name": "Sync project",
                "networks": [
                    {"id": "net-1", "name": "default_network"}
                ],
                "web": [{
                    "_id": "web-1",
                    "name": "Website",
                    "code": "website",
                    "type": "web",
                    "custom": true,
                    "dockerhub_image": "nginx:1.27",
                    "domain": "example.com",
                    "restart": "always",
                    "network": ["net-1"],
                    "environment": [{"key": "PUBLIC_URL", "value": "https://example.com"}],
                    "shared_ports": [{"host_port": "80", "container_port": "8080"}],
                    "volumes": []
                }],
                "service": [{
                    "_id": "svc-1",
                    "name": "Redis",
                    "code": "redis",
                    "type": "service",
                    "custom": true,
                    "dockerhub_image": "redis:7-alpine",
                    "domain": "",
                    "restart": "unless-stopped",
                    "network": ["net-1"],
                    "environment": [],
                    "shared_ports": [{"host_port": "", "container_port": "6379"}],
                    "volumes": []
                }],
                    "feature": [{
                        "_id": "feat-1",
                        "name": "Search",
                        "code": "search",
                        "type": "feature",
                        "custom": true,
                        "dockerhub_image": "getmeili/meilisearch:v1.12",
                        "domain": "",
                        "restart": "always",
                        "network": ["net-1"],
                    "environment": [],
                    "shared_ports": [],
                    "volumes": []
                }]
            }
        }))
        .expect("project form should deserialize");

        let apps = project_level_apps_from_form(42, &form);
        let codes = apps.iter().map(|app| app.code.as_str()).collect::<Vec<_>>();

        assert_eq!(codes, vec!["website", "redis", "search"]);
        assert_eq!(apps[0].image, "nginx:1.27");
        assert_eq!(apps[0].domain.as_deref(), Some("example.com"));
        assert_eq!(apps[0].networks, Some(json!(["default_network"])));
        assert_eq!(
            apps[0].environment,
            Some(json!({"PUBLIC_URL": "https://example.com"}))
        );
        assert_eq!(
            apps[1].ports,
            Some(json!([{"host_port": "", "container_port": "6379", "protocol": null}]))
        );
        assert_eq!(apps[2].restart_policy.as_deref(), Some("always"));
    }

    #[test]
    fn project_level_apps_from_form_skips_platform_managed_entries() {
        let form: ProjectForm = serde_json::from_value(json!({
            "custom": {
                "custom_stack_code": "managed-platform",
                "project_name": "Managed platform",
                "networks": [],
                "web": [],
                "service": [{
                    "_id": "svc-1",
                    "name": "Nginx Proxy Manager",
                    "code": "nginx_proxy_manager",
                    "type": "service",
                    "custom": true,
                    "dockerhub_image": "jc21/nginx-proxy-manager:latest",
                    "domain": "",
                    "restart": "unless-stopped",
                    "network": [],
                    "environment": [],
                    "shared_ports": [],
                    "volumes": []
                }],
                "feature": [{
                    "_id": "feat-1",
                    "name": "Status Panel",
                    "code": "statuspanel",
                    "type": "feature",
                    "custom": true,
                    "dockerhub_image": "trydirect/status:dev",
                    "domain": "",
                    "restart": "always",
                    "network": [],
                    "environment": [],
                    "shared_ports": [],
                    "volumes": []
                }]
            }
        }))
        .expect("project form should deserialize");

        let apps = project_level_apps_from_form(42, &form);

        assert!(apps.is_empty());
    }
}
