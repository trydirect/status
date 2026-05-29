pub(crate) mod hydration;
pub(crate) mod mapping;
pub(crate) mod sync;
pub(crate) mod upsert;
pub(crate) mod vault;

pub(crate) use mapping::{merge_project_app, project_app_from_post};
pub(crate) use sync::sync_project_level_apps_from_form;
pub(crate) use upsert::upsert_app_config_for_deploy;
pub(crate) use vault::{
    parse_registry_auth_config, store_configs_to_vault_from_params,
    store_registry_auth_command_to_vault, store_registry_auth_to_vault, REGISTRY_AUTH_VAULT_KEY,
};

const PLATFORM_MANAGED_APP_CODES: &[&str] = &["nginx_proxy_manager", "statuspanel"];

pub(crate) fn is_platform_managed_app_code(value: &str) -> bool {
    let normalized = normalize_app_code(value);
    PLATFORM_MANAGED_APP_CODES.contains(&normalized.as_str())
}

pub(crate) fn is_platform_managed_app_identity(service_name: &str, image: Option<&str>) -> bool {
    app_identity_candidates(service_name, image)
        .iter()
        .any(|candidate| is_platform_managed_app_code(candidate))
}

pub(crate) fn is_nginx_proxy_manager_identity(service_name: &str, image: Option<&str>) -> bool {
    app_identity_candidates(service_name, image)
        .iter()
        .any(|candidate| candidate == "nginx_proxy_manager")
}

pub(crate) fn normalize_app_code(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('/')
        .to_lowercase()
        .split(['-', '_'])
        .filter(|part| !part.is_empty())
        .collect::<Vec<&str>>()
        .join("_")
}

fn app_identity_candidates(service_name: &str, image: Option<&str>) -> Vec<String> {
    let normalized_service_name = normalize_app_code(service_name);
    let mut candidates = vec![normalized_service_name.clone()];
    if normalized_service_name == "npm" {
        candidates.push("nginx_proxy_manager".to_string());
    }

    if let Some(image) = image {
        if let Some(image_name) = image.split('/').last() {
            if let Some(name_without_tag) = image_name.split(':').next() {
                let normalized_image_name = normalize_app_code(name_without_tag);
                if normalized_image_name == "npm" {
                    candidates.push("nginx_proxy_manager".to_string());
                }
                candidates.push(normalized_image_name);
            }
        }
    }

    candidates
}

pub(crate) fn is_compose_filename(file_name: &str) -> bool {
    matches!(
        file_name,
        "compose"
            | "compose.yml"
            | "compose.yaml"
            | "docker-compose"
            | "docker-compose.yml"
            | "docker-compose.yaml"
    )
}

#[cfg(test)]
mod tests;
