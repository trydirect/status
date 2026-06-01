use std::collections::HashMap;

pub const PROJECT_ID: &str = "my.stacker.project_id";
pub const TARGET: &str = "my.stacker.target";
pub const SCOPE: &str = "my.stacker.scope";
pub const SERVICE: &str = "my.stacker.service";
pub const DNS: &str = "my.stacker.dns";

pub const SCOPE_PROJECT: &str = "project";
pub const SCOPE_PLATFORM: &str = "platform";

pub fn insert_runtime_labels(
    labels: &mut HashMap<String, String>,
    project_id: Option<impl ToString>,
    target: Option<&str>,
    scope: &str,
    service: &str,
    dns: &str,
) {
    if let Some(project_id) = project_id {
        labels.insert(PROJECT_ID.to_string(), project_id.to_string());
    }
    if let Some(target) = target.filter(|value| !value.trim().is_empty()) {
        labels.insert(TARGET.to_string(), target.to_string());
    }
    labels.insert(SCOPE.to_string(), scope.to_string());
    labels.insert(SERVICE.to_string(), service.to_string());
    labels.insert(DNS.to_string(), dns.to_string());
}
