use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};

pub const RENDER_HEADER: &str = "# stacker-render ";

#[derive(Debug, Clone, Copy)]
pub struct EnvLayer<'a> {
    pub name: &'static str,
    pub entries: &'a HashMap<String, String>,
    pub include_in_inputs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciledEnv {
    pub entries: BTreeMap<String, String>,
    pub inputs: Vec<&'static str>,
}

pub fn reconcile_env_layers(layers: &[EnvLayer<'_>]) -> ReconciledEnv {
    let mut entries = BTreeMap::new();
    let mut inputs = Vec::new();

    for layer in layers {
        if layer.entries.is_empty() {
            continue;
        }

        if layer.include_in_inputs {
            inputs.push(layer.name);
        }

        for (key, value) in layer.entries {
            entries.insert(key.clone(), value.clone());
        }
    }

    ReconciledEnv { entries, inputs }
}

pub fn reconcile_env_file_content(existing_content: &str, rendered_env_content: &str) -> String {
    let authored_content = strip_rendered_env_block(existing_content);
    let rendered_keys: HashSet<String> = parse_env_assignments(rendered_env_content)
        .into_keys()
        .collect();

    let authored_lines: Vec<&str> = authored_content
        .lines()
        .filter(|line| !should_remove_authored_line(line, &rendered_keys))
        .collect();

    let authored_content = authored_lines.join("\n");
    let authored_content = authored_content.trim_end();
    if authored_content.is_empty() {
        return rendered_env_content.to_string();
    }

    format!("{authored_content}\n\n{rendered_env_content}")
}

pub fn strip_rendered_env_block(existing_content: &str) -> &str {
    match existing_content.find(RENDER_HEADER) {
        Some(0) => "",
        Some(index) => &existing_content[..index],
        None => existing_content,
    }
}

pub fn parse_env_assignments(content: &str) -> BTreeMap<String, String> {
    content.lines().filter_map(parse_env_assignment).collect()
}

pub fn normalize_json_env(env: &Value) -> BTreeMap<String, String> {
    match env {
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| (key.clone(), stringify_json_env_value(value)))
            .collect(),
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str().and_then(parse_env_assignment))
            .collect(),
        _ => BTreeMap::new(),
    }
}

pub fn normalize_optional_json_env(env: Option<&Value>) -> BTreeMap<String, String> {
    env.map(normalize_json_env).unwrap_or_default()
}

fn should_remove_authored_line(line: &str, rendered_keys: &HashSet<String>) -> bool {
    parse_env_assignment(line)
        .map(|(key, _)| rendered_keys.contains(&key))
        .unwrap_or(false)
}

fn parse_env_assignment(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let line = line
        .strip_prefix("export ")
        .map(str::trim_start)
        .unwrap_or(line);

    if let Some((key, value)) = line.split_once('=') {
        return Some((key.trim().to_string(), value.trim().to_string()));
    }

    line.split_once(':')
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
}

fn stringify_json_env_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_json_env, normalize_optional_json_env, parse_env_assignments,
        reconcile_env_file_content, reconcile_env_layers, EnvLayer,
    };
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn reconcile_env_layers_applies_precedence_by_order() {
        let base = HashMap::from([("SHARED".to_string(), "base".to_string())]);
        let service = HashMap::from([("SHARED".to_string(), "service".to_string())]);

        let reconciled = reconcile_env_layers(&[
            EnvLayer {
                name: "base",
                entries: &base,
                include_in_inputs: true,
            },
            EnvLayer {
                name: "service",
                entries: &service,
                include_in_inputs: true,
            },
        ]);

        assert_eq!(
            reconciled.entries.get("SHARED").map(String::as_str),
            Some("service")
        );
        assert_eq!(reconciled.inputs, vec!["base", "service"]);
    }

    #[test]
    fn reconcile_env_file_content_replaces_overridden_authored_keys() {
        let existing = "RUST_LOG=debug\nS3_BUCKET=local\n# comment\n";
        let rendered =
            "# stacker-render version=2 hash=new generated_at=now inputs=service\nS3_BUCKET=remote\n";

        let merged = reconcile_env_file_content(existing, rendered);

        assert_eq!(
            merged,
            "RUST_LOG=debug\n# comment\n\n# stacker-render version=2 hash=new generated_at=now inputs=service\nS3_BUCKET=remote\n"
        );
    }

    #[test]
    fn reconcile_env_file_content_removes_previous_rendered_block() {
        let existing = "RUST_LOG=debug\n\n# stacker-render version=1 hash=old generated_at=now inputs=service\nOLD_SECRET=outdated\n";
        let rendered =
            "# stacker-render version=2 hash=new generated_at=now inputs=service\nNEW_SECRET=fresh\n";

        let merged = reconcile_env_file_content(existing, rendered);

        assert_eq!(
            merged,
            "RUST_LOG=debug\n\n# stacker-render version=2 hash=new generated_at=now inputs=service\nNEW_SECRET=fresh\n"
        );
        assert!(!merged.contains("OLD_SECRET=outdated"));
    }

    #[test]
    fn parse_env_assignments_skips_comments_and_headers() {
        let parsed = parse_env_assignments(
            "# comment\n# stacker-render version=1 hash=abc generated_at=now inputs=base\nFOO=bar\nexport BAR=baz\n",
        );

        assert_eq!(parsed.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(parsed.get("BAR").map(String::as_str), Some("baz"));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn normalize_json_env_handles_object_and_array_inputs() {
        let object = normalize_json_env(&json!({
            "DATABASE_URL": "postgres://localhost/db",
            "PORT": 8080,
            "DEBUG": true
        }));
        let array = normalize_json_env(&json!([
            "DATABASE_URL=postgres://localhost/db",
            "PORT=8080"
        ]));

        assert_eq!(
            object.get("DATABASE_URL").map(String::as_str),
            Some("postgres://localhost/db")
        );
        assert_eq!(object.get("PORT").map(String::as_str), Some("8080"));
        assert_eq!(object.get("DEBUG").map(String::as_str), Some("true"));
        assert_eq!(
            array.get("DATABASE_URL").map(String::as_str),
            Some("postgres://localhost/db")
        );
        assert_eq!(array.get("PORT").map(String::as_str), Some("8080"));
    }

    #[test]
    fn normalize_optional_json_env_defaults_to_empty_map() {
        let normalized = normalize_optional_json_env(None);
        assert!(normalized.is_empty());
    }
}
