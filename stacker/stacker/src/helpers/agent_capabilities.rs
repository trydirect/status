use serde_json::Value;

pub const NPM_CREDENTIAL_SOURCE_KEY: &str = "npm_credential_source";
pub const NPM_CREDENTIAL_SOURCE_VAULT: &str = "npm_credential_source=vault";

pub fn extract_capabilities(value: Option<Value>) -> Vec<String> {
    value
        .and_then(|val| serde_json::from_value::<Vec<String>>(val).ok())
        .unwrap_or_default()
}

pub fn has_capability(capabilities: &[String], required: &str) -> bool {
    capabilities.iter().any(|capability| capability == required)
}

pub fn capability_value<'a>(capabilities: &'a [String], key: &str) -> Option<&'a str> {
    capabilities.iter().find_map(|capability| {
        capability
            .split_once('=')
            .or_else(|| capability.split_once(':'))
            .and_then(|(candidate_key, candidate_value)| {
                (candidate_key == key).then_some(candidate_value)
            })
    })
}

pub fn has_capability_value(capabilities: &[String], key: &str, expected: &str) -> bool {
    capability_value(capabilities, key) == Some(expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_capabilities_from_json_array() {
        let capabilities = extract_capabilities(Some(serde_json::json!(["docker", "logs"])));
        assert_eq!(capabilities, vec!["docker".to_string(), "logs".to_string()]);
    }

    #[test]
    fn returns_empty_when_capabilities_missing() {
        assert!(extract_capabilities(None).is_empty());
    }

    #[test]
    fn finds_key_value_capabilities_with_equals_or_colon() {
        let capabilities = vec![
            "docker".to_string(),
            "npm_credential_source=vault".to_string(),
            "proxy_owner:true".to_string(),
        ];

        assert_eq!(
            capability_value(&capabilities, NPM_CREDENTIAL_SOURCE_KEY),
            Some("vault")
        );
        assert_eq!(capability_value(&capabilities, "proxy_owner"), Some("true"));
        assert!(has_capability_value(
            &capabilities,
            NPM_CREDENTIAL_SOURCE_KEY,
            "vault"
        ));
    }
}
