use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Var {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::Var;
    use serde_json::json;

    #[test]
    fn preserves_key_value_entries() {
        let parsed: Var = serde_json::from_value(json!({
            "key": "status_panel_only",
            "value": "true"
        }))
        .expect("var should deserialize");

        assert_eq!(parsed.key.as_deref(), Some("status_panel_only"));
        assert_eq!(parsed.value, Some(json!("true")));

        let serialized = serde_json::to_value(parsed).expect("var should serialize");
        assert_eq!(serialized["key"], json!("status_panel_only"));
        assert_eq!(serialized["value"], json!("true"));
    }
}
