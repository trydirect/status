use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Environment {
    #[serde(default, deserialize_with = "deserialize_environment")]
    pub(crate) environment: Option<Vec<EnvVar>>,
}

/// Custom deserializer that accepts either:
/// - An array of {key, value} objects: [{"key": "FOO", "value": "bar"}]
/// - An object/map: {"FOO": "bar"} or {}
fn deserialize_environment<'de, D>(deserializer: D) -> Result<Option<Vec<EnvVar>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum EnvFormat {
        Array(Vec<EnvVar>),
        Map(HashMap<String, serde_json::Value>),
    }

    match Option::<EnvFormat>::deserialize(deserializer)? {
        None => Ok(None),
        Some(EnvFormat::Array(arr)) => Ok(Some(arr)),
        Some(EnvFormat::Map(map)) => {
            if map.is_empty() {
                Ok(Some(vec![]))
            } else {
                let vars: Vec<EnvVar> = map
                    .into_iter()
                    .map(|(key, value)| EnvVar {
                        key,
                        value: match value {
                            serde_json::Value::String(s) => s,
                            other => other.to_string(),
                        },
                    })
                    .collect();
                Ok(Some(vars))
            }
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvVar {
    pub(crate) key: String,
    pub(crate) value: String,
}
