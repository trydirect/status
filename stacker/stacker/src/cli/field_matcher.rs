use std::collections::HashMap;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// FieldMatcher trait — abstraction for pipe field matching
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Suggestion for a field transformation (beyond 1:1 mapping).
#[derive(Debug, Clone)]
pub struct TransformSuggestion {
    pub target_field: String,
    pub expression: String,
    pub description: String,
}

/// Result of field matching: the mapping, per-field confidence, and optional transformations.
#[derive(Debug, Clone)]
pub struct FieldMatchResult {
    /// The mapping from target field → JSONPath source expression.
    pub mapping: serde_json::Value,
    /// Per-field confidence scores (0.0–1.0). Deterministic matcher always returns 1.0.
    pub confidence: HashMap<String, f32>,
    /// AI-only: suggested transformations for complex mappings.
    pub suggestions: Vec<TransformSuggestion>,
    /// Which matching mode produced this result.
    pub mode: MatchingMode,
}

/// Which matching strategy was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchingMode {
    Deterministic,
    Ai,
    Ml,
}

impl std::fmt::Display for MatchingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deterministic => write!(f, "deterministic"),
            Self::Ai => write!(f, "ai"),
            Self::Ml => write!(f, "ml"),
        }
    }
}

/// Trait for field matching strategies.
pub trait FieldMatcher {
    fn match_fields(
        &self,
        src_fields: &[String],
        tgt_fields: &[String],
        source_sample: Option<&serde_json::Value>,
    ) -> FieldMatchResult;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// FIELD_ALIASES — semantic alias groups
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Common semantic aliases for field name matching.
pub const FIELD_ALIASES: &[(&[&str], &[&str])] = &[
    (
        &["email", "user_email", "mail", "email_address"],
        &["email", "user_email", "mail", "email_address"],
    ),
    (
        &["name", "display_name", "full_name", "username"],
        &["name", "display_name", "full_name", "username"],
    ),
    (
        &["first_name", "fname", "given_name"],
        &["first_name", "fname", "given_name"],
    ),
    (
        &["last_name", "lname", "family_name", "surname"],
        &["last_name", "lname", "family_name", "surname"],
    ),
    (
        &["phone", "phone_number", "tel", "telephone"],
        &["phone", "phone_number", "tel", "telephone"],
    ),
    (
        &["address", "street", "street_address"],
        &["address", "street", "street_address"],
    ),
    (&["city", "town"], &["city", "town"]),
    (&["country", "country_code"], &["country", "country_code"]),
    (
        &["title", "subject", "heading"],
        &["title", "subject", "heading"],
    ),
    (
        &["body", "content", "text", "description", "message"],
        &["body", "content", "text", "description", "message"],
    ),
    (
        &["url", "link", "href", "website"],
        &["url", "link", "href", "website"],
    ),
    (&["id", "identifier"], &["id", "identifier"]),
    (
        &["created_at", "created", "date_created"],
        &["created_at", "created", "date_created"],
    ),
    (
        &["updated_at", "updated", "date_updated", "modified"],
        &["updated_at", "updated", "date_updated", "modified"],
    ),
];

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DeterministicFieldMatcher — 4-layer matching algorithm
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Deterministic field matcher using the 4-layer algorithm:
/// 1. Exact name match
/// 2. Case-insensitive match
/// 3. Semantic alias match
/// 4. Type-aware suffix match (requires sample data)
pub struct DeterministicFieldMatcher;

impl FieldMatcher for DeterministicFieldMatcher {
    fn match_fields(
        &self,
        src_fields: &[String],
        tgt_fields: &[String],
        source_sample: Option<&serde_json::Value>,
    ) -> FieldMatchResult {
        let mapping = smart_field_match(src_fields, tgt_fields, source_sample);
        let mut confidence = HashMap::new();

        if let Some(obj) = mapping.as_object() {
            for key in obj.keys() {
                confidence.insert(key.clone(), 1.0);
            }
        }

        FieldMatchResult {
            mapping,
            confidence,
            suggestions: Vec::new(),
            mode: MatchingMode::Deterministic,
        }
    }
}

/// Smart field matching: exact name → case-insensitive → semantic aliases → type-aware.
fn smart_field_match(
    src_fields: &[String],
    tgt_fields: &[String],
    source_sample: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut mapping = serde_json::Map::new();

    for tgt_field in tgt_fields {
        // 1. Exact name match
        if src_fields.contains(tgt_field) {
            mapping.insert(
                tgt_field.clone(),
                serde_json::Value::String(format!("$.{}", tgt_field)),
            );
            continue;
        }

        // 2. Case-insensitive match
        let tgt_lower = tgt_field.to_ascii_lowercase();
        if let Some(src) = src_fields
            .iter()
            .find(|s| s.to_ascii_lowercase() == tgt_lower)
        {
            mapping.insert(
                tgt_field.clone(),
                serde_json::Value::String(format!("$.{}", src)),
            );
            continue;
        }

        // 3. Semantic alias match
        let mut found_alias = false;
        for (group_a, group_b) in FIELD_ALIASES {
            if group_a.iter().any(|a| a.eq_ignore_ascii_case(tgt_field)) {
                if let Some(src) = src_fields
                    .iter()
                    .find(|sf| group_b.iter().any(|b| b.eq_ignore_ascii_case(sf)))
                {
                    mapping.insert(
                        tgt_field.clone(),
                        serde_json::Value::String(format!("$.{}", src)),
                    );
                    found_alias = true;
                    break;
                }
            }
        }
        if found_alias {
            continue;
        }

        // 4. Type-aware match using sample data (if available)
        if let Some(sample) = source_sample {
            if let Some(obj) = sample.as_object() {
                let mapped_sources: Vec<&str> = mapping
                    .values()
                    .filter_map(|v| v.as_str())
                    .filter_map(|s| s.strip_prefix("$."))
                    .collect();

                let tgt_suffix = tgt_field.rsplit('_').next().unwrap_or(tgt_field);
                if let Some(src) = src_fields.iter().find(|sf| {
                    !mapped_sources.contains(&sf.as_str())
                        && sf.ends_with(tgt_suffix)
                        && sf.as_str() != tgt_field.as_str()
                        && obj.contains_key(sf.as_str())
                }) {
                    mapping.insert(
                        tgt_field.clone(),
                        serde_json::Value::String(format!("$.{}", src)),
                    );
                }
            }
        }
    }

    serde_json::Value::Object(mapping)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_deterministic_exact_match() {
        let matcher = DeterministicFieldMatcher;
        let src = vec!["email".to_string(), "name".to_string(), "id".to_string()];
        let tgt = vec!["email".to_string(), "name".to_string()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["email"], "$.email");
        assert_eq!(map["name"], "$.name");
        assert_eq!(result.mode, MatchingMode::Deterministic);
        assert_eq!(*result.confidence.get("email").unwrap(), 1.0);
    }

    #[test]
    fn test_deterministic_case_insensitive() {
        let matcher = DeterministicFieldMatcher;
        let src = vec!["Email".to_string(), "UserName".to_string()];
        let tgt = vec!["email".to_string(), "username".to_string()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["email"], "$.Email");
        assert_eq!(map["username"], "$.UserName");
    }

    #[test]
    fn test_deterministic_semantic_aliases() {
        let matcher = DeterministicFieldMatcher;
        let src = vec!["user_email".to_string(), "display_name".to_string()];
        let tgt = vec!["email".to_string(), "name".to_string()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["email"], "$.user_email");
        assert_eq!(map["name"], "$.display_name");
    }

    #[test]
    fn test_deterministic_type_aware_suffix() {
        let matcher = DeterministicFieldMatcher;
        let src = vec!["author_id".to_string(), "post_id".to_string()];
        let tgt = vec!["user_id".to_string()];
        let sample = json!({"author_id": 42, "post_id": 1});
        let result = matcher.match_fields(&src, &tgt, Some(&sample));
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["user_id"], "$.author_id");
    }

    #[test]
    fn test_deterministic_no_matches() {
        let matcher = DeterministicFieldMatcher;
        let src = vec!["foo".to_string()];
        let tgt = vec!["bar".to_string()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert!(map.is_empty());
        assert!(result.confidence.is_empty());
        assert!(result.suggestions.is_empty());
    }

    #[test]
    fn test_deterministic_mixed_strategies() {
        let matcher = DeterministicFieldMatcher;
        let src = vec![
            "email".to_string(),
            "display_name".to_string(),
            "Phone".to_string(),
        ];
        let tgt = vec![
            "email".to_string(),
            "name".to_string(),
            "phone".to_string(),
            "unknown".to_string(),
        ];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map["email"], "$.email");
        assert_eq!(map["name"], "$.display_name");
        assert_eq!(map["phone"], "$.Phone");
        assert!(!map.contains_key("unknown"));
        assert_eq!(result.confidence.len(), 3);
    }

    #[test]
    fn test_matching_mode_display() {
        assert_eq!(MatchingMode::Deterministic.to_string(), "deterministic");
        assert_eq!(MatchingMode::Ai.to_string(), "ai");
        assert_eq!(MatchingMode::Ml.to_string(), "ml");
    }

    #[test]
    fn test_field_match_result_default_no_suggestions() {
        let matcher = DeterministicFieldMatcher;
        let src = vec!["email".to_string()];
        let tgt = vec!["email".to_string()];
        let result = matcher.match_fields(&src, &tgt, None);
        assert!(result.suggestions.is_empty());
    }
}
