use std::collections::HashMap;

use crate::cli::ai_client::{create_provider, AiProvider};
use crate::cli::config_parser::AiConfig;
use crate::cli::error::CliError;
use crate::cli::field_matcher::{
    DeterministicFieldMatcher, FieldMatchResult, FieldMatcher, MatchingMode, TransformSuggestion,
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AiFieldMatcher — LLM-powered semantic field matching
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const FIELD_MATCH_SYSTEM_PROMPT: &str = "\
You are a data integration expert. Given source and target API field lists, \
produce a JSON field mapping. For each target field, find the best matching \
source field using semantic understanding of field names, not just string patterns.

Rules:
- Map each target field to exactly one source field (JSONPath format: $.field_name)
- Include a confidence score (0.0–1.0) for each mapping
- If no good match exists (confidence < 0.3), omit the mapping
- Suggest transformations when multiple source fields should combine (e.g., first_name + last_name → full_name)

Respond with ONLY valid JSON in this exact format:
{
  \"mappings\": {
    \"target_field\": {\"source\": \"$.source_field\", \"confidence\": 0.95}
  },
  \"transformations\": [
    {\"target\": \"full_name\", \"expression\": \"concat($.first_name, ' ', $.last_name)\", \"description\": \"Combine first and last name\"}
  ]
}";

pub struct AiFieldMatcher {
    provider: Box<dyn AiProvider>,
    model_name: String,
}

impl AiFieldMatcher {
    pub fn new(config: &AiConfig) -> Result<Self, CliError> {
        let provider = create_provider(config)?;
        let model_name = config
            .model
            .clone()
            .unwrap_or_else(|| "default".to_string());
        Ok(Self {
            provider,
            model_name,
        })
    }

    /// For testing: create from a pre-built provider.
    #[cfg(test)]
    pub fn from_provider(provider: Box<dyn AiProvider>, model_name: String) -> Self {
        Self {
            provider,
            model_name,
        }
    }

    pub fn model_name(&self) -> &str {
        &self.model_name
    }

    fn build_prompt(
        &self,
        src_fields: &[String],
        tgt_fields: &[String],
        source_sample: Option<&serde_json::Value>,
    ) -> String {
        let mut prompt = format!(
            "Source fields: [{}]\nTarget fields: [{}]",
            src_fields.join(", "),
            tgt_fields.join(", ")
        );

        if let Some(sample) = source_sample {
            if let Ok(s) = serde_json::to_string(sample) {
                // Truncate large samples
                let truncated = if s.len() > 500 { &s[..500] } else { &s };
                prompt.push_str(&format!("\n\nSample source data: {}", truncated));
            }
        }

        prompt
    }

    fn parse_response(
        &self,
        response: &str,
    ) -> Option<(HashMap<String, (String, f32)>, Vec<TransformSuggestion>)> {
        // Try to extract JSON from the response (may be wrapped in markdown code blocks)
        let json_str = extract_json_block(response);
        let parsed: serde_json::Value = serde_json::from_str(json_str).ok()?;

        let mut field_mappings = HashMap::new();
        if let Some(mappings) = parsed.get("mappings").and_then(|m| m.as_object()) {
            for (target, info) in mappings {
                let source = info.get("source").and_then(|s| s.as_str())?;
                let confidence = info
                    .get("confidence")
                    .and_then(|c| c.as_f64())
                    .unwrap_or(0.8) as f32;
                field_mappings.insert(target.clone(), (source.to_string(), confidence));
            }
        }

        let mut suggestions = Vec::new();
        if let Some(transforms) = parsed.get("transformations").and_then(|t| t.as_array()) {
            for t in transforms {
                if let (Some(target), Some(expr), Some(desc)) = (
                    t.get("target").and_then(|v| v.as_str()),
                    t.get("expression").and_then(|v| v.as_str()),
                    t.get("description").and_then(|v| v.as_str()),
                ) {
                    suggestions.push(TransformSuggestion {
                        target_field: target.to_string(),
                        expression: expr.to_string(),
                        description: desc.to_string(),
                    });
                }
            }
        }

        Some((field_mappings, suggestions))
    }
}

impl FieldMatcher for AiFieldMatcher {
    fn match_fields(
        &self,
        src_fields: &[String],
        tgt_fields: &[String],
        source_sample: Option<&serde_json::Value>,
    ) -> FieldMatchResult {
        let prompt = self.build_prompt(src_fields, tgt_fields, source_sample);

        let response = match self.provider.complete(FIELD_MATCH_SYSTEM_PROMPT, &prompt) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "  ⚠ AI field matching failed ({}), falling back to deterministic",
                    e
                );
                return DeterministicFieldMatcher.match_fields(
                    src_fields,
                    tgt_fields,
                    source_sample,
                );
            }
        };

        match self.parse_response(&response) {
            Some((field_mappings, suggestions)) => {
                let mut mapping = serde_json::Map::new();
                let mut confidence = HashMap::new();

                for (target, (source, conf)) in &field_mappings {
                    mapping.insert(target.clone(), serde_json::Value::String(source.clone()));
                    confidence.insert(target.clone(), *conf);
                }

                FieldMatchResult {
                    mapping: serde_json::Value::Object(mapping),
                    confidence,
                    suggestions,
                    mode: MatchingMode::Ai,
                }
            }
            None => {
                eprintln!("  ⚠ Failed to parse AI response, falling back to deterministic");
                DeterministicFieldMatcher.match_fields(src_fields, tgt_fields, source_sample)
            }
        }
    }
}

/// Extract a JSON block from a response that may contain markdown code fences.
fn extract_json_block(text: &str) -> &str {
    // Try to find ```json ... ``` block
    if let Some(start) = text.find("```json") {
        let json_start = start + "```json".len();
        if let Some(end) = text[json_start..].find("```") {
            return text[json_start..json_start + end].trim();
        }
    }
    // Try ``` ... ``` block
    if let Some(start) = text.find("```") {
        let json_start = start + "```".len();
        // Skip optional language identifier on first line
        let content = &text[json_start..];
        let actual_start = content.find('\n').map(|n| n + 1).unwrap_or(0);
        if let Some(end) = content[actual_start..].find("```") {
            return content[actual_start..actual_start + end].trim();
        }
    }
    // Assume the whole response is JSON
    text.trim()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ai_client::AiProvider;
    use crate::cli::error::CliError;
    use serde_json::json;

    /// Mock AI provider for testing.
    struct MockAiProvider {
        response: String,
    }

    impl MockAiProvider {
        fn new(response: &str) -> Self {
            Self {
                response: response.to_string(),
            }
        }
    }

    impl AiProvider for MockAiProvider {
        fn name(&self) -> &str {
            "mock"
        }
        fn complete(&self, _prompt: &str, _context: &str) -> Result<String, CliError> {
            Ok(self.response.clone())
        }
    }

    #[test]
    fn test_ai_field_match_basic() {
        let mock = MockAiProvider::new(
            r#"{"mappings": {"email": {"source": "$.user_email", "confidence": 0.95}, "name": {"source": "$.display_name", "confidence": 0.88}}, "transformations": []}"#,
        );
        let matcher = AiFieldMatcher::from_provider(Box::new(mock), "test-model".to_string());

        let src = vec![
            "user_email".to_string(),
            "display_name".to_string(),
            "id".to_string(),
        ];
        let tgt = vec!["email".to_string(), "name".to_string()];
        let result = matcher.match_fields(&src, &tgt, None);

        assert_eq!(result.mode, MatchingMode::Ai);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["email"], "$.user_email");
        assert_eq!(map["name"], "$.display_name");
        assert!((*result.confidence.get("email").unwrap() - 0.95).abs() < 0.01);
        assert!((*result.confidence.get("name").unwrap() - 0.88).abs() < 0.01);
    }

    #[test]
    fn test_ai_field_match_with_transformations() {
        let mock = MockAiProvider::new(
            r#"{"mappings": {"email": {"source": "$.mail", "confidence": 0.9}}, "transformations": [{"target": "full_name", "expression": "concat($.first_name, ' ', $.last_name)", "description": "Combine first and last name"}]}"#,
        );
        let matcher = AiFieldMatcher::from_provider(Box::new(mock), "test-model".to_string());

        let src = vec![
            "mail".to_string(),
            "first_name".to_string(),
            "last_name".to_string(),
        ];
        let tgt = vec!["email".to_string(), "full_name".to_string()];
        let result = matcher.match_fields(&src, &tgt, None);

        assert_eq!(result.suggestions.len(), 1);
        assert_eq!(result.suggestions[0].target_field, "full_name");
        assert!(result.suggestions[0].expression.contains("concat"));
    }

    #[test]
    fn test_ai_field_match_with_code_fence() {
        let mock = MockAiProvider::new(
            "Here's the mapping:\n```json\n{\"mappings\": {\"email\": {\"source\": \"$.mail\", \"confidence\": 0.9}}, \"transformations\": []}\n```",
        );
        let matcher = AiFieldMatcher::from_provider(Box::new(mock), "test-model".to_string());

        let src = vec!["mail".to_string()];
        let tgt = vec!["email".to_string()];
        let result = matcher.match_fields(&src, &tgt, None);

        assert_eq!(result.mode, MatchingMode::Ai);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["email"], "$.mail");
    }

    #[test]
    fn test_ai_field_match_fallback_on_bad_response() {
        let mock = MockAiProvider::new("This is not JSON at all!");
        let matcher = AiFieldMatcher::from_provider(Box::new(mock), "test-model".to_string());

        let src = vec!["email".to_string()];
        let tgt = vec!["email".to_string()];
        let result = matcher.match_fields(&src, &tgt, None);

        // Falls back to deterministic
        assert_eq!(result.mode, MatchingMode::Deterministic);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["email"], "$.email");
    }

    #[test]
    fn test_ai_field_match_fallback_on_provider_error() {
        struct FailingProvider;
        impl AiProvider for FailingProvider {
            fn name(&self) -> &str {
                "failing"
            }
            fn complete(&self, _: &str, _: &str) -> Result<String, CliError> {
                Err(CliError::AiProviderError {
                    provider: "failing".to_string(),
                    message: "Connection refused".to_string(),
                })
            }
        }

        let matcher = AiFieldMatcher::from_provider(Box::new(FailingProvider), "test".to_string());
        let src = vec!["email".to_string()];
        let tgt = vec!["email".to_string()];
        let result = matcher.match_fields(&src, &tgt, None);

        assert_eq!(result.mode, MatchingMode::Deterministic);
    }

    #[test]
    fn test_extract_json_block_bare() {
        let input = r#"{"mappings": {}}"#;
        assert_eq!(extract_json_block(input), r#"{"mappings": {}}"#);
    }

    #[test]
    fn test_extract_json_block_fenced() {
        let input = "Some text\n```json\n{\"key\": \"value\"}\n```\nMore text";
        assert_eq!(extract_json_block(input), "{\"key\": \"value\"}");
    }

    #[test]
    fn test_build_prompt_with_sample() {
        let mock = MockAiProvider::new("{}");
        let matcher = AiFieldMatcher::from_provider(Box::new(mock), "test".to_string());
        let sample = json!({"email": "test@example.com", "name": "John"});
        let prompt = matcher.build_prompt(
            &["email".to_string(), "name".to_string()],
            &["mail".to_string()],
            Some(&sample),
        );
        assert!(prompt.contains("Source fields: [email, name]"));
        assert!(prompt.contains("Target fields: [mail]"));
        assert!(prompt.contains("Sample source data:"));
    }
}
