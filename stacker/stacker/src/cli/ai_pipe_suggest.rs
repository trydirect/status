use crate::cli::ai_client::{create_provider, AiProvider};
use crate::cli::config_parser::AiConfig;
use crate::cli::error::CliError;
use serde::{Deserialize, Serialize};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AI Pipe Connection Suggestion Engine
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const PIPE_SUGGEST_SYSTEM_PROMPT: &str = "\
You are a data integration architect. Given two application API endpoint lists, \
suggest meaningful pipe connections between them. A pipe connects a source endpoint \
(that produces data) to a target endpoint (that consumes data).

Rules:
- Only suggest connections where data from the source can logically flow to the target
- Rank by confidence (0.0–1.0)
- Include a brief description of what each connection achieves
- Maximum 10 suggestions

Respond with ONLY valid JSON in this exact format:
{
  \"suggestions\": [
    {
      \"source\": {\"method\": \"GET\", \"path\": \"/api/posts\"},
      \"target\": {\"method\": \"POST\", \"path\": \"/api/messages\"},
      \"description\": \"Send new blog posts as messages\",
      \"confidence\": 0.92
    }
  ]
}";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeSuggestion {
    pub source: EndpointInfo,
    pub target: EndpointInfo,
    pub description: String,
    pub confidence: f32,
}

pub struct AiPipeSuggest {
    provider: Box<dyn AiProvider>,
}

impl AiPipeSuggest {
    pub fn new(config: &AiConfig) -> Result<Self, CliError> {
        let provider = create_provider(config)?;
        Ok(Self { provider })
    }

    #[cfg(test)]
    pub fn from_provider(provider: Box<dyn AiProvider>) -> Self {
        Self { provider }
    }

    /// Suggest pipe connections between source and target app endpoints.
    pub fn suggest(
        &self,
        source_app: &str,
        target_app: &str,
        source_endpoints: &[EndpointInfo],
        target_endpoints: &[EndpointInfo],
    ) -> Result<Vec<PipeSuggestion>, CliError> {
        let prompt = self.build_prompt(source_app, target_app, source_endpoints, target_endpoints);

        let response = self
            .provider
            .complete(PIPE_SUGGEST_SYSTEM_PROMPT, &prompt)?;

        match self.parse_response(&response) {
            Some(mut suggestions) => {
                // Sort by confidence descending
                suggestions.sort_by(|a, b| {
                    b.confidence
                        .partial_cmp(&a.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                Ok(suggestions)
            }
            None => {
                eprintln!("  ⚠ Failed to parse AI pipe suggestions");
                Ok(Vec::new())
            }
        }
    }

    fn build_prompt(
        &self,
        source_app: &str,
        target_app: &str,
        source_endpoints: &[EndpointInfo],
        target_endpoints: &[EndpointInfo],
    ) -> String {
        let src_json = serde_json::to_string_pretty(source_endpoints).unwrap_or_default();
        let tgt_json = serde_json::to_string_pretty(target_endpoints).unwrap_or_default();

        format!(
            "Source app: {source_app}\nSource endpoints:\n{src_json}\n\n\
             Target app: {target_app}\nTarget endpoints:\n{tgt_json}"
        )
    }

    fn parse_response(&self, response: &str) -> Option<Vec<PipeSuggestion>> {
        let json_str = extract_json_block(response);
        let parsed: serde_json::Value = serde_json::from_str(json_str).ok()?;

        let suggestions_arr = parsed.get("suggestions")?.as_array()?;
        let mut result = Vec::new();

        for item in suggestions_arr {
            let source = parse_endpoint_info(item.get("source")?)?;
            let target = parse_endpoint_info(item.get("target")?)?;
            let description = item.get("description")?.as_str()?.to_string();
            let confidence = item.get("confidence")?.as_f64()? as f32;

            result.push(PipeSuggestion {
                source,
                target,
                description,
                confidence,
            });
        }

        Some(result)
    }
}

fn parse_endpoint_info(val: &serde_json::Value) -> Option<EndpointInfo> {
    Some(EndpointInfo {
        method: val.get("method")?.as_str()?.to_string(),
        path: val.get("path")?.as_str()?.to_string(),
        description: val
            .get("description")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string()),
        fields: None,
    })
}

/// Extract a JSON block from a response that may contain markdown code fences.
fn extract_json_block(text: &str) -> &str {
    if let Some(start) = text.find("```json") {
        let json_start = start + "```json".len();
        if let Some(end) = text[json_start..].find("```") {
            return text[json_start..json_start + end].trim();
        }
    }
    if let Some(start) = text.find("```") {
        let json_start = start + "```".len();
        let content = &text[json_start..];
        let actual_start = content.find('\n').map(|n| n + 1).unwrap_or(0);
        if let Some(end) = content[actual_start..].find("```") {
            return content[actual_start..actual_start + end].trim();
        }
    }
    text.trim()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ai_client::AiProvider;
    use crate::cli::error::CliError;

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
    fn test_suggest_basic() {
        let mock = MockAiProvider::new(
            r#"{"suggestions": [{"source": {"method": "GET", "path": "/api/posts"}, "target": {"method": "POST", "path": "/api/messages"}, "description": "Post blog updates to chat", "confidence": 0.92}]}"#,
        );
        let engine = AiPipeSuggest::from_provider(Box::new(mock));

        let src = vec![EndpointInfo {
            method: "GET".to_string(),
            path: "/api/posts".to_string(),
            description: None,
            fields: None,
        }];
        let tgt = vec![EndpointInfo {
            method: "POST".to_string(),
            path: "/api/messages".to_string(),
            description: None,
            fields: None,
        }];

        let result = engine.suggest("wordpress", "slack", &src, &tgt).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].source.path, "/api/posts");
        assert_eq!(result[0].target.path, "/api/messages");
        assert!(result[0].confidence > 0.9);
    }

    #[test]
    fn test_suggest_multiple_sorted_by_confidence() {
        let mock = MockAiProvider::new(
            r#"{"suggestions": [
                {"source": {"method": "GET", "path": "/api/posts"}, "target": {"method": "POST", "path": "/api/feed"}, "description": "Low confidence", "confidence": 0.5},
                {"source": {"method": "GET", "path": "/api/users"}, "target": {"method": "POST", "path": "/api/contacts"}, "description": "High confidence", "confidence": 0.95}
            ]}"#,
        );
        let engine = AiPipeSuggest::from_provider(Box::new(mock));

        let result = engine.suggest("app1", "app2", &[], &[]).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result[0].confidence > result[1].confidence);
        assert_eq!(result[0].description, "High confidence");
    }

    #[test]
    fn test_suggest_empty_on_bad_response() {
        let mock = MockAiProvider::new("Not valid JSON");
        let engine = AiPipeSuggest::from_provider(Box::new(mock));

        let result = engine.suggest("app1", "app2", &[], &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_suggest_error_propagation() {
        struct FailingProvider;
        impl AiProvider for FailingProvider {
            fn name(&self) -> &str {
                "failing"
            }
            fn complete(&self, _: &str, _: &str) -> Result<String, CliError> {
                Err(CliError::AiProviderError {
                    provider: "failing".to_string(),
                    message: "timeout".to_string(),
                })
            }
        }

        let engine = AiPipeSuggest::from_provider(Box::new(FailingProvider));
        let result = engine.suggest("app1", "app2", &[], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_suggest_with_code_fence() {
        let mock = MockAiProvider::new(
            "Here are my suggestions:\n```json\n{\"suggestions\": [{\"source\": {\"method\": \"GET\", \"path\": \"/data\"}, \"target\": {\"method\": \"POST\", \"path\": \"/ingest\"}, \"description\": \"Sync data\", \"confidence\": 0.88}]}\n```",
        );
        let engine = AiPipeSuggest::from_provider(Box::new(mock));

        let result = engine.suggest("src", "tgt", &[], &[]).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].description, "Sync data");
    }
}
