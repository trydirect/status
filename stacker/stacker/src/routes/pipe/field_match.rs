use crate::cli::field_matcher::FieldMatcher;
use crate::cli::ml_field_matcher::MlFieldMatcher;
use crate::helpers::JsonResponse;
use crate::models::User;
use actix_web::{post, web, Responder, Result};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct FieldMatchRequest {
    pub source_fields: Vec<String>,
    pub target_fields: Vec<String>,
    pub threshold: Option<f32>,
}

#[tracing::instrument(name = "Match fields using ML matcher", skip_all)]
#[post("/field-match")]
pub async fn field_match_handler(
    _user: web::ReqData<Arc<User>>,
    body: web::Json<FieldMatchRequest>,
) -> Result<impl Responder> {
    let matcher = match body.threshold {
        Some(t) => MlFieldMatcher::with_threshold(t),
        None => MlFieldMatcher::new(),
    };

    let result = matcher.match_fields(&body.source_fields, &body.target_fields, None);

    // Compute unmatched fields from the mapping
    let mapped_sources: Vec<String> = result
        .mapping
        .as_object()
        .map(|m| {
            m.values()
                .filter_map(|v| v.as_str().map(|s| s.trim_start_matches("$.").to_string()))
                .collect()
        })
        .unwrap_or_default();

    let mapped_targets: Vec<&str> = result
        .mapping
        .as_object()
        .map(|m| m.keys().map(|k| k.as_str()).collect())
        .unwrap_or_default();

    let unmatched_source: Vec<&str> = body
        .source_fields
        .iter()
        .filter(|s| !s.is_empty() && !mapped_sources.contains(&s.to_string()))
        .map(|s| s.as_str())
        .collect();

    let unmatched_target: Vec<&str> = body
        .target_fields
        .iter()
        .filter(|t| !t.is_empty() && !mapped_targets.contains(&t.as_str()))
        .map(|t| t.as_str())
        .collect();

    Ok(JsonResponse::build()
        .set_item(Some(serde_json::json!({
            "mapping": result.mapping,
            "confidence": result.confidence,
            "suggestions": result.suggestions.iter().map(|s| serde_json::json!({
                "target_field": s.target_field,
                "expression": s.expression,
                "description": s.description,
            })).collect::<Vec<_>>(),
            "unmatched_source": unmatched_source,
            "unmatched_target": unmatched_target,
        })))
        .ok("Field matching completed"))
}
