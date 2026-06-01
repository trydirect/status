use std::collections::HashMap;

use crate::cli::field_matcher::{
    FieldMatchResult, FieldMatcher, MatchingMode, TransformSuggestion, FIELD_ALIASES,
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// MlFieldMatcher — cosine-similarity matching on n-gram vectors
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Minimum cosine similarity to consider a match.
const DEFAULT_THRESHOLD: f32 = 0.45;

/// Size of character n-grams.
const NGRAM_SIZE: usize = 3;

/// ML-inspired field matcher using character n-gram vectorization and cosine similarity.
///
/// Matching layers (applied in order, first match wins):
/// 1. Exact name match (confidence 1.0)
/// 2. Case-insensitive match (confidence 0.95)
/// 3. Semantic alias match (confidence 0.90)
/// 4. N-gram cosine similarity (confidence = similarity score)
/// 5. Token overlap scoring for compound field names (confidence = overlap ratio)
pub struct MlFieldMatcher {
    threshold: f32,
}

impl MlFieldMatcher {
    pub fn new() -> Self {
        Self {
            threshold: DEFAULT_THRESHOLD,
        }
    }

    pub fn with_threshold(threshold: f32) -> Self {
        Self { threshold }
    }
}

impl Default for MlFieldMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldMatcher for MlFieldMatcher {
    fn match_fields(
        &self,
        src_fields: &[String],
        tgt_fields: &[String],
        _source_sample: Option<&serde_json::Value>,
    ) -> FieldMatchResult {
        let mut mapping = serde_json::Map::new();
        let mut confidence = HashMap::new();
        let mut suggestions = Vec::new();
        let mut used_sources: Vec<String> = Vec::new();

        for tgt_field in tgt_fields {
            let available: Vec<&String> = src_fields
                .iter()
                .filter(|s| !used_sources.contains(s))
                .collect();

            if available.is_empty() {
                break;
            }

            if let Some((src, score)) = best_match(tgt_field, &available, self.threshold) {
                mapping.insert(
                    tgt_field.clone(),
                    serde_json::Value::String(format!("$.{}", src)),
                );
                confidence.insert(tgt_field.clone(), score);
                used_sources.push(src.clone());

                // Suggest transformation if score is moderate (fuzzy match)
                if score < 0.85 && score >= self.threshold {
                    suggestions.push(TransformSuggestion {
                        target_field: tgt_field.clone(),
                        expression: format!("$.{}", src),
                        description: format!(
                            "Fuzzy match (confidence {:.0}%) — verify mapping correctness",
                            score * 100.0
                        ),
                    });
                }
            }
        }

        FieldMatchResult {
            mapping: serde_json::Value::Object(mapping),
            confidence,
            suggestions,
            mode: MatchingMode::Ml,
        }
    }
}

/// Find the best matching source field for a target field.
/// Returns (source_field, confidence) or None if below threshold.
fn best_match(target: &str, sources: &[&String], threshold: f32) -> Option<(String, f32)> {
    // Layer 1: Exact match
    if let Some(src) = sources.iter().find(|s| s.as_str() == target) {
        return Some(((*src).clone(), 1.0));
    }

    // Layer 2: Case-insensitive
    let tgt_lower = target.to_ascii_lowercase();
    if let Some(src) = sources.iter().find(|s| s.to_ascii_lowercase() == tgt_lower) {
        return Some(((*src).clone(), 0.95));
    }

    // Layer 3: Semantic aliases
    for (group_a, group_b) in FIELD_ALIASES {
        if group_a.iter().any(|a| a.eq_ignore_ascii_case(target)) {
            if let Some(src) = sources
                .iter()
                .find(|sf| group_b.iter().any(|b| b.eq_ignore_ascii_case(sf)))
            {
                return Some(((*src).clone(), 0.90));
            }
        }
    }

    // Layer 4: N-gram cosine similarity
    let tgt_vec = ngram_vector(target);
    let mut best: Option<(String, f32)> = None;

    for src in sources {
        let src_vec = ngram_vector(src);
        let sim = cosine_similarity(&tgt_vec, &src_vec);
        if sim >= threshold {
            if best.as_ref().map_or(true, |(_, s)| sim > *s) {
                best = Some(((*src).clone(), sim));
            }
        }
    }

    if let Some(ref b) = best {
        if b.1 >= threshold {
            return best;
        }
    }

    // Layer 5: Token overlap (split on _ and compare tokens)
    let tgt_tokens = tokenize(target);
    let mut best_overlap: Option<(String, f32)> = None;

    for src in sources {
        let src_tokens = tokenize(src);
        let overlap = token_overlap_score(&tgt_tokens, &src_tokens);
        if overlap >= threshold {
            if best_overlap.as_ref().map_or(true, |(_, s)| overlap > *s) {
                best_overlap = Some(((*src).clone(), overlap));
            }
        }
    }

    best_overlap
}

/// Build a character n-gram frequency vector (HashMap representation).
fn ngram_vector(field: &str) -> HashMap<String, f32> {
    let normalized = normalize_field_name(field);
    let chars: Vec<char> = normalized.chars().collect();
    let mut vec = HashMap::new();

    if chars.len() < NGRAM_SIZE {
        // For very short strings, use the whole string as a single gram
        *vec.entry(normalized.clone()).or_insert(0.0) += 1.0;
        return vec;
    }

    for window in chars.windows(NGRAM_SIZE) {
        let gram: String = window.iter().collect();
        *vec.entry(gram).or_insert(0.0) += 1.0;
    }
    vec
}

/// Cosine similarity between two sparse vectors.
fn cosine_similarity(a: &HashMap<String, f32>, b: &HashMap<String, f32>) -> f32 {
    let dot: f32 = a
        .iter()
        .filter_map(|(k, v)| b.get(k).map(|bv| v * bv))
        .sum();

    let mag_a: f32 = a.values().map(|v| v * v).sum::<f32>().sqrt();
    let mag_b: f32 = b.values().map(|v| v * v).sum::<f32>().sqrt();

    if mag_a == 0.0 || mag_b == 0.0 {
        return 0.0;
    }

    dot / (mag_a * mag_b)
}

/// Normalize a field name for n-gram extraction.
fn normalize_field_name(name: &str) -> String {
    // Convert camelCase to snake_case, then lowercase
    let mut result = String::with_capacity(name.len() + 4);
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(ch.to_ascii_lowercase());
    }
    result
}

/// Tokenize a field name by splitting on _, -, and camelCase boundaries.
fn tokenize(name: &str) -> Vec<String> {
    let normalized = normalize_field_name(name);
    normalized
        .split(|c: char| c == '_' || c == '-')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Compute token overlap score (Jaccard-like).
fn token_overlap_score(a: &[String], b: &[String]) -> f32 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

    let matches = a.iter().filter(|t| b.contains(t)).count();
    let total = a.len().max(b.len());

    matches as f32 / total as f32
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Unit tests for helper functions ─────────────────

    #[test]
    fn test_normalize_camel_case() {
        assert_eq!(normalize_field_name("firstName"), "first_name");
        assert_eq!(
            normalize_field_name("userEmailAddress"),
            "user_email_address"
        );
        assert_eq!(normalize_field_name("id"), "id");
        assert_eq!(normalize_field_name("HTTPStatus"), "h_t_t_p_status");
    }

    #[test]
    fn test_tokenize() {
        assert_eq!(tokenize("first_name"), vec!["first", "name"]);
        assert_eq!(tokenize("userName"), vec!["user", "name"]);
        assert_eq!(tokenize("email"), vec!["email"]);
        assert_eq!(
            tokenize("user-email-address"),
            vec!["user", "email", "address"]
        );
    }

    #[test]
    fn test_ngram_vector_basic() {
        let vec = ngram_vector("email");
        // "email" → 5 chars → 3 trigrams: "ema", "mai", "ail"
        assert_eq!(vec.len(), 3);
        assert_eq!(*vec.get("ema").unwrap(), 1.0);
        assert_eq!(*vec.get("mai").unwrap(), 1.0);
        assert_eq!(*vec.get("ail").unwrap(), 1.0);
    }

    #[test]
    fn test_ngram_vector_short() {
        let vec = ngram_vector("id");
        assert_eq!(vec.len(), 1);
        assert!(vec.contains_key("id"));
    }

    #[test]
    fn test_cosine_similarity_identical() {
        let a = ngram_vector("email");
        let b = ngram_vector("email");
        let sim = cosine_similarity(&a, &b);
        assert!((sim - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_cosine_similarity_similar() {
        let a = ngram_vector("user_email");
        let b = ngram_vector("email_user");
        let sim = cosine_similarity(&a, &b);
        // These share many trigrams so similarity should be high
        assert!(sim > 0.5, "Expected > 0.5, got {}", sim);
    }

    #[test]
    fn test_cosine_similarity_dissimilar() {
        let a = ngram_vector("email");
        let b = ngram_vector("zzzzzz");
        let sim = cosine_similarity(&a, &b);
        assert!(sim < 0.1, "Expected < 0.1, got {}", sim);
    }

    #[test]
    fn test_cosine_empty_vector() {
        let a: HashMap<String, f32> = HashMap::new();
        let b = ngram_vector("email");
        assert_eq!(cosine_similarity(&a, &b), 0.0);
    }

    #[test]
    fn test_token_overlap_exact() {
        let a = tokenize("first_name");
        let b = tokenize("first_name");
        assert_eq!(token_overlap_score(&a, &b), 1.0);
    }

    #[test]
    fn test_token_overlap_partial() {
        let a = tokenize("user_name");
        let b = tokenize("user_email");
        // overlap: "user" (1 of 2)
        assert!((token_overlap_score(&a, &b) - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_token_overlap_empty() {
        let a: Vec<String> = vec![];
        let b = tokenize("email");
        assert_eq!(token_overlap_score(&a, &b), 0.0);
    }

    // ── Integration tests for MlFieldMatcher ────────────

    #[test]
    fn test_ml_exact_match() {
        let matcher = MlFieldMatcher::new();
        let src = vec!["email".into(), "name".into()];
        let tgt = vec!["email".into(), "name".into()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["email"], "$.email");
        assert_eq!(map["name"], "$.name");
        assert_eq!(*result.confidence.get("email").unwrap(), 1.0);
        assert_eq!(*result.confidence.get("name").unwrap(), 1.0);
        assert_eq!(result.mode, MatchingMode::Ml);
    }

    #[test]
    fn test_ml_case_insensitive() {
        let matcher = MlFieldMatcher::new();
        let src = vec!["Email".into(), "UserName".into()];
        let tgt = vec!["email".into(), "username".into()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["email"], "$.Email");
        assert_eq!(map["username"], "$.UserName");
        assert_eq!(*result.confidence.get("email").unwrap(), 0.95);
    }

    #[test]
    fn test_ml_semantic_aliases() {
        let matcher = MlFieldMatcher::new();
        let src = vec!["user_email".into(), "display_name".into()];
        let tgt = vec!["email".into(), "name".into()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["email"], "$.user_email");
        assert_eq!(map["name"], "$.display_name");
        assert_eq!(*result.confidence.get("email").unwrap(), 0.90);
    }

    #[test]
    fn test_ml_ngram_fuzzy_match() {
        let matcher = MlFieldMatcher::new();
        let src = vec!["customer_email_address".into(), "customer_name".into()];
        let tgt = vec!["email_addr".into()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        // Should fuzzy-match via n-gram similarity
        assert!(
            map.contains_key("email_addr"),
            "Expected fuzzy match for email_addr"
        );
        let conf = *result.confidence.get("email_addr").unwrap();
        assert!(
            conf >= 0.45 && conf < 1.0,
            "Expected fuzzy confidence, got {}",
            conf
        );
    }

    #[test]
    fn test_ml_token_overlap_match() {
        let matcher = MlFieldMatcher::new();
        let src = vec!["order_date".into(), "order_total".into()];
        let tgt = vec!["purchase_date".into()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        // "purchase_date" and "order_date" share token "date"
        if map.contains_key("purchase_date") {
            assert_eq!(map["purchase_date"], "$.order_date");
        }
    }

    #[test]
    fn test_ml_no_match_below_threshold() {
        let matcher = MlFieldMatcher::new();
        let src = vec!["aaaa".into(), "bbbb".into()];
        let tgt = vec!["xxxx".into()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert!(
            map.is_empty(),
            "Expected no match for totally dissimilar fields"
        );
    }

    #[test]
    fn test_ml_custom_threshold() {
        let matcher = MlFieldMatcher::with_threshold(0.99);
        let src = vec!["order_status".into()];
        let tgt = vec!["shipment_state".into()];
        let result = matcher.match_fields(&src, &tgt, None);
        // With 0.99 threshold, only exact/near-exact matches qualify
        let map = result.mapping.as_object().unwrap();
        assert!(
            map.is_empty(),
            "Expected no match at 0.99 threshold, got: {:?}",
            map
        );
    }

    #[test]
    fn test_ml_suggestions_for_fuzzy() {
        let matcher = MlFieldMatcher::with_threshold(0.40);
        let src = vec!["customer_email_address".into()];
        let tgt = vec!["email_addr".into()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        if map.contains_key("email_addr") {
            let conf = *result.confidence.get("email_addr").unwrap();
            if conf < 0.85 {
                assert!(
                    !result.suggestions.is_empty(),
                    "Expected suggestion for fuzzy match"
                );
                assert!(result.suggestions[0].description.contains("Fuzzy match"));
            }
        }
    }

    #[test]
    fn test_ml_no_duplicate_source_mapping() {
        let matcher = MlFieldMatcher::new();
        let src = vec!["email".into()];
        let tgt = vec!["email".into(), "mail".into()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        // "email" should only map once (first match wins)
        assert_eq!(map.len(), 1);
        assert_eq!(map["email"], "$.email");
    }

    #[test]
    fn test_ml_mixed_strategies() {
        let matcher = MlFieldMatcher::new();
        let src = vec![
            "email".into(),
            "display_name".into(),
            "Phone".into(),
            "customer_address_line1".into(),
        ];
        let tgt = vec![
            "email".into(),      // exact → 1.0
            "name".into(),       // alias → 0.90
            "phone".into(),      // case insensitive → 0.95
            "addr_line1".into(), // fuzzy
        ];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["email"], "$.email");
        assert_eq!(map["name"], "$.display_name");
        assert_eq!(map["phone"], "$.Phone");
        assert!(
            map.len() >= 3,
            "Expected at least 3 matches, got {}",
            map.len()
        );
    }

    #[test]
    fn test_ml_empty_inputs() {
        let matcher = MlFieldMatcher::new();
        let result = matcher.match_fields(&[], &[], None);
        assert!(result.mapping.as_object().unwrap().is_empty());
        assert!(result.confidence.is_empty());

        let result2 = matcher.match_fields(&["a".into()], &[], None);
        assert!(result2.mapping.as_object().unwrap().is_empty());

        let result3 = matcher.match_fields(&[], &["a".into()], None);
        assert!(result3.mapping.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_ml_mode_is_ml() {
        let matcher = MlFieldMatcher::new();
        let result = matcher.match_fields(&["a".into()], &["a".into()], None);
        assert_eq!(result.mode, MatchingMode::Ml);
    }

    #[test]
    fn test_ml_camel_case_normalization() {
        let matcher = MlFieldMatcher::new();
        let src = vec!["firstName".into()];
        let tgt = vec!["first_name".into()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        // After normalization, "firstName" → "first_name" which is a near-perfect match
        assert!(
            map.contains_key("first_name"),
            "Expected camelCase to snake_case match"
        );
    }
}
