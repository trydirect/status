/// Helper function to determine if a plan tier can access a required plan
/// Hierarchy (lowest to highest): free < basic < professional < enterprise
pub(crate) fn is_plan_higher_tier(user_plan: &str, required_plan: &str) -> bool {
    let plan_hierarchy = vec!["free", "basic", "professional", "enterprise"];

    let user_lower = user_plan.to_lowercase();
    let required_lower = required_plan.to_lowercase();

    let user_level = plan_hierarchy
        .iter()
        .position(|&p| p == user_lower.as_str());
    let required_level = plan_hierarchy
        .iter()
        .position(|&p| p == required_lower.as_str());

    match (user_level, required_level) {
        (Some(user_level), Some(required_level)) => user_level >= required_level,
        // Fail closed if either plan is unknown
        _ => false,
    }
}
