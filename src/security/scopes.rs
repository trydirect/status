use std::collections::HashSet;

#[derive(Debug, Clone, Default)]
pub struct Scopes {
    allowed: HashSet<String>,
}

impl Scopes {
    pub fn from_env() -> Self {
        let mut s = Self { allowed: HashSet::new() };
        if let Ok(val) = std::env::var("AGENT_SCOPES") {
            for item in val.split(',') {
                let scope = item.trim();
                if !scope.is_empty() { s.allowed.insert(scope.to_string()); }
            }
        }
        s
    }

    pub fn is_allowed(&self, scope: &str) -> bool {
        if self.allowed.is_empty() { return true; }
        self.allowed.contains(scope)
    }
}
