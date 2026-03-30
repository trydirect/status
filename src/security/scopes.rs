use std::collections::HashSet;

#[derive(Debug, Clone, Default)]
pub struct Scopes {
    allowed: HashSet<String>,
}

impl Scopes {
    pub fn from_env() -> Self {
        let mut s = Self {
            allowed: HashSet::new(),
        };
        if let Ok(val) = std::env::var("AGENT_SCOPES") {
            for item in val.split(',') {
                let scope = item.trim();
                if !scope.is_empty() {
                    s.allowed.insert(scope.to_string());
                }
            }
        }
        s
    }

    pub fn is_allowed(&self, scope: &str) -> bool {
        if self.allowed.is_empty() {
            return true;
        }
        self.allowed.contains(scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::EnvGuard;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn empty_scopes_allow_everything() {
        let scopes = Scopes::default();
        assert!(scopes.is_allowed("anything"));
        assert!(scopes.is_allowed("docker:restart"));
        assert!(scopes.is_allowed(""));
    }

    #[test]
    fn scopes_with_values_restrict_access() {
        let mut allowed = HashSet::new();
        allowed.insert("docker:restart".to_string());
        allowed.insert("docker:logs".to_string());
        let scopes = Scopes { allowed };

        assert!(scopes.is_allowed("docker:restart"));
        assert!(scopes.is_allowed("docker:logs"));
        assert!(!scopes.is_allowed("docker:stop"));
        assert!(!scopes.is_allowed("admin"));
    }

    #[test]
    fn scopes_from_env_parses_comma_separated() {
        let _lock = env_lock().lock().expect("env lock poisoned");
        let _env = EnvGuard::set("AGENT_SCOPES", "docker:restart,docker:logs,admin");
        let scopes = Scopes::from_env();
        assert!(scopes.is_allowed("docker:restart"));
        assert!(scopes.is_allowed("docker:logs"));
        assert!(scopes.is_allowed("admin"));
        assert!(!scopes.is_allowed("docker:stop"));
    }

    #[test]
    fn scopes_from_env_trims_whitespace() {
        let _lock = env_lock().lock().expect("env lock poisoned");
        let _env = EnvGuard::set("AGENT_SCOPES", " docker:restart , admin ");
        let scopes = Scopes::from_env();
        assert!(scopes.is_allowed("docker:restart"));
        assert!(scopes.is_allowed("admin"));
    }

    #[test]
    fn scopes_from_env_skips_empty_items() {
        let _lock = env_lock().lock().expect("env lock poisoned");
        let _env = EnvGuard::set("AGENT_SCOPES", "docker:restart,,, ,admin");
        let scopes = Scopes::from_env();
        assert!(scopes.is_allowed("docker:restart"));
        assert!(scopes.is_allowed("admin"));
        // The empty strings should NOT be in the set
        assert!(!scopes.is_allowed(""));
    }

    #[test]
    fn scopes_from_env_missing_var_allows_all() {
        let _lock = env_lock().lock().expect("env lock poisoned");
        let _env = EnvGuard::remove("AGENT_SCOPES");
        let scopes = Scopes::from_env();
        assert!(scopes.is_allowed("anything"));
    }

    #[test]
    fn scopes_from_env_empty_string_allows_all() {
        let _lock = env_lock().lock().expect("env lock poisoned");
        let _env = EnvGuard::set("AGENT_SCOPES", "");
        let scopes = Scopes::from_env();
        assert!(scopes.is_allowed("anything"));
    }
}
