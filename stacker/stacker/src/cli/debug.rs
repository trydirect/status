pub fn cli_debug_enabled() -> bool {
    ["DEBUG", "STACKER_DEBUG"].iter().any(|key| {
        std::env::var(key)
            .map(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    }) || std::env::var("RUST_LOG")
        .map(|value| {
            value.split(',').any(|directive| {
                let directive = directive.trim();
                directive.eq_ignore_ascii_case("debug")
                    || directive
                        .rsplit_once('=')
                        .is_some_and(|(_, level)| level.eq_ignore_ascii_case("debug"))
            })
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::cli_debug_enabled;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn clear_debug_env() {
        std::env::remove_var("DEBUG");
        std::env::remove_var("STACKER_DEBUG");
        std::env::remove_var("RUST_LOG");
    }

    #[test]
    fn cli_debug_enabled_accepts_debug_true() {
        let _guard = env_lock();
        clear_debug_env();
        std::env::set_var("DEBUG", "true");
        assert!(cli_debug_enabled());
        clear_debug_env();
    }

    #[test]
    fn cli_debug_enabled_accepts_stacker_debug_true() {
        let _guard = env_lock();
        clear_debug_env();
        std::env::set_var("STACKER_DEBUG", "true");
        assert!(cli_debug_enabled());
        clear_debug_env();
    }

    #[test]
    fn cli_debug_enabled_accepts_rust_log_debug() {
        let _guard = env_lock();
        clear_debug_env();
        std::env::set_var("RUST_LOG", "debug");
        assert!(cli_debug_enabled());
        clear_debug_env();
    }

    #[test]
    fn cli_debug_enabled_accepts_module_rust_log_debug() {
        let _guard = env_lock();
        clear_debug_env();
        std::env::set_var("RUST_LOG", "info,stacker=debug");
        assert!(cli_debug_enabled());
        clear_debug_env();
    }

    #[test]
    fn cli_debug_enabled_ignores_non_debug_rust_log() {
        let _guard = env_lock();
        clear_debug_env();
        std::env::set_var("RUST_LOG", "info,stacker=trace");
        assert!(!cli_debug_enabled());
        clear_debug_env();
    }
}
