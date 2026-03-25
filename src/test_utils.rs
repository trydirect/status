/// A drop-based guard that saves an environment variable's original value before modification
/// and restores it when dropped, ensuring cleanup even when test assertions panic.
pub(crate) struct EnvGuard {
    key: &'static str,
    original: Option<String>,
}

impl EnvGuard {
    /// Sets `key` to `value` and saves the previous value for restoration on drop.
    pub(crate) fn set(key: &'static str, value: &str) -> Self {
        let original = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, original }
    }

    /// Removes `key` from the environment and saves the previous value for restoration on drop.
    pub(crate) fn remove(key: &'static str) -> Self {
        let original = std::env::var(key).ok();
        std::env::remove_var(key);
        Self { key, original }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.original {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}
