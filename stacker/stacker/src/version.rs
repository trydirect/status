use std::sync::OnceLock;

static DISPLAY_VERSION: OnceLock<String> = OnceLock::new();

pub fn display_version() -> &'static str {
    DISPLAY_VERSION
        .get_or_init(|| match git_short_hash() {
            Some(hash) => format!("{} ({hash})", env!("CARGO_PKG_VERSION")),
            None => env!("CARGO_PKG_VERSION").to_string(),
        })
        .as_str()
}

pub fn git_short_hash() -> Option<&'static str> {
    option_env!("STACKER_GIT_SHORT_HASH").filter(|hash| !hash.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_version_uses_package_version_prefix() {
        assert!(display_version().starts_with(env!("CARGO_PKG_VERSION")));
    }
}
