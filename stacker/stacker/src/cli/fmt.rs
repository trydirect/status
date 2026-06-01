//! Shared terminal formatting helpers.
//!
//! Provides reusable utilities for table rendering, string truncation,
//! and human-readable output that multiple CLI commands can share.

/// Truncate a string to `max_len` characters, appending "…" if truncated.
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() > max_len {
        let truncated: String = s.chars().take(max_len.saturating_sub(1)).collect();
        format!("{}…", truncated)
    } else {
        s.to_string()
    }
}

/// Generate a horizontal separator of `width` Unicode box-drawing characters.
pub fn separator(width: usize) -> String {
    "─".repeat(width)
}

/// Format a JSON `Value` as pretty-printed JSON string, falling back to
/// compact `to_string()` if pretty-printing fails.
pub fn pretty_json(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// Display an optional string, returning the provided default when `None`.
pub fn display_opt(opt: Option<&str>, default: &str) -> String {
    opt.unwrap_or(default).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn truncate_exact_length_unchanged() {
        assert_eq!(truncate("abc", 3), "abc");
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("hello world", 6), "hello…");
    }

    #[test]
    fn separator_width() {
        assert_eq!(separator(3), "───");
    }

    #[test]
    fn display_opt_some() {
        assert_eq!(display_opt(Some("val"), "-"), "val");
    }

    #[test]
    fn display_opt_none() {
        assert_eq!(display_opt(None, "-"), "-");
    }
}
