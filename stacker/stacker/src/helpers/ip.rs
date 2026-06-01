pub(crate) fn extract_ipv4_from_text(text: &str) -> Option<String> {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .find_map(|candidate| {
            let trimmed = candidate.trim_matches('.');
            if trimmed.parse::<std::net::Ipv4Addr>().is_ok() {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ipv4_from_status_message_prefix() {
        assert_eq!(
            extract_ipv4_from_text("178.104.222.170: Copy files is done"),
            Some("178.104.222.170".to_string())
        );
    }

    #[test]
    fn ignores_text_without_valid_ipv4() {
        assert_eq!(extract_ipv4_from_text("Deployment still in progress"), None);
        assert_eq!(
            extract_ipv4_from_text("invalid 999.104.222.170: message"),
            None
        );
    }
}
