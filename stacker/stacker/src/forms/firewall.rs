use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct FirewallPortRule {
    pub port: u16,
    #[serde(default = "default_firewall_protocol")]
    pub protocol: String,
    #[serde(default = "default_firewall_source")]
    pub source: String,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallRuleDirection {
    Inbound,
    Outbound,
}

impl FirewallRuleDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

pub fn default_firewall_protocol() -> String {
    "tcp".to_string()
}

pub fn default_firewall_source() -> String {
    "0.0.0.0/0".to_string()
}

pub fn parse_public_port(input: &str) -> Result<FirewallPortRule, String> {
    let (port, protocol) = parse_port_proto(input)?;
    let rule = FirewallPortRule {
        port,
        protocol,
        source: default_firewall_source(),
        comment: None,
    };
    validate_rule(&rule)?;
    Ok(rule)
}

pub fn parse_private_port(input: &str) -> Result<FirewallPortRule, String> {
    let (port_proto, source) = input.split_once(':').ok_or_else(|| {
        format!(
            "Invalid private port '{}'. Expected format: port[/proto]:source",
            input
        )
    })?;
    if source.trim().is_empty() {
        return Err(format!(
            "Invalid private port '{}'. Source CIDR is required",
            input
        ));
    }

    let (port, protocol) = parse_port_proto(port_proto)?;
    let rule = FirewallPortRule {
        port,
        protocol,
        source: source.to_string(),
        comment: None,
    };
    validate_rule(&rule)?;
    Ok(rule)
}

pub fn validate_rule(rule: &FirewallPortRule) -> Result<(), String> {
    if rule.port == 0 {
        return Err("port must be > 0".to_string());
    }
    if !matches!(rule.protocol.as_str(), "tcp" | "udp") {
        return Err("protocol must be one of: tcp, udp".to_string());
    }
    validate_cidr(&rule.source)?;
    Ok(())
}

fn parse_port_proto(input: &str) -> Result<(u16, String), String> {
    let (port, protocol) = input
        .split_once('/')
        .map(|(port, protocol)| (port, protocol))
        .unwrap_or((input, "tcp"));
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("Invalid port number: {}", port))?;
    Ok((port, protocol.to_string()))
}

fn validate_cidr(input: &str) -> Result<(), String> {
    let (ip, prefix) = input
        .split_once('/')
        .ok_or_else(|| format!("source must be a CIDR range: {}", input))?;
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| format!("source IP is invalid: {}", input))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| format!("source CIDR prefix is invalid: {}", input))?;
    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return Err(format!("source CIDR prefix is invalid: {}", input));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_public_port_defaults_tcp_and_public_source() {
        let rule = parse_public_port("8000").expect("port should parse");

        assert_eq!(rule.port, 8000);
        assert_eq!(rule.protocol, "tcp");
        assert_eq!(rule.source, "0.0.0.0/0");
    }

    #[test]
    fn parse_public_port_accepts_udp() {
        let rule = parse_public_port("53/udp").expect("udp port should parse");

        assert_eq!(rule.port, 53);
        assert_eq!(rule.protocol, "udp");
    }

    #[test]
    fn parse_private_port_requires_source_cidr() {
        let rule = parse_private_port("5432/tcp:10.0.0.0/8").expect("private port should parse");

        assert_eq!(rule.port, 5432);
        assert_eq!(rule.protocol, "tcp");
        assert_eq!(rule.source, "10.0.0.0/8");
    }

    #[test]
    fn parse_firewall_port_rejects_invalid_values() {
        assert!(parse_public_port("0/tcp").is_err());
        assert!(parse_public_port("65536/tcp").is_err());
        assert!(parse_public_port("80/icmp").is_err());
        assert!(parse_private_port("5432/tcp:not-a-cidr").is_err());
    }
}
