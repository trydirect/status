use docker_compose_types as dctypes;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_valid::Validate;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct Port {
    #[validate(custom(|v| validate_non_empty(v)))]
    pub host_port: Option<String>,
    #[validate(pattern = r"^\d{2,6}+$")]
    pub container_port: String,
    #[validate(enumerate("tcp", "udp"))]
    pub protocol: Option<String>,
}

fn validate_non_empty(v: &Option<String>) -> Result<(), serde_valid::validation::Error> {
    if v.is_none() {
        return Ok(());
    }

    if let Some(value) = v {
        if value.is_empty() {
            return Ok(());
        }

        let re = Regex::new(r"^\d{2,6}$").unwrap();

        if !re.is_match(value.as_str()) {
            return Err(serde_valid::validation::Error::Custom(
                "Port is not valid.".to_owned(),
            ));
        }
    }

    Ok(())
}

// impl Default for Port{
//     fn default() -> Self {
//         Port {
//             target: 80,
//             host_ip: None,
//             published: None,
//             protocol: None,
//             mode: None,
//         }
//     }
// }

impl TryInto<dctypes::Port> for &Port {
    type Error = String;
    fn try_into(self) -> Result<dctypes::Port, Self::Error> {
        let normalized = normalize_port_mapping(self);

        let cp = normalized
            .container_port
            .parse::<u16>()
            .map_err(|_err| "Could not parse container port".to_string())?;

        let hp = match normalized.host_port {
            Some(hp) => {
                if hp.is_empty() {
                    None
                } else {
                    match hp.parse::<u16>() {
                        Ok(port) => Some(dctypes::PublishedPort::Single(port)),
                        Err(_) => {
                            tracing::debug!("Could not parse host port: {}", hp);
                            None
                        }
                    }
                }
            }
            _ => None,
        };

        tracing::debug!("Port conversion result: cp: {:?} hp: {:?}", cp, hp);

        Ok(dctypes::Port {
            target: cp,
            host_ip: normalized.host_ip,
            published: hp,
            protocol: self.protocol.clone(),
            mode: None,
        })
    }
}

struct NormalizedPortMapping {
    host_ip: Option<String>,
    host_port: Option<String>,
    container_port: String,
}

fn normalize_port_mapping(port: &Port) -> NormalizedPortMapping {
    let container_no_proto = port
        .container_port
        .split('/')
        .next()
        .unwrap_or(port.container_port.as_str());

    if let Some((host_part, container_port)) = container_no_proto.rsplit_once(':') {
        let (host_ip, host_port) = match host_part.rsplit_once(':') {
            Some((ip, published)) => (Some(ip.to_string()), Some(published.to_string())),
            None => match port.host_port.as_deref() {
                Some(host) if host.parse::<u16>().is_err() => {
                    (Some(host.to_string()), Some(host_part.to_string()))
                }
                _ => (None, Some(host_part.to_string())),
            },
        };

        return NormalizedPortMapping {
            host_ip,
            host_port,
            container_port: container_port.to_string(),
        };
    }

    NormalizedPortMapping {
        host_ip: None,
        host_port: port.host_port.clone(),
        container_port: container_no_proto.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_non_empty_none() {
        assert!(validate_non_empty(&None).is_ok());
    }

    #[test]
    fn test_validate_non_empty_empty_string() {
        assert!(validate_non_empty(&Some("".to_string())).is_ok());
    }

    #[test]
    fn test_validate_non_empty_valid_port() {
        assert!(validate_non_empty(&Some("8080".to_string())).is_ok());
        assert!(validate_non_empty(&Some("80".to_string())).is_ok());
        assert!(validate_non_empty(&Some("443".to_string())).is_ok());
    }

    #[test]
    fn test_validate_non_empty_invalid_port() {
        assert!(validate_non_empty(&Some("abc".to_string())).is_err());
        assert!(validate_non_empty(&Some("1".to_string())).is_err()); // too short (min 2 digits)
        assert!(validate_non_empty(&Some("1234567".to_string())).is_err()); // too long (max 6 digits)
    }

    #[test]
    fn test_port_try_into_valid() {
        let port = Port {
            host_port: Some("8080".to_string()),
            container_port: "80".to_string(),
            protocol: Some("tcp".to_string()),
        };
        let result: Result<dctypes::Port, String> = (&port).try_into();
        assert!(result.is_ok());
        let dc_port = result.unwrap();
        assert_eq!(dc_port.target, 80);
    }

    #[test]
    fn test_port_try_into_accepts_host_ip_mapping_in_container_port() {
        let port = Port {
            host_port: Some("127.0.0.1".to_string()),
            container_port: "1025:25".to_string(),
            protocol: Some("tcp".to_string()),
        };

        let result: Result<dctypes::Port, String> = (&port).try_into();

        assert!(result.is_ok());
        let dc_port = result.unwrap();
        assert_eq!(dc_port.target, 25);
        assert_eq!(dc_port.host_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(
            dc_port.published,
            Some(dctypes::PublishedPort::Single(1025))
        );
        assert_eq!(dc_port.protocol.as_deref(), Some("tcp"));
    }

    #[test]
    fn test_port_try_into_accepts_full_compose_mapping_in_container_port() {
        let port = Port {
            host_port: None,
            container_port: "127.0.0.1:1025:25/tcp".to_string(),
            protocol: None,
        };

        let result: Result<dctypes::Port, String> = (&port).try_into();

        assert!(result.is_ok());
        let dc_port = result.unwrap();
        assert_eq!(dc_port.target, 25);
        assert_eq!(dc_port.host_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(
            dc_port.published,
            Some(dctypes::PublishedPort::Single(1025))
        );
    }

    #[test]
    fn test_port_try_into_no_host_port() {
        let port = Port {
            host_port: None,
            container_port: "3000".to_string(),
            protocol: None,
        };
        let result: Result<dctypes::Port, String> = (&port).try_into();
        assert!(result.is_ok());
        let dc_port = result.unwrap();
        assert_eq!(dc_port.target, 3000);
        assert!(dc_port.published.is_none());
    }

    #[test]
    fn test_port_try_into_empty_host_port() {
        let port = Port {
            host_port: Some("".to_string()),
            container_port: "5432".to_string(),
            protocol: None,
        };
        let result: Result<dctypes::Port, String> = (&port).try_into();
        assert!(result.is_ok());
        let dc_port = result.unwrap();
        assert!(dc_port.published.is_none());
    }

    #[test]
    fn test_port_try_into_invalid_container_port() {
        let port = Port {
            host_port: None,
            container_port: "not_a_number".to_string(),
            protocol: None,
        };
        let result: Result<dctypes::Port, String> = (&port).try_into();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Could not parse container port"));
    }

    #[test]
    fn test_port_default() {
        let port = Port::default();
        assert!(port.host_port.is_none());
        assert_eq!(port.container_port, "");
        assert!(port.protocol.is_none());
    }

    #[test]
    fn test_port_serialization() {
        let port = Port {
            host_port: Some("8080".to_string()),
            container_port: "80".to_string(),
            protocol: Some("tcp".to_string()),
        };
        let json = serde_json::to_string(&port).unwrap();
        let deserialized: Port = serde_json::from_str(&json).unwrap();
        assert_eq!(port, deserialized);
    }
}
