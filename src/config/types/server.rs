//! Server configuration types.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::address::NetLocation;
use crate::option_util::{NoneOrSome, OneOrSome};

use super::common::{default_reality_server_short_ids, default_reality_time_diff, default_true};
use super::dns::DnsConfig;
use super::rules::{ClientChainHop, RuleConfig};
use super::selection::ConfigSelection;
use super::transport::{BindLocation, ServerQuicConfig, TcpConfig, Transport};

pub fn direct_allow_rule() -> NoneOrSome<ConfigSelection<RuleConfig>> {
    NoneOrSome::One(ConfigSelection::Config(RuleConfig::default()))
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerConfig {
    #[serde(flatten)]
    pub bind_location: BindLocation,
    pub protocol: ServerProxyConfig,
    #[serde(
        alias = "transport",
        default,
        skip_serializing_if = "Transport::is_default"
    )]
    pub transport: Transport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_settings: Option<TcpConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_settings: Option<ServerQuicConfig>,
    #[serde(
        alias = "rule",
        default = "direct_allow_rule",
        skip_serializing_if = "NoneOrSome::is_unspecified"
    )]
    pub rules: NoneOrSome<ConfigSelection<RuleConfig>>,
    /// DNS configuration for this server (optional).
    /// Can reference a dns_group by name or specify inline DNS servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,
}

impl<'de> serde::de::Deserialize<'de> for ServerConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::Error;

        let value = serde_yaml::Value::deserialize(deserializer)?;
        let map = value
            .as_mapping()
            .ok_or_else(|| Error::custom("ServerConfig must be a YAML mapping"))?;

        // Valid fields: address/path (bind_location), protocol, transport, tcp_settings, quic_settings, rules/rule, dns
        const VALID_FIELDS: &[&str] = &[
            "address",
            "path", // BindLocation (flattened)
            "protocol",
            "transport",
            "tcp_settings",
            "quic_settings",
            "rules",
            "rule",
            "dns",
        ];

        // Check for unknown fields
        for key in map.keys() {
            if let Some(key_str) = key.as_str()
                && !VALID_FIELDS.contains(&key_str)
            {
                return Err(Error::custom(format!(
                    "unknown field `{}` in server config. Expected one of: {}",
                    key_str,
                    VALID_FIELDS.join(", ")
                )));
            }
        }

        // Parse bind_location (flattened - either address or path)
        let bind_location = if let Some(v) = map.get("address") {
            serde_yaml::from_value(v.clone())
                .map(BindLocation::Address)
                .map_err(|e| Error::custom(format!("invalid address: {e}")))?
        } else if let Some(v) = map.get("path") {
            serde_yaml::from_value(v.clone())
                .map(BindLocation::Path)
                .map_err(|e| Error::custom(format!("invalid path: {e}")))?
        } else {
            return Err(Error::custom(
                "server config must have either 'address' or 'path' field",
            ));
        };

        // Parse protocol (required)
        let protocol: ServerProxyConfig = map
            .get("protocol")
            .ok_or_else(|| Error::custom("missing 'protocol' field in server config"))
            .and_then(|v| {
                serde_yaml::from_value(v.clone())
                    .map_err(|e| Error::custom(format!("invalid protocol: {e}")))
            })?;

        // Parse transport (optional, default)
        let transport: Transport = map
            .get("transport")
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid transport: {e}")))?
            .unwrap_or_default();

        // Parse tcp_settings (optional, skip if null)
        let tcp_settings: Option<TcpConfig> = map
            .get("tcp_settings")
            .filter(|v| !v.is_null())
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid tcp_settings: {e}")))?;

        // Parse quic_settings (optional, skip if null)
        let quic_settings: Option<ServerQuicConfig> = map
            .get("quic_settings")
            .filter(|v| !v.is_null())
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid quic_settings: {e}")))?;

        // Parse rules (optional, with alias "rule", default to direct_allow_rule, skip if null)
        let rules: NoneOrSome<ConfigSelection<RuleConfig>> = map
            .get("rules")
            .or_else(|| map.get("rule"))
            .filter(|v| !v.is_null())
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid rules: {e}")))?
            .unwrap_or_else(direct_allow_rule);

        // Parse dns (optional)
        let dns: Option<DnsConfig> = map
            .get("dns")
            .filter(|v| !v.is_null())
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid dns: {e}")))?;

        Ok(ServerConfig {
            bind_location,
            protocol,
            transport,
            tcp_settings,
            quic_settings,
            rules,
            dns,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RealityServerConfig {
    /// X25519 private key (32 bytes, base64url encoded)
    pub private_key: String,

    /// List of valid short IDs (hex strings, 0-16 chars each)
    #[serde(alias = "short_id", default = "default_reality_server_short_ids")]
    pub short_ids: OneOrSome<String>,

    /// Fallback destination (e.g., "example.com:443")
    pub dest: NetLocation,

    /// Maximum timestamp difference in milliseconds (optional)
    #[serde(default = "default_reality_time_diff")]
    pub max_time_diff: Option<u64>,

    /// Minimum client version [major, minor, patch] (optional)
    #[serde(default)]
    pub min_client_version: Option<[u8; 3]>,

    /// Maximum client version [major, minor, patch] (optional)
    #[serde(default)]
    pub max_client_version: Option<[u8; 3]>,

    /// TLS 1.3 cipher suites to support (optional)
    /// Valid values: "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"
    /// If empty or not specified, the default set is used.
    #[serde(alias = "cipher_suite", default)]
    pub cipher_suites: NoneOrSome<crate::reality::CipherSuite>,

    /// Enable XTLS-Vision protocol for TLS-in-TLS optimization.
    /// When enabled, the inner protocol MUST be VLESS.
    /// Vision detects TLS-in-TLS scenarios and switches to Direct mode for zero-copy performance.
    /// Reality provides censorship resistance while Vision provides performance optimization.
    #[serde(default)]
    pub vision: bool,
    /// Inner protocol (VLESS, etc.)
    pub protocol: ServerProxyConfig,

    /// Client chain for connecting to dest server (for fallback connections).
    /// If not specified, connects directly to dest.
    #[serde(default)]
    pub dest_client_chain: NoneOrSome<ClientChainHop>,

    /// Override rules
    #[serde(alias = "override_rule", default)]
    pub override_rules: NoneOrSome<ConfigSelection<RuleConfig>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsServerConfig {
    pub cert: String,
    pub key: String,
    #[serde(alias = "alpn_protocol", default)]
    pub alpn_protocols: NoneOrSome<String>,

    // trusted CA certs that client certs must chain to.
    #[serde(alias = "client_ca_cert", default)]
    pub client_ca_certs: NoneOrSome<String>,

    // sha256 fingerprint of allowed client certificates
    #[serde(alias = "client_fingerprint", default)]
    pub client_fingerprints: NoneOrSome<String>,

    /// Enable XTLS-Vision protocol for TLS-in-TLS optimization.
    /// When enabled, the inner protocol MUST be VLESS.
    /// Requires TLS 1.3.
    #[serde(default)]
    pub vision: bool,
    pub protocol: ServerProxyConfig,

    #[serde(alias = "override_rule", default)]
    pub override_rules: NoneOrSome<ConfigSelection<RuleConfig>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerProxyConfig {
    Vless {
        user_id: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
        /// Fallback destination for failed authentication (optional)
        /// When set, failed auth attempts are proxied here instead of rejected
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fallback: Option<NetLocation>,
    },
    Tls {
        // sni_targets is the previous field name
        #[serde(default, alias = "sni_targets", alias = "targets")]
        tls_targets: HashMap<String, TlsServerConfig>,
        // default_target is the previous field name
        #[serde(
            default,
            alias = "default_target",
            skip_serializing_if = "Option::is_none"
        )]
        default_tls_target: Option<Box<TlsServerConfig>>,
        #[serde(default)]
        reality_targets: HashMap<String, RealityServerConfig>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        tls_buffer_size: Option<usize>,
    },
}

impl std::fmt::Display for ServerProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vless { .. } => write!(f, "Vless"),
            Self::Tls {
                tls_targets,
                default_tls_target,
                reality_targets,
                ..
            } => {
                let mut parts = vec![];

                if !tls_targets.is_empty() {
                    parts.push("TLS");
                }

                if !reality_targets.is_empty() {
                    parts.push("REALITY");
                }
                if tls_targets.values().any(|cfg| cfg.vision)
                    || default_tls_target.as_ref().is_some_and(|cfg| cfg.vision)
                    || reality_targets.values().any(|cfg| cfg.vision)
                {
                    parts.push("Vision");
                }

                write!(f, "{}", parts.join("+"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn create_test_server_config_vless() -> ServerConfig {
        ServerConfig {
            bind_location: BindLocation::Address(
                NetLocation::from_ip_addr(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 443)
                    .into(),
            ),
            protocol: ServerProxyConfig::Vless {
                user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                udp_enabled: true,
                fallback: None,
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: NoneOrSome::None,
            dns: None,
        }
    }

    fn create_test_server_config_tls() -> ServerConfig {
        let mut tls_targets = HashMap::new();
        tls_targets.insert(
            "example.com".to_string(),
            TlsServerConfig {
                cert: "example.crt".to_string(),
                key: "example.key".to_string(),
                alpn_protocols: NoneOrSome::Some(vec!["h2".to_string(), "http/1.1".to_string()]),
                client_ca_certs: NoneOrSome::One("ca.crt".to_string()),
                client_fingerprints: NoneOrSome::One("abc123".to_string()),
                vision: false,
                protocol: ServerProxyConfig::Vless {
                    user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                    udp_enabled: true,
                    fallback: None,
                },
                override_rules: NoneOrSome::None,
            },
        );

        ServerConfig {
            bind_location: BindLocation::Address(
                NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8443).into(),
            ),
            protocol: ServerProxyConfig::Tls {
                tls_targets,
                default_tls_target: Some(Box::new(TlsServerConfig {
                    cert: "default.crt".to_string(),
                    key: "default.key".to_string(),
                    alpn_protocols: NoneOrSome::None,
                    client_ca_certs: NoneOrSome::None,
                    client_fingerprints: NoneOrSome::None,
                    vision: false,
                    protocol: ServerProxyConfig::Vless {
                        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                        udp_enabled: true,
                        fallback: None,
                    },
                    override_rules: NoneOrSome::None,
                })),
                reality_targets: HashMap::new(),
                tls_buffer_size: Some(8192),
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: NoneOrSome::None,
            dns: None,
        }
    }

    #[test]
    fn test_server_config_vless() {
        let original = create_test_server_config_vless();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: ServerConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ServerProxyConfig::Vless { .. }
        ));
    }

    #[test]
    fn test_server_config_tls() {
        let original = create_test_server_config_tls();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: ServerConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ServerProxyConfig::Tls { .. }
        ));
    }

    #[test]
    fn test_rejects_invalid_upstream_field() {
        let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: vless
  user_id: "550e8400-e29b-41d4-a716-446655440000"
upstream:
  address: "127.0.0.1:443"
  protocol:
    type: vless
    user_id: "test-uuid"
"#;

        let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_err(),
            "Should reject config with invalid 'upstream' field"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("upstream"),
            "Error should mention 'upstream' as unknown field, got: {err}"
        );
    }

    #[test]
    fn test_rejects_typo_in_field_name() {
        let yaml = r#"
address: "127.0.0.1:8080"
protocl:
  type: vless
  user_id: "550e8400-e29b-41d4-a716-446655440000"
"#;

        let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "Should reject config with typo 'protocl'");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("protocl"),
            "Error should mention 'protocl' as unknown field, got: {err}"
        );
    }

    #[test]
    fn test_accepts_valid_server_config() {
        let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: vless
  user_id: "550e8400-e29b-41d4-a716-446655440000"
rules:
  - mask: 0.0.0.0/0
    action: allow
"#;

        let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_ok(),
            "Should accept valid server config: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_accepts_valid_server_config_with_all_fields() {
        let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: vless
  user_id: "550e8400-e29b-41d4-a716-446655440000"
transport: tcp
tcp_settings:
  no_delay: true
rules:
  - mask: 0.0.0.0/0
    action: allow
"#;

        let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_ok(),
            "Should accept valid server config with all fields: {:?}",
            result.err()
        );
    }
}
