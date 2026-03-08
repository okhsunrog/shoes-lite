//! Public API for floppa-vless.
//!
//! Provides `VlessTunnel`, `VlessConfig`, and `TunnelStats` for programmatic
//! use as a library dependency. This bypasses the YAML config engine entirely.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::address::{NetLocation, NetLocationMask};
use crate::client_proxy_chain::ClientChainGroup;
use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
use crate::config::selection::ConfigSelection;
use crate::config::{ClientChainHop, ClientConfig, ClientProxyConfig};
use crate::option_util::{NoneOrOne, NoneOrSome};
use crate::resolver::{NativeResolver, Resolver};
use crate::tcp::chain_builder::build_client_proxy_chain;
use crate::tun::TunServerConfig;

/// Configuration for a VLESS+REALITY VPN connection.
#[derive(Debug, Clone)]
pub struct VlessConfig {
    /// VLESS user ID (UUID v4).
    pub uuid: String,
    /// Server address as "host:port".
    pub server_addr: String,
    /// SNI hostname for REALITY handshake.
    pub server_name: String,
    /// REALITY public key (base64).
    pub reality_public_key: String,
    /// REALITY short ID (hex).
    pub reality_short_id: String,
    /// Flow control mode, e.g. "xtls-rprx-vision".
    pub flow: Option<String>,
    /// Client tunnel IP address, e.g. "10.0.0.2".
    pub address: Option<String>,
    /// Client tunnel netmask, e.g. "255.255.255.0".
    pub netmask: Option<String>,
    /// DNS server to use inside tunnel.
    pub dns: Option<String>,
    /// MTU for TUN device (default: platform-specific).
    pub mtu: Option<u16>,
    /// Allowed IPs for routing, e.g. "0.0.0.0/0".
    pub allowed_ips: Option<String>,
}

impl VlessConfig {
    /// Parse a standard VLESS URI into a VlessConfig.
    ///
    /// Format:
    /// ```text
    /// vless://UUID@HOST:PORT?encryption=none&flow=xtls-rprx-vision
    ///   &security=reality&sni=example.com&fp=chrome
    ///   &pbk=PUBLIC_KEY&sid=SHORT_ID&type=tcp#profile-name
    /// ```
    ///
    /// VPN-specific fields (`address`, `dns`, `mtu`, `allowed_ips`) are not
    /// part of the VLESS URI standard and will be `None`/default.
    pub fn from_uri(uri: &str) -> Result<Self, String> {
        let url = url::Url::parse(uri).map_err(|e| format!("Invalid URI: {e}"))?;

        if url.scheme() != "vless" {
            return Err(format!("Expected vless:// scheme, got {}://", url.scheme()));
        }

        let uuid = url.username().to_string();
        if uuid.is_empty() {
            return Err("Missing UUID in URI".to_string());
        }

        let host = url.host_str().ok_or("Missing host in URI")?.to_string();
        let port = url.port().unwrap_or(443);
        let server_addr = format!("{host}:{port}");

        let params: std::collections::HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        let security = params.get("security").map(|s| s.as_str()).unwrap_or("");
        if security != "reality" {
            return Err(format!(
                "Expected security=reality, got security={security}"
            ));
        }

        let server_name = params.get("sni").cloned().unwrap_or_default();
        if server_name.is_empty() {
            return Err("Missing sni parameter".to_string());
        }

        let reality_public_key = params
            .get("pbk")
            .cloned()
            .ok_or("Missing pbk (public key) parameter")?;

        let reality_short_id = params.get("sid").cloned().unwrap_or_default();

        let flow = params.get("flow").cloned();

        Ok(VlessConfig {
            uuid,
            server_addr,
            server_name,
            reality_public_key,
            reality_short_id,
            flow,
            address: None,
            netmask: None,
            dns: None,
            mtu: None,
            allowed_ips: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// Thread-safe traffic statistics (shared between tunnel and caller).
pub struct TunnelStats {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    connected_at: Instant,
    /// Milliseconds elapsed since `connected_at` when the last RX data arrived.
    last_rx_elapsed_ms: AtomicU64,
}

impl TunnelStats {
    pub fn new() -> Self {
        Self {
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            connected_at: Instant::now(),
            last_rx_elapsed_ms: AtomicU64::new(0),
        }
    }

    pub fn add_tx(&self, bytes: u64) {
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_rx(&self, bytes: u64) {
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
        if bytes > 0 {
            let elapsed_ms = self.connected_at.elapsed().as_millis() as u64;
            self.last_rx_elapsed_ms.store(elapsed_ms, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> TrafficStats {
        TrafficStats {
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            connected_at: self.connected_at,
            last_rx_elapsed_ms: self.last_rx_elapsed_ms.load(Ordering::Relaxed),
        }
    }
}

impl Default for TunnelStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Immutable snapshot of traffic statistics.
#[derive(Debug, Clone)]
pub struct TrafficStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub connected_at: Instant,
    last_rx_elapsed_ms: u64,
}

impl TrafficStats {
    pub fn duration(&self) -> Duration {
        self.connected_at.elapsed()
    }

    /// Time elapsed since the last packet was received.
    ///
    /// Returns `None` if no packet has been received yet.
    pub fn time_since_last_packet_received(&self) -> Option<Duration> {
        if self.last_rx_elapsed_ms == 0 {
            return None;
        }
        let last_rx = Duration::from_millis(self.last_rx_elapsed_ms);
        Some(self.connected_at.elapsed().saturating_sub(last_rx))
    }
}

impl VlessConfig {
    /// Verify VLESS+REALITY connectivity by making a test TCP connection
    /// through the proxy chain directly (no TUN needed).
    ///
    /// Proves: server reachable -> REALITY handshake -> UUID accepted -> proxy
    /// forwards traffic. Use this before or after tunnel creation to verify
    /// the config works.
    pub async fn check_connectivity(&self, timeout: Duration) -> Result<(), String> {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = Arc::new(build_vless_selector(self, resolver.clone())?);

        let target = NetLocation::from_str("1.1.1.1:443", None)
            .map_err(|e| format!("Invalid target: {e}"))?;
        let resolved: crate::address::ResolvedLocation = target.into();

        let decision = selector
            .judge(resolved, &resolver)
            .await
            .map_err(|e| format!("Selector error: {e}"))?;

        match decision {
            crate::client_proxy_selector::ConnectDecision::Allow {
                chain_group,
                remote_location,
            } => {
                tokio::time::timeout(timeout, chain_group.connect_tcp(remote_location, &resolver))
                    .await
                    .map_err(|_| "connectivity check timed out".to_string())?
                    .map_err(|e| format!("connectivity check failed: {e}"))?;
                Ok(())
            }
            crate::client_proxy_selector::ConnectDecision::Block => {
                Err("Connection blocked by selector".to_string())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Chain builder
// ---------------------------------------------------------------------------

/// Build a `ClientProxySelector` from a `VlessConfig`.
///
/// Creates a single catch-all rule that routes all traffic through one
/// VLESS+REALITY chain.
fn build_vless_selector(
    config: &VlessConfig,
    resolver: Arc<dyn Resolver>,
) -> Result<ClientProxySelector, String> {
    let server_location = NetLocation::from_str(&config.server_addr, None)
        .map_err(|e| format!("Invalid server_addr '{}': {e}", config.server_addr))?;

    let has_vision = config.flow.as_deref() == Some("xtls-rprx-vision");

    let client_config = ClientConfig {
        bind_interface: NoneOrOne::None,
        address: server_location,
        protocol: ClientProxyConfig::Reality {
            public_key: config.reality_public_key.clone(),
            short_id: config.reality_short_id.clone(),
            sni_hostname: Some(config.server_name.clone()),
            cipher_suites: NoneOrSome::default(),
            vision: has_vision,
            protocol: Box::new(ClientProxyConfig::Vless {
                user_id: config.uuid.clone(),
                udp_enabled: true,
            }),
        },
        ..Default::default()
    };

    let chain = build_client_proxy_chain(
        crate::option_util::OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
            client_config,
        ))),
        resolver,
    );

    let chain_group = ClientChainGroup::new(vec![chain]);

    let rule = ConnectRule::new(
        vec![NetLocationMask::ANY],
        ConnectAction::new_allow(None, chain_group),
    );

    Ok(ClientProxySelector::new(vec![rule]))
}

// ---------------------------------------------------------------------------
// VlessTunnel
// ---------------------------------------------------------------------------

/// A running VLESS+REALITY VPN tunnel.
pub struct VlessTunnel {
    shutdown_tx: Option<oneshot::Sender<()>>,
    task_handle: JoinHandle<()>,
    stats: Arc<TunnelStats>,
    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
}

impl VlessTunnel {
    /// Create a TUN device and start the VLESS+REALITY tunnel (Linux desktop).
    pub async fn new(config: &VlessConfig, interface_name: &str) -> Result<Self, String> {
        let mut tun_config = TunServerConfig::new().tun_name(interface_name.to_string());

        if let Some(ref addr_str) = config.address {
            let addr: IpAddr = addr_str
                .parse()
                .map_err(|e| format!("Invalid tunnel address '{addr_str}': {e}"))?;
            tun_config = tun_config.address(addr);
        }
        if let Some(ref mask_str) = config.netmask {
            let mask: IpAddr = mask_str
                .parse()
                .map_err(|e| format!("Invalid tunnel netmask '{mask_str}': {e}"))?;
            tun_config = tun_config.netmask(mask);
        }
        if let Some(mtu) = config.mtu {
            tun_config = tun_config.mtu(mtu);
        }

        Self::start(config, tun_config).await
    }

    /// Start tunnel using an existing TUN file descriptor (Android/iOS).
    pub async fn from_fd(config: &VlessConfig, tun_fd: i32) -> Result<Self, String> {
        let mut tun_config = TunServerConfig::new()
            .raw_fd(tun_fd)
            .close_fd_on_drop(false);

        if let Some(mtu) = config.mtu {
            tun_config = tun_config.mtu(mtu);
        }

        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            tun_config = tun_config.packet_information(true);
        }

        Self::start(config, tun_config).await
    }

    /// Start tunnel with a custom `TunServerConfig`.
    ///
    /// Use this when you need fine-grained control over TUN device creation,
    /// e.g., setting `manage_device(false)` for pre-created persistent devices.
    ///
    /// The TUN device is created eagerly before spawning the background task,
    /// so it is guaranteed to exist when this method returns. This allows the
    /// caller to configure routes/DNS on the interface immediately.
    pub async fn start(config: &VlessConfig, tun_config: TunServerConfig) -> Result<Self, String> {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = Arc::new(build_vless_selector(config, resolver.clone())?);
        let stats = Arc::new(TunnelStats::new());

        // Create TUN device eagerly so it exists before we return.
        let tun_device = tun_config
            .create_async_device()
            .map_err(|e| format!("Failed to create TUN device: {e}"))?;
        log::info!("Created async TUN device");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let selector_clone = selector.clone();
        let resolver_clone = resolver.clone();
        let stats_clone = stats.clone();
        let task_handle = tokio::spawn(async move {
            if let Err(e) = crate::tun::run_tun_server_with_device(
                tun_config,
                tun_device,
                selector_clone,
                resolver_clone,
                shutdown_rx,
                stats_clone,
            )
            .await
            {
                log::error!("TUN server error: {e}");
            }
        });

        Ok(Self {
            shutdown_tx: Some(shutdown_tx),
            task_handle,
            stats,
            selector,
            resolver,
        })
    }

    /// Get current traffic statistics (non-blocking).
    pub fn get_stats(&self) -> TrafficStats {
        self.stats.snapshot()
    }

    /// Get connection duration.
    pub fn connection_duration(&self) -> Duration {
        self.stats.snapshot().duration()
    }

    /// Time elapsed since the last packet was received.
    ///
    /// Returns `None` if no packet has been received yet.
    pub fn time_since_last_packet_received(&self) -> Option<Duration> {
        self.stats.snapshot().time_since_last_packet_received()
    }

    /// Ping the VLESS server through the tunnel's own proxy chain (bypasses TUN).
    ///
    /// Makes a test TCP connection to 1.1.1.1:443 using the same
    /// `ClientProxySelector` the running tunnel uses. On success, updates
    /// `last_packet_received` so callers see fresh activity.
    pub async fn ping(&self, timeout: Duration) -> Result<(), String> {
        let target = NetLocation::from_str("1.1.1.1:443", None)
            .map_err(|e| format!("Invalid target: {e}"))?;
        let resolved: crate::address::ResolvedLocation = target.into();

        let decision = self
            .selector
            .judge(resolved, &self.resolver)
            .await
            .map_err(|e| format!("Selector error: {e}"))?;

        match decision {
            crate::client_proxy_selector::ConnectDecision::Allow {
                chain_group,
                remote_location,
            } => {
                tokio::time::timeout(
                    timeout,
                    chain_group.connect_tcp(remote_location, &self.resolver),
                )
                .await
                .map_err(|_| "ping timed out".to_string())?
                .map_err(|e| format!("ping failed: {e}"))?;
                self.stats.add_rx(1);
                Ok(())
            }
            crate::client_proxy_selector::ConnectDecision::Block => {
                Err("Connection blocked by selector".to_string())
            }
        }
    }

    /// Stop the tunnel gracefully.
    pub async fn stop(mut self) -> Result<(), String> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        self.task_handle
            .await
            .map_err(|e| format!("Task join error: {e}"))
    }
}

/// Set a socket protection callback (required on Android to prevent routing loops).
///
/// On Android, outbound sockets to the VLESS server must be "protected" via
/// `VpnService.protect()` to avoid being routed back through the TUN device.
/// Call this before starting the tunnel.
pub fn set_socket_protector(protector: Arc<dyn crate::tun::SocketProtector>) {
    crate::tun::set_global_socket_protector(protector);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vless_uri_basic() {
        let uri = "vless://550e8400-e29b-41d4-a716-446655440000@example.com:443\
                    ?encryption=none&flow=xtls-rprx-vision\
                    &security=reality&sni=www.microsoft.com&fp=chrome\
                    &pbk=abc123publickey&sid=deadbeef&type=tcp#my-server";
        let config = VlessConfig::from_uri(uri).unwrap();
        assert_eq!(config.uuid, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(config.server_addr, "example.com:443");
        assert_eq!(config.server_name, "www.microsoft.com");
        assert_eq!(config.reality_public_key, "abc123publickey");
        assert_eq!(config.reality_short_id, "deadbeef");
        assert_eq!(config.flow.as_deref(), Some("xtls-rprx-vision"));
        assert!(config.address.is_none());
        assert!(config.mtu.is_none());
    }

    #[test]
    fn test_parse_vless_uri_default_port() {
        let uri = "vless://uuid@host.example.com\
                    ?security=reality&sni=sni.example.com&pbk=key123";
        let config = VlessConfig::from_uri(uri).unwrap();
        assert_eq!(config.server_addr, "host.example.com:443");
        assert!(config.flow.is_none());
        assert!(config.reality_short_id.is_empty());
    }

    #[test]
    fn test_parse_vless_uri_custom_port() {
        let uri = "vless://uuid@1.2.3.4:8443\
                    ?security=reality&sni=sni.example.com&pbk=key123";
        let config = VlessConfig::from_uri(uri).unwrap();
        assert_eq!(config.server_addr, "1.2.3.4:8443");
    }

    #[test]
    fn test_parse_vless_uri_wrong_scheme() {
        let uri = "vmess://uuid@host:443?security=reality&sni=a&pbk=b";
        let err = VlessConfig::from_uri(uri).unwrap_err();
        assert!(err.contains("vless://"));
    }

    #[test]
    fn test_parse_vless_uri_missing_uuid() {
        let uri = "vless://host:443?security=reality&sni=a&pbk=b";
        // url crate parses "host" as username when no @ present,
        // but with this format it should fail
        let result = VlessConfig::from_uri(uri);
        // The host:443 part gets parsed as host, no username
        assert!(result.is_err() || result.unwrap().uuid.is_empty());
    }

    #[test]
    fn test_parse_vless_uri_missing_sni() {
        let uri = "vless://uuid@host:443?security=reality&pbk=key";
        let err = VlessConfig::from_uri(uri).unwrap_err();
        assert!(err.contains("sni"));
    }

    #[test]
    fn test_parse_vless_uri_missing_public_key() {
        let uri = "vless://uuid@host:443?security=reality&sni=example.com";
        let err = VlessConfig::from_uri(uri).unwrap_err();
        assert!(err.contains("pbk"));
    }

    #[test]
    fn test_parse_vless_uri_wrong_security() {
        let uri = "vless://uuid@host:443?security=tls&sni=a&pbk=b";
        let err = VlessConfig::from_uri(uri).unwrap_err();
        assert!(err.contains("reality"));
    }

    #[test]
    fn test_tunnel_stats() {
        let stats = TunnelStats::new();
        stats.add_tx(100);
        stats.add_tx(200);
        stats.add_rx(50);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.tx_bytes, 300);
        assert_eq!(snapshot.rx_bytes, 50);
        assert!(snapshot.duration() < Duration::from_secs(1));
    }

    #[test]
    fn test_build_vless_selector() {
        // Use a valid 32-byte X25519 public key (base64url-no-pad encoded)
        let config = VlessConfig {
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            server_addr: "1.2.3.4:443".to_string(),
            server_name: "www.microsoft.com".to_string(),
            reality_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            reality_short_id: "deadbeef".to_string(),
            flow: Some("xtls-rprx-vision".to_string()),
            address: None,
            netmask: None,
            dns: None,
            mtu: None,
            allowed_ips: None,
        };
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = build_vless_selector(&config, resolver);
        assert!(
            selector.is_ok(),
            "Failed to build selector: {:?}",
            selector.err()
        );
    }

    // -----------------------------------------------------------------------
    // E2E tests (require Docker infrastructure)
    // Run: cd tests/docker && ./run-e2e.sh
    // Or manually: docker compose up -d && cargo test e2e -- --ignored
    // -----------------------------------------------------------------------

    // Pre-generated test-only keys (no security value)
    const E2E_SERVER_ADDR: &str = "127.0.0.1:10443";
    const E2E_SERVER_NAME: &str = "www.example.com";
    const E2E_PUBLIC_KEY: &str = "nvgtQmmD0yTsjpc-qgF8AGhF_OkKAj44uaaP-f5zFBo";
    const E2E_SHORT_ID: &str = "abcdef1234567890";
    // UUID with Vision flow configured in Xray
    const E2E_UUID_VISION: &str = "a4cbbde8-e6c2-44b6-8ba8-b68b8018f99c";
    // UUID without Vision flow configured in Xray
    const E2E_UUID_BASIC: &str = "1a4f9a9e-1561-47ba-a2be-149a85625763";
    const E2E_ECHO_HOST: &str = "127.0.0.1";
    const E2E_ECHO_PORT: u16 = 18080;

    fn e2e_config(uuid: &str, flow: Option<&str>) -> VlessConfig {
        VlessConfig {
            uuid: uuid.to_string(),
            server_addr: E2E_SERVER_ADDR.to_string(),
            server_name: E2E_SERVER_NAME.to_string(),
            reality_public_key: E2E_PUBLIC_KEY.to_string(),
            reality_short_id: E2E_SHORT_ID.to_string(),
            flow: flow.map(|s| s.to_string()),
            address: None,
            netmask: None,
            dns: None,
            mtu: None,
            allowed_ips: None,
        }
    }

    async fn connect_through_vless(
        config: &VlessConfig,
        target_host: &str,
        target_port: u16,
    ) -> std::io::Result<Box<dyn crate::async_stream::AsyncStream>> {
        let resolver: Arc<dyn crate::resolver::Resolver> = Arc::new(NativeResolver::new());
        let selector = Arc::new(
            build_vless_selector(config, resolver.clone())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
        );

        let target =
            NetLocation::from_str(&format!("{target_host}:{target_port}"), None).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid target: {e}"),
                )
            })?;
        let resolved: crate::address::ResolvedLocation = target.into();

        let decision = selector.judge(resolved, &resolver).await?;

        match decision {
            crate::client_proxy_selector::ConnectDecision::Allow {
                chain_group,
                remote_location,
            } => {
                let result = chain_group.connect_tcp(remote_location, &resolver).await?;
                Ok(result.client_stream)
            }
            crate::client_proxy_selector::ConnectDecision::Block => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Connection blocked by selector",
            )),
        }
    }

    #[tokio::test]
    #[ignore] // Requires Docker: cd tests/docker && ./run-e2e.sh
    async fn test_e2e_vless_reality_basic() {
        let config = e2e_config(E2E_UUID_BASIC, None);

        let mut stream = tokio::time::timeout(
            Duration::from_secs(30),
            connect_through_vless(&config, E2E_ECHO_HOST, E2E_ECHO_PORT),
        )
        .await
        .expect("Connection timed out")
        .expect("Failed to connect through VLESS+REALITY");

        // Send data and verify echo
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let test_data = b"Hello from shoes e2e test!";
        stream.write_all(test_data).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = vec![0u8; test_data.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, test_data);
    }

    #[tokio::test]
    #[ignore]
    async fn test_e2e_vless_reality_vision() {
        let config = e2e_config(E2E_UUID_VISION, Some("xtls-rprx-vision"));

        let mut stream = tokio::time::timeout(
            Duration::from_secs(30),
            connect_through_vless(&config, E2E_ECHO_HOST, E2E_ECHO_PORT),
        )
        .await
        .expect("Connection timed out")
        .expect("Failed to connect through VLESS+REALITY+Vision");

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let test_data = b"Hello from Vision e2e test!";
        stream.write_all(test_data).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = vec![0u8; test_data.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, test_data);
    }

    #[tokio::test]
    #[ignore]
    async fn test_e2e_vless_reality_large_payload() {
        let config = e2e_config(E2E_UUID_BASIC, None);

        let mut stream = tokio::time::timeout(
            Duration::from_secs(30),
            connect_through_vless(&config, E2E_ECHO_HOST, E2E_ECHO_PORT),
        )
        .await
        .expect("Connection timed out")
        .expect("Failed to connect");

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Send 1MB of data
        let test_data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        stream.write_all(&test_data).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = vec![0u8; test_data.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, test_data);
    }

    #[tokio::test]
    #[ignore]
    async fn test_e2e_vless_reality_multiple_exchanges() {
        let config = e2e_config(E2E_UUID_BASIC, None);

        let mut stream = tokio::time::timeout(
            Duration::from_secs(30),
            connect_through_vless(&config, E2E_ECHO_HOST, E2E_ECHO_PORT),
        )
        .await
        .expect("Connection timed out")
        .expect("Failed to connect");

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for i in 0..10 {
            let msg = format!("Message {i} from shoes e2e test");
            stream.write_all(msg.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();

            let mut buf = vec![0u8; msg.len()];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(String::from_utf8(buf).unwrap(), msg);
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_e2e_vless_reality_wrong_uuid() {
        let config = e2e_config("00000000-0000-4000-8000-000000000000", None);

        let result = tokio::time::timeout(
            Duration::from_secs(15),
            connect_through_vless(&config, E2E_ECHO_HOST, E2E_ECHO_PORT),
        )
        .await
        .expect("Timed out");

        // Connection with wrong UUID should fail (Xray rejects it)
        // It may fail at connect or when trying to use the stream
        if let Ok(mut stream) = result {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let test_data = b"this should not echo back";
            let _ = stream.write_all(test_data).await;
            let _ = stream.flush().await;

            let mut buf = vec![0u8; test_data.len()];
            let read_result =
                tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf)).await;

            // Should either timeout or get an error — not get valid echo
            match read_result {
                Ok(Ok(_)) => {
                    assert_ne!(&buf, test_data, "Wrong UUID should not produce valid echo");
                }
                _ => {} // Expected: error or timeout
            }
        }
        // If connect itself failed, that's also correct behavior
    }

    // -----------------------------------------------------------------------
    // E2E speed limiting tests (require Docker for dest + echo servers)
    // Run: cd tests/docker && ./run-e2e.sh
    // -----------------------------------------------------------------------

    /// Authenticator that applies a shared bandwidth limiter per user.
    #[derive(Debug)]
    struct TestSpeedLimitAuthenticator {
        user_id: [u8; 16],
        limiter: Option<crate::speed_limit::Limiter>,
    }

    impl crate::vless::VlessAuthenticator for TestSpeedLimitAuthenticator {
        fn authenticate(&self, uuid: &[u8; 16]) -> bool {
            use subtle::ConstantTimeEq;
            self.user_id.ct_eq(uuid.as_slice()).unwrap_u8() == 1
        }

        fn get_limiter(&self, _uuid: &[u8; 16]) -> Option<crate::speed_limit::Limiter> {
            self.limiter.clone()
        }
    }

    /// Start an in-process shoes-lite REALITY+Vision server.
    /// Uses Docker's nginx dest (port 19443) for REALITY handshake.
    /// Returns (server_port, public_key_b64, server_handle).
    async fn start_shoes_reality_server(
        uuid_str: &str,
        speed_limit: Option<f64>,
    ) -> (u16, String, tokio::task::JoinHandle<()>) {
        use crate::client_proxy_chain::ClientChainGroup;
        use crate::config::{ClientChainHop, ClientConfig};
        use crate::option_util::OneOrSome;
        use crate::reality::{
            RealityServerTarget, decode_private_key, decode_short_id, generate_keypair,
        };
        use crate::tcp::chain_builder::build_client_proxy_chain;
        use crate::tcp::tcp_server::process_stream;
        use crate::tls_server_handler::{
            InnerProtocol, TlsServerHandler, TlsServerTarget, VisionVlessConfig,
        };
        use rustc_hash::FxHashMap;

        let (priv_key_b64, pub_key_b64) = generate_keypair().unwrap();
        let private_key = decode_private_key(&priv_key_b64).unwrap();
        let short_id = decode_short_id(E2E_SHORT_ID).unwrap();

        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

        // "Direct connect" selector for the server to reach the echo server
        let direct_chain = build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                ClientConfig::default(),
            ))),
            resolver.clone(),
        );
        let chain_group = ClientChainGroup::new(vec![direct_chain]);
        let server_selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![NetLocationMask::ANY],
            ConnectAction::new_allow(None, chain_group),
        )]));

        // Direct chain for connecting to REALITY dest (nginx TLS)
        let dest_chain = build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                ClientConfig::default(),
            ))),
            resolver.clone(),
        );

        let user_uuid_bytes: [u8; 16] = crate::uuid_util::parse_uuid(uuid_str)
            .unwrap()
            .try_into()
            .unwrap();

        let limiter = speed_limit.map(crate::speed_limit::Limiter::new);
        let authenticator = Arc::new(TestSpeedLimitAuthenticator {
            user_id: user_uuid_bytes,
            limiter,
        });

        let target = RealityServerTarget {
            private_key,
            short_ids: vec![short_id],
            dest: NetLocation::from_str("localhost:19443", None).unwrap(),
            max_time_diff: Some(60000),
            min_client_version: None,
            max_client_version: None,
            cipher_suites: vec![],
            effective_selector: server_selector,
            inner_protocol: InnerProtocol::VisionVless(VisionVlessConfig {
                authenticator,
                udp_enabled: false,
                fallback: None,
            }),
            dest_client_chain: dest_chain,
        };

        let mut targets = FxHashMap::default();
        targets.insert(
            E2E_SERVER_NAME.to_string(),
            TlsServerTarget::Reality(target),
        );

        let handler: Arc<dyn crate::tcp::tcp_handler::TcpServerHandler> =
            Arc::new(TlsServerHandler::new(targets, None, None, resolver.clone()));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = listener.local_addr().unwrap().port();

        let server_handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let handler = handler.clone();
                        let resolver = resolver.clone();
                        tokio::spawn(async move {
                            let _ = process_stream(stream, handler, resolver).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        (server_port, pub_key_b64, server_handle)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore] // Requires Docker: cd tests/docker && ./run-e2e.sh
    async fn test_e2e_shoes_reality_server() {
        // Verify our in-process shoes-lite REALITY server works (no speed limit)
        let uuid = E2E_UUID_VISION;
        let (server_port, pub_key, server_handle) = start_shoes_reality_server(uuid, None).await;

        let config = VlessConfig {
            uuid: uuid.to_string(),
            server_addr: format!("127.0.0.1:{server_port}"),
            server_name: E2E_SERVER_NAME.to_string(),
            reality_public_key: pub_key,
            reality_short_id: E2E_SHORT_ID.to_string(),
            flow: Some("xtls-rprx-vision".to_string()),
            address: None,
            netmask: None,
            dns: None,
            mtu: None,
            allowed_ips: None,
        };

        let mut stream = tokio::time::timeout(
            Duration::from_secs(30),
            connect_through_vless(&config, E2E_ECHO_HOST, E2E_ECHO_PORT),
        )
        .await
        .expect("Connection timed out")
        .expect("Failed to connect through shoes-lite REALITY server");

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let test_data = b"Hello from shoes-lite REALITY server test!";
        stream.write_all(test_data).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = vec![0u8; test_data.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, test_data);

        server_handle.abort();
    }

    /// Helper: run a speed-limited echo test.
    /// `speed_bps` — limiter rate in bytes/sec.
    /// `data_size` — payload size in bytes (sent and echoed back).
    async fn run_speed_limit_test(speed_bps: f64, data_size: usize) {
        let uuid = E2E_UUID_VISION;
        let (server_port, pub_key, server_handle) =
            start_shoes_reality_server(uuid, Some(speed_bps)).await;

        let config = VlessConfig {
            uuid: uuid.to_string(),
            server_addr: format!("127.0.0.1:{server_port}"),
            server_name: E2E_SERVER_NAME.to_string(),
            reality_public_key: pub_key,
            reality_short_id: E2E_SHORT_ID.to_string(),
            flow: Some("xtls-rprx-vision".to_string()),
            address: None,
            netmask: None,
            dns: None,
            mtu: None,
            allowed_ips: None,
        };

        let mut stream = tokio::time::timeout(
            Duration::from_secs(30),
            connect_through_vless(&config, E2E_ECHO_HOST, E2E_ECHO_PORT),
        )
        .await
        .expect("Connection timed out")
        .expect("Failed to connect through speed-limited REALITY server");

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let test_data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();
        let start = std::time::Instant::now();

        stream.write_all(&test_data).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = vec![0u8; data_size];
        stream.read_exact(&mut buf).await.unwrap();

        let elapsed = start.elapsed();
        assert_eq!(buf, test_data, "Data integrity check failed");

        // Total bytes through limiter = data_size * 2 (send + receive).
        // Expected minimum time ≈ total / speed_bps. Use 0.5x for tolerance.
        let expected_secs = (data_size as f64 * 2.0) / speed_bps;
        let min_secs = expected_secs * 0.5;
        assert!(
            elapsed.as_secs_f64() >= min_secs,
            "Transfer too fast ({elapsed:?}), expected >= {min_secs:.1}s at {:.0} B/s with {data_size} bytes",
            speed_bps,
        );
        assert!(
            elapsed <= Duration::from_secs(30),
            "Transfer too slow ({elapsed:?}), possible deadlock",
        );

        eprintln!(
            "Speed limit test: {:.1} Mbps, {} KB payload, took {:.2}s (expected ~{:.2}s)",
            speed_bps * 8.0 / 1_000_000.0,
            data_size / 1024,
            elapsed.as_secs_f64(),
            expected_secs,
        );

        server_handle.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore] // Requires Docker: cd tests/docker && ./run-e2e.sh
    async fn test_e2e_speed_limit_32kbps() {
        // 32 KB/s ≈ 0.25 Mbps, 64 KB payload
        run_speed_limit_test(32_768.0, 65_536).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore] // Requires Docker: cd tests/docker && ./run-e2e.sh
    async fn test_e2e_speed_limit_10mbps() {
        // 10 Mbps = 1.25 MB/s, 2 MB payload
        run_speed_limit_test(1_250_000.0, 2 * 1024 * 1024).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore] // Requires Docker: cd tests/docker && ./run-e2e.sh
    async fn test_e2e_speed_limit_20mbps() {
        // 20 Mbps = 2.5 MB/s, 4 MB payload
        run_speed_limit_test(2_500_000.0, 4 * 1024 * 1024).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore] // Requires Docker: cd tests/docker && ./run-e2e.sh
    async fn test_e2e_speed_limit_50mbps() {
        // 50 Mbps = 6.25 MB/s, 10 MB payload
        run_speed_limit_test(6_250_000.0, 10 * 1024 * 1024).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore] // Requires Docker: cd tests/docker && ./run-e2e.sh
    async fn test_e2e_speed_limit_100mbps() {
        // 100 Mbps = 12.5 MB/s, 20 MB payload
        run_speed_limit_test(12_500_000.0, 20 * 1024 * 1024).await;
    }
}
