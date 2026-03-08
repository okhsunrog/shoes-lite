//! TUN device support for shoes.
//!
//! This module provides VPN functionality by accepting IP packets from a TUN
//! device and routing TCP/UDP traffic through configured proxy chains.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │   TUN Device    │ ←→  │  shoes/smoltcp  │ ←→  │  Proxy Chain    │
//! │ (IP packets)    │     │ (our TCP stack) │     │ (VLESS, etc.)   │
//! └─────────────────┘     └─────────────────┘     └─────────────────┘
//! ```
//!
//! The smoltcp stack runs in a tokio task, using `tun::AsyncDevice` for
//! cross-platform async packet I/O.
//!
//! # Platform Support
//!
//! - **Linux**: Creates TUN device with specified name/address. Requires root
//!   privileges or `CAP_NET_ADMIN` capability.
//!
//! - **Windows**: Creates TUN device via Wintun driver. Requires `wintun.dll`
//!   in the application directory or PATH.
//!
//! - **Android**: Accepts raw FD from `VpnService.Builder.establish()`. The
//!   VPN configuration (routes, DNS, etc.) is handled by the Android VpnService.
//!   You must pass the FD via `TunServerConfig::raw_fd()`.
//!
//! - **iOS/macOS**: Accepts raw FD from `NEPacketTunnelProvider.packetFlow`.
//!   Use `TunServerConfig::packet_information(true)` if using the socket FD
//!   directly, or `false` if using the readPackets/writePackets API.

mod tcp_conn;
mod tcp_stack;
mod tun_server;
mod udp_handler;
mod udp_manager;

mod platform;
pub use platform::{SocketProtector, protect_socket, set_global_socket_protector};

pub use tun_server::TunServerConfig;

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use log::{debug, info, warn};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::address::{Address, NetLocation};
use crate::api::TunnelStats;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::TunConfig;
use crate::config::selection::ConfigSelection;
use crate::resolver::{NativeResolver, Resolver};
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;

use tcp_stack::TcpStack;
use udp_manager::TunUdpManager;

/// Wrapper that intercepts reads/writes to update traffic statistics per chunk.
///
/// Reads from the inner stream count as RX (data from remote), writes count as TX.
struct StatsStream<S> {
    inner: S,
    stats: Arc<TunnelStats>,
}

impl<S> StatsStream<S> {
    fn new(inner: S, stats: Arc<TunnelStats>) -> Self {
        Self { inner, stats }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for StatsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let bytes_read = buf.filled().len() - before;
            if bytes_read > 0 {
                this.stats.add_rx(bytes_read as u64);
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StatsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            if *n > 0 {
                this.stats.add_tx(*n as u64);
            }
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

type PacketBuffer = Vec<u8>;

/// Run the TUN server with the given configuration.
///
/// This function:
/// 1. Creates an async TUN device
/// 2. Sets up the smoltcp-based TCP/IP stack in a tokio task
/// 3. Handles TCP connections through the proxy chain
/// 4. Handles UDP packets through tokio
pub async fn run_tun_server(
    config: TunServerConfig,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    mut shutdown_rx: oneshot::Receiver<()>,
    stats: Arc<TunnelStats>,
) -> std::io::Result<()> {
    info!(
        "Starting TUN server: mtu={}, tcp={}, udp={}, icmp={}",
        config.mtu, config.tcp_enabled, config.udp_enabled, config.icmp_enabled
    );

    let mtu = config.mtu as usize;
    let tun_device = config.create_async_device()?;
    info!("Created async TUN device");

    let mut tcp_stack = TcpStack::new();

    // Get UDP receiver (stack filters UDP and sends here)
    let udp_from_stack_rx = tcp_stack.take_udp_rx().expect("udp_rx already taken");

    // Channel for sending UDP responses back (stack will write to TUN)
    let (udp_to_stack_tx, udp_to_stack_rx) = mpsc::unbounded_channel::<PacketBuffer>();

    // Get TCP connection receiver
    let mut tcp_conn_rx = tcp_stack
        .take_new_conn_rx()
        .expect("new_conn_rx already taken");

    // Spawn the smoltcp stack task
    let stack_task: JoinHandle<()> = tokio::spawn(async move {
        tcp_stack.run(tun_device, mtu, udp_to_stack_rx).await;
    });

    let tcp_task: Option<JoinHandle<()>> = if config.tcp_enabled {
        let proxy_selector = proxy_selector.clone();
        let resolver = resolver.clone();
        let stats = stats.clone();

        Some(tokio::spawn(async move {
            info!("Starting TCP connection handler");

            while let Some(new_conn) = tcp_conn_rx.recv().await {
                let proxy_selector = proxy_selector.clone();
                let resolver = resolver.clone();
                let stats = stats.clone();

                tokio::spawn(async move {
                    let remote_addr = new_conn.remote_addr;
                    let target = socket_addr_to_net_location(remote_addr);

                    debug!("Handling TCP connection to {:?}", target);

                    if let Err(e) = handle_tcp_connection(
                        new_conn.connection,
                        target,
                        proxy_selector,
                        resolver,
                        stats,
                    )
                    .await
                    {
                        debug!("TCP connection to {} failed: {}", remote_addr, e);
                    }
                });
            }

            debug!("TCP connection handler ended");
        }))
    } else {
        None
    };

    let udp_task = if config.udp_enabled {
        let proxy_selector = proxy_selector.clone();
        let resolver = resolver.clone();
        let stats = stats.clone();

        Some(tokio::spawn(async move {
            handle_udp_packets(
                udp_from_stack_rx,
                udp_to_stack_tx,
                proxy_selector,
                resolver,
                stats,
            )
            .await;
        }))
    } else {
        None
    };

    info!("TUN server started successfully");

    // Wait for shutdown signal or stack task exit
    tokio::select! {
        _ = &mut shutdown_rx => {
            info!("TUN server shutdown requested");
        }
        _ = stack_task => {
            warn!("Stack task ended unexpectedly");
        }
    }

    if let Some(t) = tcp_task {
        t.abort();
    }
    if let Some(t) = udp_task {
        t.abort();
    }

    info!("TUN server stopped");
    Ok(())
}

/// Convert a SocketAddr to a NetLocation.
fn socket_addr_to_net_location(addr: SocketAddr) -> NetLocation {
    let address = match addr.ip() {
        std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
        std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
    };
    NetLocation::new(address, addr.port())
}

/// Handle a TCP connection by forwarding it through the proxy chain.
async fn handle_tcp_connection(
    mut connection: tcp_conn::TcpConnection,
    target: NetLocation,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    stats: Arc<TunnelStats>,
) -> std::io::Result<()> {
    let decision = proxy_selector.judge(target.into(), &resolver).await?;

    match decision {
        crate::client_proxy_selector::ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            debug!(
                "TCP: connecting to {} via chain",
                remote_location.location()
            );

            match chain_group
                .connect_tcp(remote_location.clone(), &resolver)
                .await
            {
                Ok(setup_result) => {
                    debug!(
                        "TCP: connected to {}, starting bidirectional copy",
                        remote_location.location()
                    );

                    let mut remote = StatsStream::new(setup_result.client_stream, stats);
                    let result = tokio::io::copy_bidirectional(&mut connection, &mut remote).await;

                    match result {
                        Ok((client_to_remote, remote_to_client)) => {
                            debug!(
                                "TCP connection to {} completed: {} bytes sent, {} bytes received",
                                remote_location.location(),
                                client_to_remote,
                                remote_to_client
                            );
                        }
                        Err(e) => {
                            debug!(
                                "TCP connection to {} error: {}",
                                remote_location.location(),
                                e
                            );
                        }
                    }

                    Ok(())
                }
                Err(e) => {
                    warn!("Failed to connect to {}: {}", remote_location.location(), e);
                    Err(e)
                }
            }
        }
        crate::client_proxy_selector::ConnectDecision::Block => {
            debug!("TCP connection blocked by rules");
            Ok(())
        }
    }
}

/// Handle UDP packets from the stack.
async fn handle_udp_packets(
    from_stack_rx: mpsc::UnboundedReceiver<PacketBuffer>,
    to_stack_tx: mpsc::UnboundedSender<PacketBuffer>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    stats: Arc<TunnelStats>,
) {
    info!("Starting UDP handler (session-based)");

    let udp_handler = udp_handler::UdpHandler::new(from_stack_rx, to_stack_tx);
    let (reader, writer) = udp_handler.split();

    let manager = TunUdpManager::new(reader, writer, proxy_selector, resolver, stats);

    if let Err(e) = manager.run().await {
        warn!("UDP handler error: {}", e);
    }

    info!("UDP handler stopped");
}

/// Start TUN server based on the provided configuration.
pub async fn start_tun_server(
    config: TunConfig,
    _resolver: std::sync::Arc<dyn crate::resolver::Resolver>,
) -> std::io::Result<JoinHandle<()>> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let handle = tokio::spawn(async move {
        let _keep_alive = shutdown_tx;
        if let Err(e) = run_tun_from_config(config, shutdown_rx, true).await {
            warn!("TUN server error: {}", e);
        }
    });

    Ok(handle)
}

/// Run TUN server from config with external shutdown control.
pub async fn run_tun_from_config(
    config: TunConfig,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    close_fd_on_drop: bool,
) -> std::io::Result<()> {
    let mut tun_server_config = TunServerConfig::new()
        .mtu(config.mtu)
        .tcp_enabled(config.tcp_enabled)
        .udp_enabled(config.udp_enabled)
        .icmp_enabled(config.icmp_enabled)
        .close_fd_on_drop(close_fd_on_drop);

    if let Some(ref name) = config.device_name {
        tun_server_config = tun_server_config.tun_name(name.clone());
        println!("Starting TUN server on device {}", name);
    }
    if let Some(fd) = config.device_fd {
        tun_server_config = tun_server_config.raw_fd(fd);
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            tun_server_config = tun_server_config.packet_information(true);
        }
        println!("Starting TUN server from device FD {}", fd);
    }
    if let Some(addr) = config.address {
        tun_server_config = tun_server_config.address(addr);
    }
    if let Some(mask) = config.netmask {
        tun_server_config = tun_server_config.netmask(mask);
    }
    if let Some(dest) = config.destination {
        tun_server_config = tun_server_config.destination(dest);
    }

    let rules = config.rules.map(ConfigSelection::unwrap_config).into_vec();
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()));

    run_tun_server(
        tun_server_config,
        client_proxy_selector,
        resolver,
        shutdown_rx,
        Arc::new(TunnelStats::new()),
    )
    .await
}
