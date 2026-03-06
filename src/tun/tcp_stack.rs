//! Async TCP Stack Manager for smoltcp integration.
//!
//! This module manages the smoltcp TCP/IP stack in an async tokio task,
//! using `tun::AsyncDevice` for cross-platform packet I/O.

use std::{
    collections::HashMap,
    mem,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::BytesMut;

use log::{debug, error, info, trace, warn};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{
        CongestionControl, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
    },
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address,
        Ipv6Packet, TcpPacket,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};
use tun::AsyncDevice;

use super::tcp_conn::{TcpConnection, TcpConnectionControl, TcpSocketState};

pub type PacketBuffer = Vec<u8>;

/// Maximum number of buffers cached globally.
/// Each buffer has capacity ~65536, so 64 * 65536 = 4MB max.
const BUFFER_POOL_MAX_SIZE: usize = 64;

static BUFFER_POOL: LazyLock<Mutex<Vec<BytesMut>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Pooled buffer that returns to pool on drop instead of deallocating.
pub struct PooledBuffer {
    buffer: BytesMut,
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Ok(mut pool) = BUFFER_POOL.lock()
            && pool.len() < BUFFER_POOL_MAX_SIZE
        {
            let empty = BytesMut::new();
            let mut buffer = mem::replace(&mut self.buffer, empty);
            buffer.clear();
            pool.push(buffer);
        }
    }
}

impl PooledBuffer {
    /// Get a buffer from the pool or create a new one.
    pub fn with_capacity(cap: usize) -> Self {
        if let Ok(mut pool) = BUFFER_POOL.lock()
            && let Some(mut buffer) = pool.pop()
        {
            buffer.reserve(cap);
            return Self { buffer };
        }
        Self {
            buffer: BytesMut::with_capacity(cap),
        }
    }
}

impl Deref for PooledBuffer {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

/// Tracks socket info including addresses for proper cleanup.
struct SocketInfo {
    control: Arc<TcpConnectionControl>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
}

/// Information about a new TCP connection from the stack.
pub struct NewTcpConnection {
    pub connection: TcpConnection,
    pub remote_addr: SocketAddr,
}

// Buffer sizes matched to netstack-smoltcp: 0x3FFF * 20 = 327,660 bytes (~320KB)
const TCP_SEND_BUFFER_SIZE: usize = 0x3FFF * 20; // ~320KB for high throughput
const TCP_RECV_BUFFER_SIZE: usize = 0x3FFF * 20; // ~320KB
const MAX_CONCURRENT_CONNECTIONS: usize = 1024; // Limit concurrent connections like gvisor

/// Queue-based smoltcp device.
///
/// Packets are enqueued from TUN reads and dequeued by smoltcp during poll.
/// Outgoing packets from smoltcp are queued for async TUN writes.
struct QueueDevice {
    rx_queue: std::collections::VecDeque<PooledBuffer>,
    tx_queue: Vec<Vec<u8>>,
    mtu: usize,
}

impl QueueDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx_queue: std::collections::VecDeque::new(),
            tx_queue: Vec::new(),
            mtu,
        }
    }

    /// Enqueue a received packet for smoltcp processing.
    fn enqueue_rx(&mut self, pkt: PooledBuffer) {
        self.rx_queue.push_back(pkt);
    }

    /// Take all outgoing packets (for async write to TUN).
    fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        mem::take(&mut self.tx_queue)
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = QueueRxToken;
    type TxToken<'a> = QueueTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(buffer) = self.rx_queue.pop_front() {
            let rx = QueueRxToken { buffer };
            let tx = QueueTxToken {
                tx_queue: &mut self.tx_queue,
            };
            Some((rx, tx))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(QueueTxToken {
            tx_queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum.ipv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.tcp = smoltcp::phy::Checksum::Tx;
        caps.checksum.udp = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv6 = smoltcp::phy::Checksum::Tx;
        caps
    }
}

struct QueueRxToken {
    buffer: PooledBuffer,
}

impl RxToken for QueueRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
        // buffer is returned to pool when dropped
    }
}

struct QueueTxToken<'a> {
    tx_queue: &'a mut Vec<Vec<u8>>,
}

impl TxToken for QueueTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.tx_queue.push(buffer);
        result
    }
}

/// Async TCP stack.
///
/// Manages the smoltcp interface with async TUN device I/O.
pub struct TcpStack {
    /// Receiver for UDP packets (filtered from TUN by the stack)
    udp_rx: Option<mpsc::UnboundedReceiver<PacketBuffer>>,
    /// Sender for new TCP connections
    new_conn_tx: mpsc::UnboundedSender<NewTcpConnection>,
    /// Receiver for new TCP connections (given to mod.rs)
    new_conn_rx: Option<mpsc::UnboundedReceiver<NewTcpConnection>>,
    /// Sender for UDP packets from TUN
    udp_tx: mpsc::UnboundedSender<PacketBuffer>,
    /// Notify for socket data ready
    notify: Arc<Notify>,
    /// Running flag
    running: Arc<AtomicBool>,
}

impl TcpStack {
    /// Create a new async TCP stack.
    pub fn new() -> Self {
        let (udp_tx, udp_rx) = mpsc::unbounded_channel();
        let (new_conn_tx, new_conn_rx) = mpsc::unbounded_channel();
        let notify = Arc::new(Notify::new());
        let running = Arc::new(AtomicBool::new(true));

        Self {
            udp_rx: Some(udp_rx),
            new_conn_tx,
            new_conn_rx: Some(new_conn_rx),
            udp_tx,
            notify,
            running,
        }
    }

    /// Take the receiver for UDP packets (filtered from TUN by the stack).
    pub fn take_udp_rx(&mut self) -> Option<mpsc::UnboundedReceiver<PacketBuffer>> {
        self.udp_rx.take()
    }

    /// Take the receiver for new TCP connections.
    pub fn take_new_conn_rx(&mut self) -> Option<mpsc::UnboundedReceiver<NewTcpConnection>> {
        self.new_conn_rx.take()
    }

    /// Run the async smoltcp stack.
    ///
    /// This is the main loop that reads packets from the TUN device,
    /// processes them through smoltcp, and writes outgoing packets back.
    pub async fn run(
        &self,
        tun_device: AsyncDevice,
        mtu: usize,
        mut udp_response_rx: mpsc::UnboundedReceiver<PacketBuffer>,
    ) {
        let (mut tun_writer, mut tun_reader) = tun_device
            .split()
            .map_err(|e| warn!("Failed to split TUN device: {}", e))
            .expect("Failed to split TUN device");
        let mut device = QueueDevice::new(mtu);

        let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random();

        let mut iface = Interface::new(iface_config, &mut device, SmolInstant::now());

        iface.update_ip_addrs(|addrs| {
            if let Err(e) = addrs.push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0)) {
                warn!("Failed to add IPv4 address: {:?}", e);
            }
            if let Err(e) = addrs.push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0)) {
                warn!("Failed to add IPv6 address: {:?}", e);
            }
        });

        if let Err(e) = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
        {
            warn!("Failed to add IPv4 route: {:?}", e);
        }
        if let Err(e) = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
        {
            warn!("Failed to add IPv6 route: {:?}", e);
        }

        iface.set_any_ip(true);

        let mut socket_set = SocketSet::new(vec![]);
        let mut sockets: HashMap<SocketHandle, SocketInfo> = HashMap::new();
        let mut active_connections: std::collections::HashSet<(SocketAddr, SocketAddr)> =
            std::collections::HashSet::new();

        let mut poll_count: u64 = 0;
        let mut last_log_time = std::time::Instant::now();

        let mut read_buf = vec![0u8; mtu + 4];

        info!("smoltcp async stack started, entering main loop");

        while self.running.load(Ordering::Relaxed) {
            // Calculate poll delay from smoltcp (capped at 10ms for responsiveness)
            let poll_delay = {
                let now = SmolInstant::now();
                let delay = iface.poll_delay(now, &socket_set);
                match delay {
                    Some(d) => Duration::from_millis(d.total_millis().min(10)),
                    None => Duration::from_millis(10),
                }
            };

            tokio::select! {
                // Read packet from TUN device
                result = tun_reader.read(&mut read_buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            let mut pkt = PooledBuffer::with_capacity(n);
                            pkt.extend_from_slice(&read_buf[..n]);

                            if !should_filter_packet(&pkt) {
                                self.process_incoming_packet(
                                    pkt,
                                    &mut device,
                                    &mut iface,
                                    &mut socket_set,
                                    &mut sockets,
                                    &mut active_connections,
                                );
                            }
                        }
                        Ok(_) => {
                            // EOF
                            error!("TUN device closed (EOF)");
                            break;
                        }
                        Err(e) => {
                            error!("TUN device read error: {}", e);
                            break;
                        }
                    }
                }

                // Write UDP response back to TUN
                Some(pkt) = udp_response_rx.recv() => {
                    if let Err(e) = tun_writer.write_all(&pkt).await {
                        warn!("Failed to write UDP response to TUN: {}", e);
                    }
                }

                // Socket data ready (TcpConnection wrote data or closed)
                _ = self.notify.notified() => {
                    // Just need to poll smoltcp below
                }

                // Periodic poll for retransmissions/keepalives
                _ = tokio::time::sleep(poll_delay) => {
                    // Just need to poll smoltcp below
                }
            }

            // Poll smoltcp and manage sockets
            let now = SmolInstant::now();
            iface.poll(now, &mut device, &mut socket_set);

            self.manage_sockets(&mut socket_set, &mut sockets, &mut active_connections);

            // Poll again after data transfer (critical for performance)
            let after_transfer = SmolInstant::now();
            iface.poll(after_transfer, &mut device, &mut socket_set);

            // Flush TX queue to TUN
            for pkt in device.drain_tx() {
                if let Err(e) = tun_writer.write_all(&pkt).await {
                    warn!("Failed to write to TUN: {}", e);
                }
            }

            poll_count += 1;
            if last_log_time.elapsed() >= Duration::from_secs(30) {
                debug!(
                    "smoltcp async stack: polls={}, active_sockets={}",
                    poll_count,
                    sockets.len()
                );
                last_log_time = std::time::Instant::now();
            }
        }

        self.running.store(false, Ordering::Relaxed);
        info!("smoltcp async stack stopped");
    }

    /// Process an incoming packet: classify and route to smoltcp or UDP handler.
    fn process_incoming_packet(
        &self,
        pkt: PooledBuffer,
        device: &mut QueueDevice,
        iface: &mut Interface,
        socket_set: &mut SocketSet<'static>,
        sockets: &mut HashMap<SocketHandle, SocketInfo>,
        active_connections: &mut std::collections::HashSet<(SocketAddr, SocketAddr)>,
    ) {
        if let Some(protocol) = get_ip_protocol(&pkt) {
            trace!(
                "Received packet: protocol={:?}, len={}",
                protocol,
                pkt.len()
            );
            match protocol {
                IpProtocol::Tcp => {
                    if let Some((src_addr, dst_addr, is_syn)) = extract_tcp_info(&pkt) {
                        trace!("TCP packet: {} -> {}, SYN={}", src_addr, dst_addr, is_syn);
                        if is_syn && !active_connections.contains(&(src_addr, dst_addr)) {
                            if sockets.len() >= MAX_CONCURRENT_CONNECTIONS {
                                warn!(
                                    "Connection limit reached ({}), dropping SYN from {}",
                                    MAX_CONCURRENT_CONNECTIONS, src_addr
                                );
                                return;
                            }

                            info!("New TCP SYN: {} -> {}", src_addr, dst_addr);

                            if let Some((handle, control)) =
                                create_tcp_connection(src_addr, dst_addr, socket_set)
                            {
                                let connection =
                                    TcpConnection::new(control.clone(), self.notify.clone());
                                sockets.insert(
                                    handle,
                                    SocketInfo {
                                        control,
                                        src_addr,
                                        dst_addr,
                                    },
                                );
                                active_connections.insert((src_addr, dst_addr));

                                let _ = self.new_conn_tx.send(NewTcpConnection {
                                    connection,
                                    remote_addr: dst_addr,
                                });
                            }
                        }
                    } else {
                        warn!("Failed to parse TCP packet, len={}", pkt.len());
                    }

                    // Feed to smoltcp for processing
                    device.enqueue_rx(pkt);
                    let now = SmolInstant::now();
                    iface.poll(now, device, socket_set);
                }
                IpProtocol::Icmp | IpProtocol::Icmpv6 => {
                    device.enqueue_rx(pkt);
                    let now = SmolInstant::now();
                    iface.poll(now, device, socket_set);
                }
                IpProtocol::Udp => {
                    let _ = self.udp_tx.send(pkt.to_vec());
                }
                _ => {
                    trace!("ignoring packet with protocol {:?}", protocol);
                }
            }
        }
    }

    /// Manage socket state: transfer data, detect close, clean up.
    fn manage_sockets(
        &self,
        socket_set: &mut SocketSet<'static>,
        sockets: &mut HashMap<SocketHandle, SocketInfo>,
        active_connections: &mut std::collections::HashSet<(SocketAddr, SocketAddr)>,
    ) {
        let mut sockets_to_remove = Vec::new();

        for (handle, socket_info) in sockets.iter() {
            let handle = *handle;
            let control = &socket_info.control;
            let socket = socket_set.get_mut::<TcpSocket>(handle);

            // Remove socket only when smoltcp reports Closed state
            if socket.state() == TcpState::Closed {
                sockets_to_remove.push(handle);
                control.set_closed();
                trace!("socket {:?} closed", handle);
                continue;
            }

            // Handle SHUT_WR: Close -> Closing transition
            if control.send_state() == TcpSocketState::Close
                && socket.send_queue() == 0
                && control.send_buffer_empty()
            {
                trace!(
                    "socket {:?}: closing write half, state={:?}",
                    handle,
                    socket.state()
                );
                socket.close();
                control.set_send_state(TcpSocketState::Closing);
            }

            // Receive data from smoltcp into our buffer
            let mut wake_receiver = false;
            while socket.can_recv() && !control.recv_buffer_full() {
                match socket.recv(|data| {
                    let n = control.enqueue_recv_data(data);
                    (n, n)
                }) {
                    Ok(n) if n > 0 => {
                        wake_receiver = true;
                    }
                    Ok(_) => break,
                    Err(e) => {
                        error!(
                            "socket {:?} recv error: {:?}, state={:?}",
                            handle,
                            e,
                            socket.state()
                        );
                        socket.abort();
                        if control.recv_state() == TcpSocketState::Normal {
                            control.set_recv_state(TcpSocketState::Closed);
                        }
                        wake_receiver = true;
                        break;
                    }
                }
            }

            // Detect recv half close
            if control.recv_state() == TcpSocketState::Normal
                && !socket.may_recv()
                && !matches!(
                    socket.state(),
                    TcpState::Listen
                        | TcpState::SynReceived
                        | TcpState::Established
                        | TcpState::FinWait1
                        | TcpState::FinWait2
                )
            {
                trace!(
                    "socket {:?}: recv half closed, state={:?}",
                    handle,
                    socket.state()
                );
                control.set_recv_state(TcpSocketState::Closed);
                wake_receiver = true;
            }

            if wake_receiver {
                control.wake_receiver();
            }

            // Send data from our buffer to smoltcp
            let mut wake_sender = false;
            while socket.can_send() && !control.send_buffer_empty() {
                match socket.send(|buf| {
                    let n = control.dequeue_send_data(buf);
                    (n, n)
                }) {
                    Ok(n) if n > 0 => {
                        wake_sender = true;
                    }
                    Ok(_) => break,
                    Err(e) => {
                        error!(
                            "socket {:?} send error: {:?}, state={:?}",
                            handle,
                            e,
                            socket.state()
                        );
                        socket.abort();
                        if control.send_state() == TcpSocketState::Normal {
                            control.set_send_state(TcpSocketState::Closed);
                        }
                        wake_sender = true;
                        break;
                    }
                }
            }

            if wake_sender {
                control.wake_sender();
            }
        }

        for handle in sockets_to_remove {
            if let Some(socket_info) = sockets.remove(&handle) {
                active_connections.remove(&(socket_info.src_addr, socket_info.dst_addr));
                trace!(
                    "Cleaned up connection: {} -> {}",
                    socket_info.src_addr, socket_info.dst_addr
                );
            }
            socket_set.remove(handle);
        }
    }
}

/// Create a new TCP connection in the smoltcp stack.
fn create_tcp_connection(
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    socket_set: &mut SocketSet<'static>,
) -> Option<(SocketHandle, Arc<TcpConnectionControl>)> {
    let mut socket = TcpSocket::new(
        TcpSocketBuffer::new(vec![0u8; TCP_RECV_BUFFER_SIZE]),
        TcpSocketBuffer::new(vec![0u8; TCP_SEND_BUFFER_SIZE]),
    );

    // Matched to netstack-smoltcp settings for optimal performance
    socket.set_congestion_control(CongestionControl::Cubic);
    socket.set_keep_alive(Some(SmolDuration::from_secs(28)));
    // 7200s matches Linux default (tcp_keepalive_time) and shadowsocks-rust
    socket.set_timeout(Some(SmolDuration::from_secs(7200)));
    socket.set_nagle_enabled(false);
    socket.set_ack_delay(None);

    if let Err(e) = socket.listen(dst_addr) {
        warn!("Failed to listen on socket for {}: {:?}", dst_addr, e);
        return None;
    }

    debug!("Creating TCP connection: {} -> {}", src_addr, dst_addr);

    let control = Arc::new(TcpConnectionControl::new(
        TCP_SEND_BUFFER_SIZE,
        TCP_RECV_BUFFER_SIZE,
    ));

    let handle = socket_set.add(socket);

    // TcpConnection is created by the caller using this control + notify

    Some((handle, control))
}

/// Extract IP protocol from a raw IP packet.
fn get_ip_protocol(packet: &[u8]) -> Option<IpProtocol> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => Ipv4Packet::new_checked(packet)
            .ok()
            .map(|p| p.next_header()),
        6 => Ipv6Packet::new_checked(packet)
            .ok()
            .map(|p| p.next_header()),
        _ => None,
    }
}

/// Extract TCP connection info from a raw IP packet.
fn extract_tcp_info(packet: &[u8]) -> Option<(SocketAddr, SocketAddr, bool)> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => {
            let ip = Ipv4Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            let src_addr = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip.src_addr().octets())),
                tcp.src_port(),
            );
            let dst_addr = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip.dst_addr().octets())),
                tcp.dst_port(),
            );
            let is_syn = tcp.syn() && !tcp.ack();
            Some((src_addr, dst_addr, is_syn))
        }
        6 => {
            let ip = Ipv6Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            let src_addr = SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip.src_addr().octets())),
                tcp.src_port(),
            );
            let dst_addr = SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip.dst_addr().octets())),
                tcp.dst_port(),
            );
            let is_syn = tcp.syn() && !tcp.ack();
            Some((src_addr, dst_addr, is_syn))
        }
        _ => None,
    }
}

/// Check if an IP packet should be filtered.
fn should_filter_packet(packet: &[u8]) -> bool {
    if packet.is_empty() {
        return true;
    }

    let version = packet[0] >> 4;
    match version {
        4 => {
            if let Ok(ip) = Ipv4Packet::new_checked(packet) {
                let src_bytes = ip.src_addr().octets();
                let dst_bytes = ip.dst_addr().octets();

                // Filter unspecified source
                if src_bytes == [0, 0, 0, 0] {
                    return true;
                }
                // Filter multicast source
                if src_bytes[0] >= 224 && src_bytes[0] <= 239 {
                    return true;
                }
                // Filter broadcast destination
                if dst_bytes == [255, 255, 255, 255] {
                    return true;
                }
                // Filter multicast destination
                if dst_bytes[0] >= 224 && dst_bytes[0] <= 239 {
                    return true;
                }
                // Filter unspecified destination
                if dst_bytes == [0, 0, 0, 0] {
                    return true;
                }

                false
            } else {
                true
            }
        }
        6 => {
            if let Ok(ip) = Ipv6Packet::new_checked(packet) {
                let src_bytes = ip.src_addr().octets();
                let dst_bytes = ip.dst_addr().octets();

                // Filter unspecified source
                if src_bytes == [0u8; 16] {
                    return true;
                }
                // Filter multicast destination
                if dst_bytes[0] == 0xff {
                    return true;
                }
                // Filter unspecified destination
                if dst_bytes == [0u8; 16] {
                    return true;
                }

                false
            } else {
                true
            }
        }
        _ => true,
    }
}
