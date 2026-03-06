# floppa-vless: VLESS+REALITY Shared Library — Implementation Plan

## Overview

Strip cfal/shoes fork to a VLESS+REALITY library (`floppa-vless`) with both **client**
(TUN tunnel + Vision) and **server** (REALITY+VLESS inbound) paths. Used by:

- **floppa-client** (Tauri 2) — client-side VPN tunnel via TUN device
- **floppa-daemon** — server-side VLESS+REALITY inbound (replacing/alongside WireGuard)

## Architecture

```
floppa-client (Tauri 2)
├── VpnBackend trait
│   ├── WireGuard path:  ProtocolConfig::WireGuard → GotatunTunnel (existing)
│   └── VLESS path:      ProtocolConfig::VlessReality → VlessTunnel (new)
│
└── VlessTunnel (thin wrapper in floppa-client)
        │
        ▼
    floppa-vless (separate repo, git dependency)
    ├── api.rs         — Public client API: VlessTunnel, VlessConfig, URI parser
    ├── reality/       — REALITY client + server (X25519 + HKDF + AES-256-GCM)
    ├── vless/         — VLESS framing + Vision flow control (client + server)
    ├── tun/           — TUN device + smoltcp TCP/IP stack (client only)
    ├── tcp/           — TCP server loop + handler factory (server only)
    ├── crypto/        — rustls wrappers
    ├── config/        — YAML config for standalone server mode
    └── core I/O       — AsyncStream, copy_bidirectional, address types

floppa-daemon
└── Uses floppa-vless server handlers:
    ├── RealityServerConnection — REALITY TLS inbound
    ├── VlessServerHandler      — VLESS protocol parsing
    └── TlsServerHandler        — TLS termination + SNI routing
```

## Design Principles

- **Keep VLESS+REALITY protocol compatible with Xray-core.** Any standard Xray/3X-UI
  server must work. Don't modify VLESS framing, REALITY handshake crypto, or Vision
  flow control. These are inside the encrypted tunnel — DPI can't see them, and changing
  them only breaks interop.
- **Customize the observable TLS layer independently.** The ClientHello fingerprint should
  mimic a real Chrome browser, not necessarily match Xray's uTLS output. Client diversity
  helps the ecosystem — DPI can't create a single signature for all REALITY users.
- **Don't add cover traffic or artificial jitter.** Adding traffic that real browsers don't
  generate makes you MORE fingerprintable, not less. Vision padding is sufficient.
- **Support standard VLESS URI format** for config import from 3X-UI panels.
- **Server code stays.** The REALITY/VLESS server handlers are kept for use in
  floppa-daemon. This library serves both sides.

---

## Phase 0: Strip non-VLESS protocols ✅ DONE

**Goal:** Delete everything except VLESS+REALITY (client + server) + TUN.

### Removed

| Category | Files |
|----------|-------|
| VMess | `vmess/` |
| Trojan | `trojan_handler.rs` |
| Shadowsocks | `shadowsocks/` |
| Snell | `snell/` |
| Hysteria2 | `hysteria2_server.rs` |
| TUIC | `tuic_server.rs` |
| NaiveProxy | `naiveproxy/` |
| AnyTLS | `anytls/` |
| ShadowTLS | `shadow_tls/` |
| HTTP/SOCKS5 inbound | `http_handler.rs`, `socks_handler.rs`, `socks5_udp_relay.rs`, `mixed_handler.rs` |
| XUDP | `xudp/` |
| H2MUX | `h2mux/` |
| WebSocket | `websocket/` |
| UoT | `uot/` |
| Port forward | `port_forward_handler.rs` |
| FFI (shoes-style) | `ffi/` (floppa has its own Tauri + JNI integration) |

### Kept

| Module | Purpose | Used by |
|--------|---------|---------|
| VLESS framing | `vless/vless_message_stream.rs`, `vless_client_handler.rs` | Client |
| VLESS server | `vless/vless_server_handler.rs` | Daemon |
| Vision flow | `vless/vision_stream.rs`, `vision_pad.rs`, `vision_unpad.rs`, `tls_deframer.rs`, `tls_fuzzy_deframer.rs` | Client |
| REALITY client | `reality/reality_client_connection.rs`, `reality_tls13_messages.rs`, `reality_tls13_keys.rs`, etc. | Client |
| REALITY server | `reality/reality_server_connection.rs`, `reality_server_handler.rs` | Daemon |
| TLS server | `tls_server_handler.rs` | Daemon |
| TCP server | `tcp/tcp_server.rs`, `tcp_server_handler_factory.rs` | Daemon |
| TUN + smoltcp | `tun/tun_server.rs`, `tcp_stack_direct.rs`, `tcp_conn.rs`, `udp_manager.rs`, etc. | Client |
| Core I/O | `async_stream.rs`, `copy_bidirectional.rs`, `address.rs`, etc. | Both |
| Crypto/TLS | `crypto/` (rustls wrappers) | Both |
| DNS resolver | `resolver.rs`, `dns/` | Both |
| Client chain | `client_proxy_chain.rs` | Client |
| Config engine | `config/` (YAML parsing) | Standalone server mode |

### Cleanup backlog (non-blocking)

These are nice-to-have cleanups, not required for integration:

- Remove unused deps from Cargo.toml (`quinn`, `parking_lot`, `serde_yaml` if config
  engine is dropped)
- Slim down `ClientProxySelector` (2K lines) if only single-chain is needed for client

### Status

- [x] `cargo build` succeeds
- [x] `cargo test` passes (480 tests)
- [x] Non-VLESS protocols removed

---

## Phase 1: Public Client API + Stats ✅ DONE

**Goal:** Expose a clean `VlessTunnel` API that matches floppa's `TunnelManager` pattern.

### VlessTunnel public API (in `api.rs`)

```rust
pub struct VlessTunnel { /* shutdown_tx, task handle, stats */ }

impl VlessTunnel {
    /// Desktop: creates TUN device, starts VLESS+REALITY tunnel
    pub async fn new(
        config: &VlessConfig,
        interface_name: &str,
    ) -> Result<Self, String>;

    /// Android/iOS: takes fd from platform VPN service
    pub async fn from_fd(
        config: &VlessConfig,
        tun_fd: i32,
    ) -> Result<Self, String>;

    /// Traffic stats (non-blocking read of atomics)
    pub fn get_stats(&self) -> TrafficStats;

    /// Connection duration
    pub fn connection_duration(&self) -> Option<Duration>;

    /// Shutdown tunnel
    pub async fn stop(self) -> Result<(), String>;
}
```

### VlessConfig struct

```rust
pub struct VlessConfig {
    pub uuid: String,
    pub server_addr: String,       // host:port
    pub server_name: String,       // SNI for REALITY
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub flow: Option<String>,      // "xtls-rprx-vision"
    pub address: Option<String>,   // client tunnel IP
    pub netmask: Option<String>,   // e.g. "255.255.255.0"
    pub dns: Option<String>,
    pub mtu: Option<u16>,
    pub allowed_ips: Option<String>,
}
```

### VLESS URI parser

Parses standard format from 3X-UI / v2rayNG:

```
vless://UUID@SERVER:443?encryption=none&flow=xtls-rprx-vision
  &security=reality&sni=www.microsoft.com&fp=chrome
  &pbk=PUBLIC_KEY&sid=SHORT_ID&type=tcp#profile-name
```

### Stats tracking

`TunnelStats` with `AtomicU64` counters for tx/rx bytes, threaded through
`handle_tcp_connection` and `handle_udp_packets` in the TUN server.

### Socket protection bridge

`set_socket_protector()` forwards floppa's callback to shoes' `tun::platform` module.

### Status

- [x] `VlessTunnel::new()` creates tunnel and returns handle
- [x] `VlessTunnel::from_fd()` for Android/iOS
- [x] `get_stats()` returns live tx/rx byte counts
- [x] `stop()` shuts down cleanly
- [x] VLESS URI parsing works (8 unit tests)
- [x] Socket protection callback bridged
- [x] `lib.rs` exports `pub mod api` + `pub mod tun`

---

## Phase 2: Floppa Integration (2-3 days)

**Goal:** Wire floppa-vless into floppa-client as second protocol.

### floppa-client changes

**state.rs** — Add variant:
```rust
pub enum ProtocolConfig {
    #[serde(rename = "wireguard")]
    WireGuard(WgConfig),
    #[serde(rename = "vless_reality")]
    VlessReality(VlessConfig),
}
```

Implement `endpoint_str()`, `address()`, `dns_servers()`, `allowed_ips_networks()`,
`get_mtu()`, `protocol_name()` for the new variant.

Add `VlessConfig::from_uri(uri: &str)` parser (delegate to floppa-vless).

**tunnel.rs** — Add `VlessTunnelWrapper` alongside `GotatunTunnel` with same interface:
`new()`, `from_fd()`, `get_stats()`, `stop()`.

Generalize `TunnelManager` to hold either tunnel type (enum or trait object).

**backend/in_process.rs** — Add match arm:
```rust
ProtocolConfig::VlessReality(vl) => {
    self.tunnel_manager.start_vless(vl, interface_name, fwmark, endpoint).await
}
```

**Android (jni_entry.rs + Kotlin)** — Dispatch based on protocol in config.
Socket protection callback bridges to floppa-vless.

**Config persistence** — Works automatically via serde enum. No changes needed.

**Platform routes/DNS** — Protocol-agnostic. No changes needed.

### Server-side (floppa-daemon)

Add VLESS+REALITY server alongside WireGuard in floppa-daemon:

- Use floppa-vless server handlers (`TlsServerHandler`, `RealityServerConnection`,
  `VlessServerHandler`) to accept VLESS+REALITY inbound connections
- Allocate UUID per peer, store in DB alongside WireGuard keys
- Extend `POST /me/peers` API with protocol parameter
- Generate VLESS URI strings for client config distribution

### Checklist

- [ ] Can connect to Xray-core server from desktop (Linux)
- [ ] Can connect from Android
- [ ] Config persists across app restarts
- [ ] Stats display works (tx/rx bytes, speed)
- [ ] Connect/disconnect lifecycle works cleanly
- [ ] WireGuard still works (no regressions)

---

## Phase 3: Reconnection + Robustness (1 week)

**Goal:** Handle connection drops gracefully. This is the hardest part — VLESS is TCP-based
(unlike WireGuard which is UDP and handles network transitions natively).

### Connection loss detection

- TCP keepalive on the outer connection (OS-level, 15-30s interval)
- Application-level timeout: if no data flows for N seconds and stats stop updating
- smoltcp stack health check: detect when the stack thread exits unexpectedly

### Reconnection flow

1. Detect loss (keepalive timeout / TCP RST / stack thread exit)
2. Keep TUN device up (apps don't notice)
3. Update connection status → `Reconnecting`
4. Tear down smoltcp state + old proxy chain
5. Re-resolve server DNS (endpoint may have changed IP)
6. Re-establish REALITY handshake + VLESS connection
7. Create new smoltcp stack on same TUN fd
8. Resume packet handling
9. Status → `Connected`

### Backoff strategy

- First retry: immediate
- Then: 1s, 2s, 4s, 8s, max 30s
- Reset backoff on successful connection lasting > 60s

### Network change handling (mobile)

- Android: listen for `CONNECTIVITY_ACTION` broadcast → trigger reconnect
- When switching wifi ↔ cellular, the source IP changes, TCP connection dies
- Need to reconnect proactively on network change, not wait for keepalive timeout

### TCP-over-TCP awareness

Document the known tradeoff: TUN captures app TCP → wraps in VLESS over TCP.
Two competing congestion control stacks degrade performance under packet loss.
Vision mitigates for TLS traffic (Direct mode). Non-TLS traffic has this overhead.
No fix needed — just document as known limitation vs WireGuard.

---

## Phase 4: TLS Fingerprint Audit (2-3 days)

**Goal:** Verify shoes' REALITY ClientHello looks like a real browser.

### Step 1: Capture and compare

- Wireshark capture of shoes' ClientHello to xray-core server
- Compare against actual Chrome 131+ ClientHello
- Check JA3/JA4 fingerprint databases
- Compare against Xray-core's uTLS `fp=chrome` output

### Step 2: Fix if needed

If shoes' `reality_tls13_messages.rs` produces a non-browser-like fingerprint:

- **Cipher suite order** — match Chrome's current order
- **Extension order** — Chrome randomizes since v110, implement random ordering
- **GREASE values** — must be random, not fixed
- **Supported groups** — Chrome sends X25519 (+ Kyber768 in newer versions)
- **ALPN** — must include h2, http/1.1

Changes go in `reality/reality_tls13_messages.rs`. This doesn't affect REALITY
protocol compatibility — only the observable TLS outer layer changes.

### Step 3: Verify

- Capture again, confirm fingerprint matches target browser
- Test against xray-core to confirm REALITY handshake still works
- Test with known DPI tools (e.g., `tlsfuzzer`, online JA3 checkers)

---

## Phase 5: Polish (ongoing)

- Kill switch (block all traffic if tunnel drops, before reconnect completes)
- DNS leak prevention (ensure OS resolver can't bypass tunnel)
- Split tunneling UI (per-app on Android, CIDR-based on desktop)
- Server selection (multiple servers, latency-based selection)
- VLESS URI import via QR code / clipboard
- Battery optimization on Android (adaptive keepalive in doze mode)

---

## Repo Structure

**floppa-vless** (separate repo, this shoes fork):
```
floppa-vless/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Public API exports
│   ├── api.rs              # VlessTunnel, VlessConfig, TrafficStats, URI parser
│   ├── vless/              # VLESS framing + Vision (client + server)
│   ├── reality/            # REALITY handshake (client + server)
│   ├── tun/                # TUN + smoltcp (client only)
│   ├── tcp/                # TCP server loop (server only)
│   ├── tls_server_handler.rs  # TLS inbound (server only)
│   ├── crypto/             # rustls wrappers
│   ├── config/             # YAML config (standalone server mode)
│   ├── address.rs          # Address types
│   ├── async_stream.rs     # I/O traits
│   ├── copy_bidirectional.rs
│   ├── stream_reader.rs
│   ├── slide_buffer.rs
│   ├── socket_util.rs
│   ├── resolver.rs
│   ├── client_proxy_chain.rs
│   └── util.rs
├── src/main.rs             # Standalone server binary
└── tests/
```

**floppa-vpn** (existing repo, add dependency):
```toml
# floppa-client/src-tauri/Cargo.toml
[dependencies]
floppa-vless = { git = "https://github.com/okhsunrog/floppa-vless" }
```

---

## Key Dependencies (floppa-vless)

| Crate | Purpose |
|-------|---------|
| tokio | Async runtime |
| rustls + aws-lc-rs | TLS 1.3 + crypto primitives |
| x25519-dalek | REALITY key exchange |
| smoltcp | TCP/IP stack for TUN |
| tun | TUN device (cross-platform) |
| log | Logging (bridges to floppa's tracing via tracing-log) |
| uuid | VLESS user ID |
| base64 | Key encoding |
| serde / serde_json | Config serialization |
| serde_yaml | YAML config for standalone server mode |
| url | VLESS URI parsing |

---

## Timeline

| Phase | Time | Cumulative |
|-------|------|------------|
| 0: Strip non-VLESS protocols | ✅ Done | — |
| 1: Public API + stats | ✅ Done | — |
| 2: Floppa integration | 2-3 days | 2-3 days |
| 3: Reconnection | 1 week | ~1.5 weeks |
| 4: Fingerprint audit | 2-3 days | ~2 weeks |
| 5: Polish | Ongoing | — |
| **Core working client** | **~2 weeks** | |

## Testing Strategy

- **Unit tests:** Keep all inline tests from shoes (480 passing)
- **Interop:** Test every phase against standard Xray-core server with VLESS+REALITY+Vision
- **Wireshark:** Capture ClientHello, verify fingerprint after Phase 4
- **Mobile:** Test Android VpnService flow after Phase 2
- **Reconnection:** Simulate network drops (iptables DROP, wifi toggle) after Phase 3
