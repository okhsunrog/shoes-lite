# floppa-vless: VLESS+REALITY Client Library — Implementation Plan

## Overview

Strip cfal/shoes fork down to a minimal VLESS+REALITY+Vision+TUN library (`floppa-vless`),
then integrate into floppa-vpn as a second protocol alongside WireGuard.

## Architecture

```
floppa-client (Tauri 2)
├── VpnBackend trait
│   ├── WireGuard path:  ProtocolConfig::WireGuard → GotatunTunnel (existing)
│   └── VLESS path:      ProtocolConfig::VlessReality → VlessTunnel (new)
│
└── VlessTunnel (thin wrapper in floppa-client or bridge crate)
        │
        ▼
    floppa-vless (separate repo, git dependency)
    ├── reality/   — REALITY client handshake (X25519 + HKDF + AES-256-GCM)
    ├── vless/     — VLESS framing + Vision flow control
    ├── tun/       — TUN device + smoltcp TCP/IP stack
    ├── crypto/    — rustls wrappers
    └── core I/O   — AsyncStream, copy_bidirectional, address types
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

---

## Phase 0: Strip shoes (1-2 days)

**Goal:** Delete everything except VLESS+REALITY client path + TUN.

### Remove (~51K lines)

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
| Server-side handlers | `tls_server_handler.rs`, `reality/reality_server_connection.rs`, all `*_server_handler` |
| XUDP | `xudp/` |
| H2MUX | `h2mux/` |
| WebSocket | `websocket/` |
| UoT | `uot/` |
| Port forward | `port_forward_handler.rs` |
| Server TCP handler factory | `tcp/tcp_server_handler_factory.rs` |
| YAML config engine | Most of `config/` (replace with typed API) |
| Heavy DNS features | DNS server, DoH server (keep client resolver only) |
| FFI (shoes-style) | `ffi/` (floppa has its own Tauri + JNI integration) |

### Keep (~16K lines)

| Module | Files | Purpose |
|--------|-------|---------|
| VLESS framing | `vless/vless_message_stream.rs`, `vless/vless_client_handler.rs` | Protocol codec |
| Vision flow | `vless/vision_stream.rs`, `vision_pad.rs`, `vision_unpad.rs`, `tls_deframer.rs`, `tls_fuzzy_deframer.rs` | TLS-in-TLS optimization |
| REALITY client | `reality/reality_client_connection.rs`, `reality_tls13_messages.rs`, `reality_tls13_keys.rs`, `reality_cipher_suite.rs`, `reality_auth.rs`, `reality_records.rs`, `reality_aead.rs`, `reality_util.rs`, `common.rs` | Custom TLS 1.3 handshake |
| TUN + smoltcp | `tun/tun_server.rs`, `tcp_stack_direct.rs`, `tcp_conn.rs`, `udp_manager.rs`, `udp_handler.rs`, `platform.rs` | VPN packet handling |
| Core I/O | `async_stream.rs`, `copy_bidirectional.rs`, `stream_reader.rs`, `address.rs`, `socket_util.rs`, `util.rs`, `slide_buffer.rs` | Shared utilities |
| Crypto/TLS | `crypto/` (rustls wrappers) | Standard TLS for non-REALITY |
| DNS resolver | `resolver.rs`, minimal `dns/` subset | Name resolution |
| Client chain | `client_proxy_chain.rs` (simplified) | Single-chain VLESS connector |

### Strip Cargo.toml dependencies

Remove: `quinn`, `h2`, `h3`, `hickory-dns` (server features), `jni`, `ndk-sys`,
`android_logger`, `parking_lot`, heavy optional deps.

Keep: `tokio`, `rustls`, `aws-lc-rs`, `x25519-dalek`, `smoltcp`, `tun`, `log`, `serde`,
`uuid`, `base64`.

### Checklist

- [ ] `cargo build` succeeds with only VLESS+REALITY+TUN code
- [ ] `cargo test` passes for all kept modules (~35 files with inline tests)
- [ ] No references to removed protocols remain

---

## Phase 1: Public API + Stats (2-3 days)

**Goal:** Expose a clean `VlessTunnel` API that matches floppa's `TunnelManager` pattern.

### Replace ClientProxySelector

Shoes' `ClientProxySelector` is 2K lines of rule-matching engine. Replace with a trivial
single-chain selector (~50 lines) that always routes through one VLESS+REALITY chain:

```rust
pub struct SingleChainSelector {
    chain: Arc<ClientProxyChain>,
}

impl SingleChainSelector {
    pub fn new(config: &VlessConfig) -> Result<Self, Error> {
        // Build one chain: socket → REALITY TLS → VLESS+Vision → target
    }
}
```

### Add stats tracking

Shoes' `run_tun_server` has no stats API. Add shared atomic counters:

```rust
pub struct TunnelStats {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub connected_at: Instant,
}
```

Thread these through `handle_tcp_connection` and `handle_udp_packets` — increment on
every `copy_bidirectional` completion. ~100 lines.

### VlessTunnel public API

```rust
pub struct VlessTunnel { /* shutdown_tx, task handle, stats */ }

impl VlessTunnel {
    /// Desktop: creates TUN device, starts VLESS+REALITY tunnel
    pub async fn new(
        config: &VlessConfig,
        interface_name: &str,
        fwmark: Option<u32>,
        endpoint: SocketAddr,
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

### Bridge socket protection

Forward floppa's `SOCKET_PROTECT_CALLBACK` to shoes' `set_global_socket_protector()`.
~30 lines.

### VlessConfig struct

```rust
pub struct VlessConfig {
    pub uuid: String,
    pub server_addr: String,       // host:port
    pub server_name: String,       // SNI for REALITY
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub flow: Option<String>,      // "xtls-rprx-vision"
    pub address: String,           // client tunnel IP, e.g. "10.0.0.2/32"
    pub dns: Option<String>,
    pub mtu: Option<u16>,
    pub allowed_ips: String,
}
```

### VLESS URI parser

Parse standard format from 3X-UI / v2rayNG:

```
vless://UUID@SERVER:443?encryption=none&flow=xtls-rprx-vision
  &security=reality&sni=www.microsoft.com&fp=chrome
  &pbk=PUBLIC_KEY&sid=SHORT_ID&type=tcp#profile-name
```

~100 lines.

### Checklist

- [ ] `VlessTunnel::new()` creates tunnel and returns handle
- [ ] `get_stats()` returns live tx/rx byte counts
- [ ] `stop()` shuts down cleanly
- [ ] VLESS URI parsing works for standard format
- [ ] Socket protection callback is bridged

---

## Phase 2: Floppa Integration (2-3 days)

**Goal:** Wire floppa-vless into floppa-client as second protocol.

### floppa-client changes

**state.rs** — Add variant + config struct:
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

Add `VlessConfig::from_uri(uri: &str)` parser (or delegate to floppa-vless).

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

### Server-side (floppa-server)

Add `generate_vless_config()` in `floppa-core/src/services.rs`:
- Allocate UUID per peer
- Return VLESS URI string
- Store in DB alongside WireGuard config

API: extend `POST /me/peers` with protocol parameter.

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
│   ├── lib.rs              # Public API: VlessTunnel, VlessConfig, TrafficStats
│   ├── vless/              # VLESS framing + Vision (from shoes)
│   ├── reality/            # REALITY client (from shoes)
│   ├── tun/                # TUN + smoltcp (from shoes)
│   ├── crypto/             # rustls wrappers (from shoes)
│   ├── address.rs          # Address types (from shoes)
│   ├── async_stream.rs     # I/O traits (from shoes)
│   ├── copy_bidirectional.rs
│   ├── stream_reader.rs
│   ├── slide_buffer.rs
│   ├── socket_util.rs
│   ├── resolver.rs
│   ├── client_proxy_chain.rs  # Simplified single-chain
│   └── util.rs
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
| url | VLESS URI parsing |

---

## Timeline

| Phase | Time | Cumulative |
|-------|------|------------|
| 0: Strip shoes | 1-2 days | 1-2 days |
| 1: Public API + stats | 2-3 days | ~1 week |
| 2: Floppa integration | 2-3 days | ~1.5 weeks |
| 3: Reconnection | 1 week | ~2.5 weeks |
| 4: Fingerprint audit | 2-3 days | ~3 weeks |
| 5: Polish | Ongoing | — |
| **Core working client** | **~3 weeks** | |

## Testing Strategy

- **Unit tests:** Keep all ~35 files of inline tests from shoes (REALITY, Vision, TUN, etc.)
- **Interop:** Test every phase against standard Xray-core server with VLESS+REALITY+Vision
- **Wireshark:** Capture ClientHello, verify fingerprint after Phase 4
- **Mobile:** Test Android VpnService flow after Phase 2
- **Reconnection:** Simulate network drops (iptables DROP, wifi toggle) after Phase 3
