# shoes-lite

A VLESS+REALITY library and server written in Rust. Forked from [cfal/shoes](https://github.com/cfal/shoes), stripped to only VLESS+REALITY with Vision flow control and TUN device support.

Used as a dependency by VPN clients (TUN tunnel) and servers (REALITY inbound).

## Features

- **VLESS protocol** with framing, Vision flow control, and fallback support
- **XTLS REALITY** handshake (X25519 + HKDF + AES-256-GCM) — client and server
- **XTLS Vision** obfuscation (padding, TLS deframing)
- **TUN device** + async smoltcp TCP/IP stack for transparent VPN mode (Linux, Windows, macOS, Android, iOS)
- **Multi-user server** via `VlessAuthenticator` trait
- **VLESS URI parser** — standard `vless://` format from 3X-UI / v2rayNG
- **Traffic stats** with atomic counters (tx/rx bytes)
- **Socket protection** bridge for Android `VpnService.protect()`
- **Linux socket marks** per client (`VlessConfig::fwmark` / `ClientConfig::fwmark`)
- **Standalone server binary** with YAML config and hot-reload

## Library Usage

Add as a git dependency:

```toml
[dependencies]
shoes-lite = { git = "https://github.com/okhsunrog/shoes-lite" }
```

### Client — VPN Tunnel

```rust
use shoes_lite::api::{VlessConfig, VlessTunnel};

// Parse a standard VLESS URI
let config = VlessConfig::from_uri(
    "vless://UUID@server:443?encryption=none&flow=xtls-rprx-vision\
     &security=reality&sni=www.microsoft.com&fp=chrome\
     &pbk=PUBLIC_KEY&sid=SHORT_ID&type=tcp#profile"
).unwrap();

// Desktop: create TUN device and start tunnel
let tunnel = VlessTunnel::new(&config, "tun0").await.unwrap();

// Android/iOS: use platform VPN fd
// let tunnel = VlessTunnel::from_fd(&config, tun_fd).await.unwrap();

// Query live traffic stats
let stats = tunnel.get_stats();
println!("TX: {} bytes, RX: {} bytes", stats.tx_bytes, stats.rx_bytes);

// Shut down
tunnel.stop().await.unwrap();
```

On Linux, set `config.fwmark = Some(mark)` before starting a tunnel when its outer
traffic must bypass a policy routing table. The same mark is used by connectivity
checks and every new TCP/UDP transport socket, before connecting or sending. A
failed `SO_MARK` returns an error and closes the socket; it never retries without
the mark. The process needs permission to set socket marks (normally
`CAP_NET_ADMIN`). The default `None` leaves sockets unmarked; requesting a mark
on other platforms returns `Unsupported`. Android socket protection is independent.

### Server — Multi-User VLESS Inbound

Implement `VlessAuthenticator` for your user registry:

```rust
use shoes_lite::vless::VlessAuthenticator;

struct MyAuthenticator { /* ... */ }

impl VlessAuthenticator for MyAuthenticator {
    fn authenticate(&self, uuid: &[u8; 16]) -> bool {
        // Look up UUID in your database
    }
}
```

Then use the REALITY server handlers (`TlsServerHandler`, `RealityServerConnection`) with your authenticator to accept VLESS+REALITY inbound connections. See the `floppa-vless` crate for a complete multi-user server implementation.

## Standalone Server

The binary loads YAML config files and runs VLESS+REALITY servers directly.

```bash
# Run server
shoes-lite config.yaml

# Generate REALITY keypair
shoes-lite generate-reality-keypair

# Generate VLESS user ID
shoes-lite generate-vless-user-id

# Validate config
shoes-lite --dry-run config.yaml
```

### Example: REALITY Server

```yaml
- address: 0.0.0.0:443
  protocol:
    type: tls
    reality_targets:
      "www.example.com":
        private_key: "YOUR_BASE64URL_PRIVATE_KEY"
        short_ids: ["0123456789abcdef"]
        dest: "www.example.com:443"
        vision: true
        protocol:
          type: vless
          user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0
          udp_enabled: true
```

### Example: TUN VPN Client

```yaml
- device_name: tun0
  address: 10.0.0.1
  netmask: 255.255.255.0
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "server.example.com:443"
        protocol:
          type: reality
          public_key: "SERVER_PUBLIC_KEY"
          short_id: "0123456789abcdef"
          sni_hostname: "www.example.com"
          vision: true
          protocol:
            type: vless
            user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0
```

See the [examples](./examples) directory and [CONFIG.md](./CONFIG.md) for more configurations.

## Supported Platforms

| Platform | TUN | Client | Server |
|----------|-----|--------|--------|
| Linux | root or `CAP_NET_ADMIN` | yes | yes |
| Android | raw fd from `VpnService` | yes | no |
| iOS/macOS | raw fd from `NEPacketTunnelProvider` | yes | no |
| Windows | Wintun driver | yes | yes |

## Related Projects

- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) — reference VLESS+REALITY implementation
- [cfal/shoes](https://github.com/cfal/shoes) — upstream multi-protocol proxy server

## License

MIT

## Upstream TLS and TUN fixes (October 2026)

Ported the TLS/Vision ownership fixes from upstream `9b0f808` and adapted the
TUN event-driven work from `ee38ccc` to this fork's cross-platform async stack.
TLS records now keep one owner through handshake and Vision END/DIRECT transitions;
REALITY and VLESS fallbacks return an owned session instead of detaching a task.
Shutdown after EOF is bounded, while active sessions have no added lifetime limit.
`CryptoTlsStream::handshake` replaces the separate public handshake function;
Vision constructors accept that owned stream. Server handlers must await the new
`TcpServerSetupResult::Session` variant. Multi-user authentication, shared bandwidth
limits, and per-client Linux socket marks remain supported.

The async TUN loop waits for packet/bridge notifications and actual TCP deadlines
instead of a 10 ms polling fallback, uses a monotonic clock, propagates device
failures, rejects partial packet writes, and owns child TCP tasks through shutdown.
It retains `tun::AsyncDevice` on Linux, Windows, and Android. Unix-only raw-fd stack,
splice/offload, and post-quantum REALITY changes are not part of this port.
