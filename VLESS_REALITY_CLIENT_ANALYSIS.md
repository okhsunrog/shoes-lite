# Shoes Codebase Analysis: Minimal VLESS+REALITY Client with TUN

## Module Map (what to keep)

| Function | Key Files | ~Lines |
|----------|-----------|--------|
| **VLESS framing** | `vless/vless_message_stream.rs`, `vless/vless_client_handler.rs` | ~600 |
| **VISION flow control** | `vless/vision_stream.rs`, `vless/vision_pad.rs`, `vless/vision_unpad.rs`, `vless/tls_deframer.rs`, `vless/tls_fuzzy_deframer.rs` | ~2,500 |
| **REALITY TLS** | `reality/reality_client_connection.rs`, `reality/reality_tls13_messages.rs`, `reality/reality_tls13_keys.rs`, `reality/reality_cipher_suite.rs`, `reality/reality_auth.rs`, `reality/reality_records.rs` | ~3,500 |
| **TUN device** | `tun/tun_server.rs`, `tun/tcp_stack_direct.rs`, `tun/tcp_conn.rs`, `tun/udp_manager.rs`, `tun/udp_handler.rs` | ~2,200 |
| **Client chain** | `client_proxy_chain.rs`, `tcp/tcp_client_handler_factory.rs` | ~1,800 |
| **Core I/O** | `async_stream.rs`, `copy_bidirectional.rs`, `stream_reader.rs`, `address.rs`, `socket_util.rs`, `util.rs`, `slide_buffer.rs` | ~2,500 |
| **Crypto/TLS** | `crypto/` (rustls wrappers) | ~1,000 |
| **DNS resolver** | `resolver.rs`, subset of `dns/` | ~800 |
| **Config** (trimmed) | `config/` (only client + VLESS + REALITY types) | ~1,000 |

**Estimated keep: ~16,000 lines** (before further trimming)

## Dependency Graph (keep path)

```
main.rs (entry)
  └─ config/ (parse YAML)
       └─ tun/tun_server.rs
            └─ tun/tcp_stack_direct.rs (smoltcp)
                 ├─ tun/tcp_conn.rs (per-connection)
                 └─ tun/udp_manager.rs
                      └─ client_proxy_chain.rs (outbound)
                           └─ tcp_client_handler_factory.rs
                                └─ VlessProxyConnector
                                     ├─ reality/reality_client_connection.rs
                                     │    ├─ reality_tls13_messages.rs
                                     │    ├─ reality_tls13_keys.rs (HKDF)
                                     │    ├─ reality_cipher_suite.rs
                                     │    ├─ reality_auth.rs (HMAC)
                                     │    └─ reality_records.rs
                                     └─ vless/vision_stream.rs
                                          ├─ vision_pad.rs / vision_unpad.rs
                                          ├─ tls_deframer.rs
                                          └─ vless_message_stream.rs
```

## What to Remove (~51,000 lines)

| Category | Files | ~Lines |
|----------|-------|--------|
| **VMess** | `vmess/` (8 files) | ~4,500 |
| **Trojan** | `trojan_handler.rs` | ~150 |
| **Shadowsocks** | `shadowsocks/` (10 files) | ~4,000 |
| **Snell** | `snell/` (3 files) | ~700 |
| **Hysteria2** | `hysteria2_server.rs` | ~1,050 |
| **TUIC** | `tuic_server.rs` | ~1,470 |
| **NaiveProxy** | `naiveproxy/` (6 files) | ~2,500 |
| **AnyTLS** | `anytls/` (7 files) | ~3,500 |
| **ShadowTLS** | `shadow_tls/` (3 files) | ~1,800 |
| **HTTP proxy inbound** | `http_handler.rs` | ~250 |
| **SOCKS5 inbound** | `socks_handler.rs`, `socks5_udp_relay.rs` | ~1,300 |
| **Mixed handler** | `mixed_handler.rs` | ~100 |
| **Server-side inbound** | `tls_server_handler.rs`, `reality/reality_server_connection.rs`, all `*_server_handler` files | ~5,000 |
| **XUDP** | `xudp/` (3 files) | ~1,500 |
| **H2MUX** | `h2mux/` | ~1,000 |
| **WebSocket** | `websocket/` | ~800 |
| **UoT** | `uot/` | ~400 |
| **Port forward** | `port_forward_handler.rs` | ~100 |
| **FFI** | `ffi/` (Android/iOS) | ~1,500 |
| **Server TCP handler factory** | `tcp/tcp_server_handler_factory.rs` | ~600 |
| **Config validation** (bulk) | most of `config/validate.rs`, server config types | ~3,000 |
| **Client proxy selector** (rules) | `client_proxy_selector.rs` (optional -- keep if you want rule routing) | ~2,070 |
| **UDP router** | `routing/udp_router.rs` | ~1,300 |
| **Misc** | `h2_multi_stream.rs`, heavy DNS features, etc. | ~3,000+ |

## Summary

| | Lines | % of total |
|---|---|---|
| **Total codebase** | ~67,500 | 100% |
| **Keep (VLESS+REALITY client+TUN)** | ~16,000 | ~24% |
| **Remove** | ~51,500 | ~76% |

## Notes

The core needed is well-contained: the `reality/` client half, `vless/` with VISION, `tun/`, `client_proxy_chain.rs`, core I/O utilities, and a slimmed config layer.

Biggest wins come from dropping all server-side inbound handlers and the 8+ protocols not needed.

Also strip heavy dependencies from `Cargo.toml`: quinn, h2, h3, hickory-dns server features, jni/ndk.
