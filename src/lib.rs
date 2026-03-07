//! shoes-lite - VLESS+REALITY client/server library.
//!
//! Stripped from cfal/shoes to provide VLESS+REALITY support
//! with Vision flow control and TUN device support.

pub mod address;
pub mod api;
pub mod async_stream;
mod buf_reader;
mod client_proxy_chain;
pub mod client_proxy_selector;
pub mod config;
pub mod copy_bidirectional;
mod copy_bidirectional_message;
pub mod crypto;
pub mod dns;
pub mod logging;
pub mod option_util;
pub mod reality;
mod reality_client_handler;
pub mod resolver;
mod routing;
mod rustls_config_util;
mod rustls_connection_util;
mod slide_buffer;
pub mod socket_util;
pub mod speed_limit;
pub mod stream_reader;
mod sync_adapter;
pub mod tcp;
mod thread_util;
mod tls_client_handler;
pub mod tls_hello_parser;
pub mod tls_server_handler;
pub mod tun;
pub mod util;
pub mod uuid_util;
pub mod vless;
