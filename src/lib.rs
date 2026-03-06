#![allow(dead_code)]

//! floppa-vless - A minimal VLESS+REALITY client library with TUN support.
//!
//! Stripped from cfal/shoes to provide only the VLESS+REALITY client path
//! with Vision flow control and TUN device support.

mod address;
pub mod api;
mod async_stream;
mod buf_reader;
mod client_proxy_chain;
mod client_proxy_selector;
pub mod config;
mod copy_bidirectional;
mod copy_bidirectional_message;
mod crypto;
pub mod dns;
pub mod logging;
mod option_util;
mod reality;
mod reality_client_handler;
pub mod resolver;
mod routing;
mod rustls_config_util;
mod rustls_connection_util;
mod slide_buffer;
mod socket_util;
mod stream_reader;
mod sync_adapter;
mod tcp;
mod thread_util;
mod tls_client_handler;
mod tls_hello_parser;
mod tls_server_handler;
pub mod tun;
mod util;
mod uuid_util;
mod vless;
