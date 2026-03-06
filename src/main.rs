mod address;
mod api;
mod async_stream;
mod buf_reader;
mod client_proxy_chain;
mod client_proxy_selector;
mod config;
mod copy_bidirectional;
mod copy_bidirectional_message;
mod crypto;
mod dns;
mod logging;
mod option_util;
mod reality;
mod reality_client_handler;
mod resolver;
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
mod tun;
mod util;
mod uuid_util;
mod vless;

#[cfg(not(any(target_env = "msvc", target_os = "ios")))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(any(target_env = "msvc", target_os = "ios")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use std::path::Path;

use log::debug;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::runtime::Builder;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use crate::reality::generate_keypair;
use crate::thread_util::set_num_threads;
use tcp::tcp_server::start_servers;

#[derive(Debug)]
struct ConfigChanged;

fn start_notify_thread(
    config_paths: Vec<String>,
) -> (RecommendedWatcher, UnboundedReceiver<ConfigChanged>) {
    let (tx, rx) = unbounded_channel();

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| match res {
        Ok(event) => {
            if matches!(event.kind, EventKind::Modify(..)) {
                tx.send(ConfigChanged {}).unwrap();
            }
        }
        Err(e) => println!("watch error: {e:?}"),
    })
    .unwrap();

    for config_path in config_paths {
        watcher
            .watch(Path::new(&config_path), RecursiveMode::NonRecursive)
            .unwrap();
    }

    (watcher, rx)
}

fn print_usage_and_exit(arg0: String) {
    eprintln!("{arg0} [OPTIONS] <config.yaml> [config.yaml...]");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("    -t, --threads NUM    Set the number of worker threads (default: CPU count)");
    eprintln!(
        "    -l, --log-file PATH  Log to file (repeatable; \"-\" means stderr; default: stderr)"
    );
    eprintln!("    -d, --dry-run        Parse the config and exit");
    eprintln!("    --no-reload          Disable automatic config reloading on file changes");
    eprintln!("    -V, --version        Print version information and exit");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("    generate-reality-keypair    Generate a new Reality X25519 keypair");
    eprintln!("    generate-vless-user-id      Generate a random VLESS user ID (UUID v4)");
    std::process::exit(1);
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let arg0 = args.remove(0);
    let mut num_threads = 0usize;
    let mut dry_run = false;
    let mut no_reload = false;
    let mut log_files: Vec<String> = Vec::new();

    while !args.is_empty() && args[0].starts_with("-") {
        if args[0] == "--threads" || args[0] == "-t" {
            args.remove(0);
            if args.is_empty() {
                eprintln!("Missing threads argument.");
                print_usage_and_exit(arg0);
                return;
            }
            num_threads = match args.remove(0).parse::<usize>() {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Invalid thread count: {e}");
                    print_usage_and_exit(arg0);
                    return;
                }
            };
        } else if args[0] == "--log-file" || args[0] == "-l" {
            args.remove(0);
            if args.is_empty() {
                eprintln!("Missing log-file argument.");
                print_usage_and_exit(arg0);
                return;
            }
            log_files.push(args.remove(0));
        } else if args[0] == "--dry-run" || args[0] == "-d" {
            args.remove(0);
            dry_run = true;
        } else if args[0] == "--no-reload" {
            args.remove(0);
            no_reload = true;
        } else if args[0] == "--version" || args[0] == "-V" {
            println!("shoes {}", env!("CARGO_PKG_VERSION"));
            return;
        } else {
            eprintln!("Invalid argument: {}", args[0]);
            print_usage_and_exit(arg0);
            return;
        }
    }

    let directives = logging::resolve_directives();
    let mut writers: Vec<Box<dyn logging::LogWriter>> = Vec::new();

    if log_files.is_empty() || log_files.iter().any(|p| p == "-") {
        writers.push(Box::new(logging::StderrWriter));
    }
    for path in &log_files {
        if path == "-" {
            continue;
        }
        match logging::FileLogWriter::new(path) {
            Ok(w) => writers.push(Box::new(w)),
            Err(e) => {
                eprintln!("Failed to open log file {path}: {e}");
                std::process::exit(1);
            }
        }
    }

    logging::init_multi_logger(writers, directives);

    if args.iter().any(|s| s == "generate-reality-keypair") {
        let (private_key, public_key) = generate_keypair().unwrap();
        println!(
            "--------------------------------------------------------------------------------"
        );
        println!("REALITY private key: {}", private_key);
        println!("REALITY public key: {}", public_key);
        println!(
            "--------------------------------------------------------------------------------"
        );
        return;
    }

    if args.iter().any(|s| s == "generate-vless-user-id") {
        let uuid = uuid_util::generate_uuid();
        println!(
            "--------------------------------------------------------------------------------"
        );
        println!("VLESS User ID: {}", uuid);
        println!(
            "--------------------------------------------------------------------------------"
        );
        return;
    }

    if args.is_empty() {
        println!("No config specified, assuming loading from file config.shoes.yaml");
        args.push("config.shoes.yaml".to_string())
    }

    if dry_run {
        println!("Starting dry run.");
    }

    if num_threads == 0 {
        num_threads = std::cmp::max(
            2,
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
        );
        debug!("Runtime threads: {num_threads}");
    } else {
        println!("Using custom thread count ({num_threads})");
    }

    set_num_threads(num_threads);

    let mut builder = if num_threads == 1 {
        Builder::new_current_thread()
    } else {
        let mut mt = Builder::new_multi_thread();
        mt.worker_threads(num_threads);
        mt
    };

    let runtime = builder
        .enable_io()
        .enable_time()
        .build()
        .expect("Could not build tokio runtime");

    runtime.block_on(async move {
        let mut reload_state = if no_reload {
            None
        } else {
            let (watcher, rx) = start_notify_thread(args.clone());
            Some((watcher, rx))
        };

        loop {
            let configs = match config::load_configs(&args).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to load server configs: {e}\n");
                    print_usage_and_exit(arg0);
                    return;
                }
            };

            let (configs, load_file_count) = match config::convert_cert_paths(configs).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to load cert files: {e}\n");
                    print_usage_and_exit(arg0);
                    return;
                }
            };

            if load_file_count > 0 {
                println!("Loaded {load_file_count} certs/keys from files");
            }

            for config in configs.iter() {
                debug!("================================================================================");
                debug!("{config:#?}");
            }
            debug!("================================================================================");

            if dry_run {
                if let Err(e) = config::create_server_configs(configs) {
                    eprintln!("Dry run failed, could not create server configs: {e}\n");
                } else {
                    println!("Finishing dry run, config parsed successfully.");
                }
                return;
            }

            let mut join_handles = vec![];

            let server_configs = match config::create_server_configs(configs) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to create server configs: {e}\n");
                    print_usage_and_exit(arg0);
                    return;
                }
            };

            let config::ValidatedConfigs {
                configs: server_configs,
                dns_groups,
            } = server_configs;

            let mut dns_registry = match dns::build_dns_registry(dns_groups).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Failed to build DNS registry: {e}\n");
                    print_usage_and_exit(arg0);
                    return;
                }
            };

            println!("\nStarting {} server(s)..", server_configs.len());

            for server_config in server_configs {
                let dns_ref = match &server_config {
                    config::Config::Server(s) => s.dns.as_ref(),
                    config::Config::TunServer(t) => t.dns.as_ref(),
                    _ => None,
                };
                let resolver = dns_registry.get_for_server(dns_ref);
                join_handles.extend(start_servers(server_config, resolver).await.unwrap());
            }

            match reload_state.as_mut() {
                Some((_watcher, rx)) => {
                    rx.recv().await.unwrap();

                    println!("Configs changed, restarting servers in 3 seconds..");

                    for join_handle in join_handles {
                        join_handle.abort();
                    }

                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                    while rx.try_recv().is_ok() {}
                }
                None => {
                    futures::future::pending::<()>().await;
                    unreachable!();
                }
            }
        }
    });
}
