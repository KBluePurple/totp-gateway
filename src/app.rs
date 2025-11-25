use crate::config::load_config;
use crate::proxy::AuthGateway;
use crate::state::{
    CompiledRoute, FILE_WATCH_DEBOUNCE_MS, MAX_IP_ENTRIES, MAX_SESSION_ENTRIES, ProxyState,
    RuntimeState,
};
use crate::utils::glob_to_regex;
use arc_swap::ArcSwap;
use ipnet::IpNet;
use log::{error, info, warn};
use moka::sync::Cache;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use pingora::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::channel;
use std::time::Duration;

pub struct App {
    config_path: PathBuf,
}

impl App {
    pub fn new<P: AsRef<Path>>(config_path: P) -> Self {
        Self {
            config_path: config_path.as_ref().to_path_buf(),
        }
    }

    fn load_runtime_state(path: &Path) -> Result<RuntimeState, String> {
        let config = load_config(path).map_err(|e| e.to_string())?;
        let secret = config.auth.get_secret().map_err(|e| e.to_string())?;

        let trusted_cidrs: Vec<(IpNet, String)> = config
            .server
            .trusted_proxies
            .iter()
            .filter_map(|(s, h)| {
                s.parse::<IpNet>()
                    .map(|cidr| (cidr, h.clone()))
                    .map_err(|e| {
                        warn!("Failed to parse trusted proxy CIDR '{}': {}", s, e);
                        e
                    })
                    .ok()
            })
            .collect();

        let routes = config
            .routes
            .iter()
            .map(|r| {
                let host = r.host.as_ref().and_then(|h| {
                    glob_to_regex(h)
                        .map_err(|e| {
                            warn!("Failed to compile host pattern '{}': {}", h, e);
                            e
                        })
                        .ok()
                });

                let path = r.path.as_ref().and_then(|p| {
                    glob_to_regex(p)
                        .map_err(|e| {
                            warn!("Failed to compile path pattern '{}': {}", p, e);
                            e
                        })
                        .ok()
                });

                CompiledRoute {
                    host,
                    path,
                    path_prefix: r.path_prefix.clone(),
                    upstream_addr: r.upstream_addr.clone(),
                }
            })
            .collect();

        let login_page_html = match &config.auth.login_page_file {
            Some(path) => fs::read_to_string(path)
                .map_err(|e| format!("Failed to read login page file {}: {}", path, e))?,
            None => include_str!("../login_page.html").to_string(),
        };

        let login_page_len = login_page_html.len().to_string();

        Ok(RuntimeState {
            config,
            secret,
            trusted_cidrs,
            routes,
            login_page_html: Arc::new(login_page_html),
            login_page_len: Arc::new(login_page_len),
        })
    }

    fn handle_config_reload(config_path: &Path, state: &Arc<ProxyState>) {
        match Self::load_runtime_state(config_path) {
            Ok(new_runtime) => {
                let new_sec = &new_runtime.config.security;
                let old_sec = &state.runtime.load().config.security;

                if new_sec.blacklist_size != old_sec.blacklist_size
                    || new_sec.ban_duration != old_sec.ban_duration
                {
                    info!(
                        "Blacklist config changed (Size: {}, Duration: {}s). Re-creating cache.",
                        new_sec.blacklist_size, new_sec.ban_duration
                    );
                    let new_blacklist = Cache::builder()
                        .time_to_live(Duration::from_secs(new_sec.ban_duration))
                        .max_capacity(new_sec.blacklist_size as u64)
                        .build();
                    state.blacklist.store(Arc::new(new_blacklist));
                }

                state.runtime.store(Arc::new(new_runtime));
                info!("Configuration reloaded successfully.");
            }
            Err(e) => {
                error!("Failed to reload configuration: {}", e);
            }
        }
    }

    pub fn run(self) {
        let initial_runtime = match Self::load_runtime_state(&self.config_path) {
            Ok(runtime) => runtime,
            Err(e) => {
                error!("Failed to load initial configuration: {}", e);
                std::process::exit(1);
            }
        };

        let bind_addr = initial_runtime.config.server.bind_addr.clone();
        let tls_config = initial_runtime.config.tls.clone();

        let security_config = &initial_runtime.config.security;
        let auth_config = &initial_runtime.config.auth;

        let blacklist_size = security_config.blacklist_size as u64;
        let ban_duration = Duration::from_secs(security_config.ban_duration);
        let whitelist_duration = Duration::from_secs(security_config.whitelist_duration);
        let ip_limit_duration = Duration::from_secs(security_config.ip_limit_duration);
        let session_duration = Duration::from_secs(auth_config.session_duration);

        let initial_blacklist = Arc::new(
            Cache::builder()
                .time_to_live(ban_duration)
                .max_capacity(blacklist_size)
                .build(),
        );

        let state = Arc::new(ProxyState {
            runtime: ArcSwap::new(Arc::new(initial_runtime)),
            sessions: Cache::builder()
                .time_to_live(session_duration)
                .max_capacity(MAX_SESSION_ENTRIES)
                .build(),
            whitelist: Cache::builder()
                .time_to_live(whitelist_duration)
                .max_capacity(MAX_IP_ENTRIES)
                .build(),
            blacklist: ArcSwap::new(initial_blacklist),
            ip_limits: Cache::builder()
                .time_to_live(ip_limit_duration)
                .max_capacity(MAX_IP_ENTRIES)
                .build(),
            last_verified_step: AtomicU64::new(0),
        });

        let state_for_watcher = state.clone();
        let config_path = self.config_path.clone();

        std::thread::spawn(move || {
            let (tx, rx) = channel();
            let mut watcher = match RecommendedWatcher::new(tx, notify::Config::default()) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to create file watcher: {}", e);
                    return;
                }
            };

            if let Err(e) = watcher.watch(&config_path, RecursiveMode::NonRecursive) {
                error!("Failed to watch config file: {}", e);
                return;
            }

            info!("Watching config file: {:?}", config_path);

            for res in rx {
                match res {
                    Ok(event) => {
                        if event.kind.is_modify() || event.kind.is_create() {
                            info!("Config file changed. Reloading...");
                            std::thread::sleep(Duration::from_millis(FILE_WATCH_DEBOUNCE_MS));
                            Self::handle_config_reload(&config_path, &state_for_watcher);
                        }
                    }
                    Err(e) => error!("Watch error: {}", e),
                }
            }
        });

        let mut server = match Server::new(None) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to create server: {}", e);
                std::process::exit(1);
            }
        };

        server.bootstrap();

        let mut my_gateway = http_proxy_service(&server.configuration, AuthGateway { state });

        if let Some(tls) = tls_config {
            if let Err(e) = my_gateway.add_tls(&bind_addr, &tls.cert_file, &tls.key_file) {
                error!("Failed to add TLS: {}", e);
                std::process::exit(1);
            }
            info!("Gateway Server running on {} (HTTPS)", bind_addr);
        } else {
            my_gateway.add_tcp(&bind_addr);
            info!("Gateway Server running on {} (HTTP)", bind_addr);
        }

        server.add_service(my_gateway);
        server.run_forever();
    }
}
