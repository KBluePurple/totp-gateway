use crate::config::Config;
use arc_swap::ArcSwap;
use ipnet::IpNet;
use moka::sync::Cache;
use regex::Regex;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

pub const MAX_BODY_SIZE: usize = 4 * 1024;
pub const MAX_IP_ENTRIES: u64 = 100_000;
pub const MAX_SESSION_ENTRIES: u64 = 50_000;

pub const TOTP_DIGITS: usize = 6;
pub const TOTP_STEP_SECS: u64 = 30;
pub const TOTP_SKEW: u64 = 1;

pub const DEFAULT_HTTP_PORT: u16 = 80;

pub const FILE_WATCH_DEBOUNCE_MS: u64 = 100;

pub struct CompiledRoute {
    pub host: Option<Regex>,
    pub path: Option<Regex>,
    pub path_prefix: Option<String>,
    pub upstream_addr: String,
}

pub struct RuntimeState {
    pub config: Config,
    pub secret: String,
    pub trusted_cidrs: Vec<(IpNet, String)>,
    pub routes: Vec<CompiledRoute>,
    pub login_page_html: Arc<String>,
    pub login_page_len: Arc<String>,
}

pub struct ProxyState {
    pub runtime: ArcSwap<RuntimeState>,
    pub sessions: Cache<String, ()>,
    pub whitelist: Cache<IpAddr, ()>,
    pub blacklist: ArcSwap<Cache<IpAddr, ()>>,
    pub ip_limits: Cache<IpAddr, u8>,
    pub last_verified_step: AtomicU64,
}
