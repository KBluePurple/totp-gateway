use crate::config::BlacklistStrategy;
use crate::state::{
    CompiledRoute, DEFAULT_HTTP_PORT, MAX_BODY_SIZE, MAX_IP_ENTRIES, MAX_SESSION_ENTRIES,
    ProxyState, TOTP_DIGITS, TOTP_SKEW, TOTP_STEP_SECS,
};
use crate::utils::{ProxyError, SessionId, UpstreamAddr};
use async_trait::async_trait;
use bytes::Bytes;
use log::{info, warn};
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use std::net::IpAddr;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};
use url::form_urlencoded;
use uuid::Uuid;

pub struct AuthGateway {
    pub state: Arc<ProxyState>,
}

impl AuthGateway {
    fn get_real_ip(&self, session: &Session) -> Option<IpAddr> {
        let client_addr = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(|inet| inet.ip())?;

        let runtime = self.state.runtime.load();

        for (cidr, header_name) in &runtime.trusted_cidrs {
            if cidr.contains(&client_addr)
                && let Some(ip) = session
                    .req_header()
                    .headers
                    .get(header_name)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| IpAddr::from_str(s).ok())
            {
                return Some(ip);
            }
        }
        Some(client_addr)
    }

    fn verify_totp(&self, code: &str) -> Result<bool, ProxyError> {
        let runtime = self.state.runtime.load();
        let secret = Secret::Encoded(runtime.secret.clone());
        let secret_bytes = secret
            .to_bytes()
            .map_err(|_| ProxyError::TotpSecretInvalid)?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            TOTP_DIGITS,
            TOTP_SKEW as u8,
            TOTP_STEP_SECS,
            secret_bytes,
        )
        .map_err(|_| ProxyError::TotpCreationFailed)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let is_valid_format = totp.check(code, now)
            || totp.check(code, now.saturating_sub(TOTP_STEP_SECS))
            || totp.check(code, now.saturating_add(TOTP_STEP_SECS));

        if !is_valid_format {
            warn!("Invalid TOTP Format: {}", code);
            return Ok(false);
        }

        let current_step = now / TOTP_STEP_SECS;
        let last_step = self.state.last_verified_step.load(Ordering::Relaxed);

        if current_step > last_step {
            let result = self.state.last_verified_step.compare_exchange(
                last_step,
                current_step,
                Ordering::SeqCst,
                Ordering::Relaxed,
            );

            return Ok(result.is_ok());
        }

        warn!("Replay Attack Detected! Code used within same step.");
        Ok(false)
    }

    fn get_session_cookie(&self, session: &Session) -> Option<SessionId> {
        if let Some(header) = session.req_header().headers.get("Cookie")
            && let Ok(cookie_str) = header.to_str()
        {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if let Some(sid) = part.strip_prefix("SID=") {
                    return Some(SessionId::new(sid.to_string()));
                }
            }
        }
        None
    }

    fn is_blacklisted(&self, ip: IpAddr) -> bool {
        let runtime = self.state.runtime.load();
        if !runtime.config.security.enabled {
            return false;
        }
        self.state.blacklist.load().contains_key(&ip)
    }

    fn register_failure(&self, ip: IpAddr) {
        let runtime = self.state.runtime.load();
        let security_config = &runtime.config.security;

        if !security_config.enabled {
            return;
        }

        if !self.state.ip_limits.contains_key(&ip)
            && self.state.ip_limits.entry_count() >= MAX_IP_ENTRIES
        {
            warn!("IP Limit Table Full. Dropping failure tracking for: {}", ip);
            return;
        }

        let entry = self.state.ip_limits.entry(ip).or_insert(0);
        let mut val = *entry.value();
        val += 1;

        if val >= security_config.max_retries as u8 {
            let blacklist = self.state.blacklist.load();

            if security_config.blacklist_strategy == BlacklistStrategy::Block
                && blacklist.iter().count() as u64 >= security_config.blacklist_size as u64
            {
                warn!(
                    "Blacklist is full and strategy is 'block', not adding new IP: {}",
                    ip
                );
                return;
            }

            warn!("IP {} added to blacklist due to repeated failures.", ip);
            blacklist.insert(ip, ());
            self.state.ip_limits.invalidate(&ip);
            return;
        }

        self.state.ip_limits.insert(ip, val);
    }

    fn reset_failure(&self, ip: IpAddr) {
        self.state.ip_limits.invalidate(&ip);
    }

    fn parse_upstream_addr(addr: &str) -> UpstreamAddr {
        addr.parse()
            .unwrap_or_else(|_| UpstreamAddr::new("127.0.0.1".to_string(), DEFAULT_HTTP_PORT))
    }

    fn check_route(host: &str, path: &str, r: &&&CompiledRoute) -> bool {
        if let Some(prefix) = &r.path_prefix {
            return path.starts_with(prefix);
        }

        let host_match = r.host.as_ref().map(|re| re.is_match(host)).unwrap_or(true);
        let path_match = r.path.as_ref().map(|re| re.is_match(path)).unwrap_or(true);

        host_match && path_match
    }
}

#[async_trait]
impl ProxyHttp for AuthGateway {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let runtime = self.state.runtime.load();

        let host = session
            .req_header()
            .headers
            .get("Host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let host = host.split(':').next().unwrap_or(host);
        let path = session.req_header().uri.path();

        let upstream_addr = runtime
            .routes
            .iter()
            .find(|r| Self::check_route(host, path, &r))
            .map(|r| &r.upstream_addr)
            .unwrap_or(&runtime.config.server.default_upstream);

        let parsed = Self::parse_upstream_addr(upstream_addr);

        Ok(Box::new(HttpPeer::new(
            (parsed.host.as_str(), parsed.port),
            false,
            parsed.host.clone(),
        )))
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let runtime_for_route = self.state.runtime.load();
        let host_hdr = session
            .req_header()
            .headers
            .get("Host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let host_only = host_hdr.split(':').next().unwrap_or(host_hdr);
        let path = session.req_header().uri.path();

        let matched_route = runtime_for_route
            .routes
            .iter()
            .find(|r| Self::check_route(host_only, path, &r));

        if let Some(route) = matched_route {
            if !route.protect {
                return Ok(false);
            }
        }

        let client_ip = match self.get_real_ip(session) {
            Some(ip) => ip,
            None => {
                let mut header = ResponseHeader::build(400, Some(1))?;
                header.insert_header("Content-Length", "0")?;
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                return Ok(true);
            }
        };

        let runtime = self.state.runtime.load();
        let auth_config = &runtime.config.auth;

        if self.is_blacklisted(client_ip) {
            warn!("Blocked Request from {}", client_ip);
            let mut header = ResponseHeader::build(429, Some(1))?;
            header.insert_header("Content-Length", "0")?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            return Ok(true);
        }

        if let Some(sid) = self.get_session_cookie(session)
            && self.state.sessions.get(sid.as_str()).is_some()
        {
            return Ok(false);
        }

        if session.req_header().method == "POST" && session.req_header().uri.path() == "/auth" {
            let content_len = session.req_header().deref().headers.get("Content-Length");
            let content_len = content_len
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok());
            let content_len = content_len.unwrap_or(0);

            if content_len > MAX_BODY_SIZE {
                warn!("Payload too large: {} bytes", content_len);
                let mut header = ResponseHeader::build(413, Some(1))?;
                header.insert_header("Content-Length", "0")?;

                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }

            let body_bytes = session.read_request_body().await?.unwrap_or_default();

            if body_bytes.len() > MAX_BODY_SIZE {
                let mut header = ResponseHeader::build(413, Some(1))?;
                header.insert_header("Content-Length", "0")?;

                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }

            let params: std::collections::HashMap<String, String> =
                form_urlencoded::parse(&body_bytes).into_owned().collect();

            if let Some(code) = params.get("code") {
                match self.verify_totp(code) {
                    Ok(true) => {
                        self.reset_failure(client_ip);

                        if self.state.sessions.entry_count() >= MAX_SESSION_ENTRIES {
                            warn!("Session Table Full. Rejecting login.");
                            let mut header = ResponseHeader::build(503, Some(2))?;
                            header.insert_header("Retry-After", "60")?;
                            header.insert_header("Content-Length", "0")?;
                            session
                                .write_response_header(Box::new(header), true)
                                .await?;
                            return Ok(true);
                        }

                        let new_sid = SessionId::new(Uuid::new_v4().to_string());
                        info!("Login Success: (IP: {:?})", client_ip);

                        self.state.sessions.insert(new_sid.as_str().to_string(), ());

                        let cookie_val = format!(
                            "SID={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
                            new_sid, auth_config.session_duration
                        );
                        let mut header = ResponseHeader::build(302, Some(3))?;
                        header.insert_header("Set-Cookie", cookie_val)?;
                        header.insert_header("Location", "/")?;
                        header.insert_header("Content-Length", "0")?;

                        session
                            .write_response_header(Box::new(header), true)
                            .await?;
                        return Ok(true);
                    }
                    Ok(false) => {
                        warn!("Login Failed (Invalid TOTP). IP: {:?}", client_ip);
                        self.register_failure(client_ip);

                        if self.is_blacklisted(client_ip) {
                            let mut header = ResponseHeader::build(429, Some(1))?;
                            header.insert_header("Content-Length", "0")?;
                            session
                                .write_response_header(Box::new(header), true)
                                .await?;
                            return Ok(true);
                        }
                    }
                    Err(e) => {
                        warn!("TOTP verification error: {}", e);
                        self.register_failure(client_ip);
                    }
                }
            }

            let mut header = ResponseHeader::build(302, Some(2))?;
            header.insert_header("Location", "/?error=1")?;
            header.insert_header("Content-Length", "0")?;
            session
                .write_response_header(Box::new(header), true)
                .await?;
            return Ok(true);
        }

        let mut header = ResponseHeader::build(200, Some(8))?;
        header.insert_header("Content-Type", "text/html; charset=utf-8")?;
        header.insert_header("Content-Length", runtime.login_page_len.as_str())?;
        header.insert_header("X-Content-Type-Options", "nosniff")?;
        header.insert_header("X-Frame-Options", "DENY")?;

        header.insert_header(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, private",
        )?;
        header.insert_header("Pragma", "no-cache")?;
        header.insert_header("Expires", "0")?;
        header.insert_header("CDN-Cache-Control", "no-store")?;

        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(
                Some(Bytes::from(runtime.login_page_html.as_bytes().to_vec())),
                true,
            )
            .await?;

        Ok(true)
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        let runtime = self.state.runtime.load();

        let host_hdr = session
            .req_header()
            .headers
            .get("Host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let host_only = host_hdr.split(':').next().unwrap_or(host_hdr);
        let path = session.req_header().uri.path();

        let matched_route = runtime
            .routes
            .iter()
            .find(|r| Self::check_route(host_only, path, &r));

        let is_unprotected = matched_route.map(|r| !r.protect).unwrap_or(false);

        if !is_unprotected {
            upstream_response
                .insert_header(
                    "Cache-Control",
                    "no-store, no-cache, must-revalidate, private",
                )
                .ok();
            upstream_response.insert_header("Pragma", "no-cache").ok();
            upstream_response.insert_header("Expires", "0").ok();

            upstream_response
                .insert_header("CDN-Cache-Control", "no-store")
                .ok();
            upstream_response
                .insert_header("Cloudflare-CDN-Cache-Control", "no-store")
                .ok();
        }

        Ok(())
    }
}
