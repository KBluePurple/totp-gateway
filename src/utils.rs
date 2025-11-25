use regex::Regex;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for SessionId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamAddr {
    pub host: String,
    pub port: u16,
}

impl UpstreamAddr {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }
}

impl FromStr for UpstreamAddr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        match parts.as_slice() {
            [host, port_str] => {
                let port = port_str
                    .parse::<u16>()
                    .map_err(|_| ParseError::InvalidPort(port_str.to_string()))?;
                Ok(Self {
                    host: host.to_string(),
                    port,
                })
            }
            [host] => Ok(Self {
                host: host.to_string(),
                port: 80,
            }),
            _ => Err(ParseError::InvalidFormat(s.to_string())),
        }
    }
}

impl fmt::Display for UpstreamAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone)]
pub enum ParseError {
    InvalidFormat(String),
    InvalidPort(String),
    InvalidRegex(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidFormat(s) => write!(f, "Invalid format: {}", s),
            ParseError::InvalidPort(s) => write!(f, "Invalid port: {}", s),
            ParseError::InvalidRegex(s) => write!(f, "Invalid regex: {}", s),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone)]
pub enum ProxyError {
    MissingClientIp,
    InvalidUpstream(String),
    TotpSecretInvalid,
    TotpCreationFailed,
    SessionTableFull,
    IpLimitTableFull,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::MissingClientIp => write!(f, "Client IP address not found"),
            ProxyError::InvalidUpstream(s) => write!(f, "Invalid upstream address: {}", s),
            ProxyError::TotpSecretInvalid => write!(f, "TOTP secret is invalid"),
            ProxyError::TotpCreationFailed => write!(f, "Failed to create TOTP instance"),
            ProxyError::SessionTableFull => write!(f, "Session table is full"),
            ProxyError::IpLimitTableFull => write!(f, "IP limit table is full"),
        }
    }
}

impl std::error::Error for ProxyError {}

pub struct ClientIp(IpAddr);

impl ClientIp {
    pub fn new(ip: IpAddr) -> Self {
        Self(ip)
    }

    pub fn inner(&self) -> IpAddr {
        self.0
    }
}

impl From<IpAddr> for ClientIp {
    fn from(ip: IpAddr) -> Self {
        Self(ip)
    }
}

pub fn glob_to_regex(pattern: &str) -> Result<Regex, ParseError> {
    let mut regex_str = String::from("^");
    for c in pattern.chars() {
        match c {
            '*' => regex_str.push_str(".*"),
            '?' => regex_str.push('.'),
            '.' | '+' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' => {
                regex_str.push('\\');
                regex_str.push(c);
            }
            _ => regex_str.push(c),
        }
    }
    regex_str.push('$');
    Regex::new(&regex_str).map_err(|e| ParseError::InvalidRegex(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upstream_addr_parse() {
        let addr: UpstreamAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(addr.host, "127.0.0.1");
        assert_eq!(addr.port, 8080);

        let addr: UpstreamAddr = "example.com".parse().unwrap();
        assert_eq!(addr.host, "example.com");
        assert_eq!(addr.port, 80);

        assert!("invalid:port:extra".parse::<UpstreamAddr>().is_err());
        assert!("host:abc".parse::<UpstreamAddr>().is_err());
    }

    #[test]
    fn test_glob_to_regex() {
        let re = glob_to_regex("*.example.com").unwrap();
        assert!(re.is_match("sub.example.com"));
        assert!(re.is_match("a.example.com"));
        assert!(!re.is_match("example.com"));

        let re = glob_to_regex("/api/*").unwrap();
        assert!(re.is_match("/api/users"));
        assert!(re.is_match("/api/"));
        assert!(!re.is_match("/api"));

        let re = glob_to_regex("test?.com").unwrap();
        assert!(re.is_match("test1.com"));
        assert!(re.is_match("testa.com"));
        assert!(!re.is_match("test.com"));
        assert!(!re.is_match("test12.com"));
    }
}
