use reqwest::Client;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use totp_gateway::App;
use totp_rs::{Algorithm, Secret, TOTP};

// Reuse the same secret format as other tests
const TEST_SECRET: &str = "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU";
const TOTP_STEP_SECS: u64 = 30;

// Short durations for faster tests
const SHORT_BAN_DURATION: u64 = 1;
const SHORT_SESSION_DURATION: u64 = 2;

struct TestFile {
    path: String,
}

impl TestFile {
    fn new(filename: &str, content: &str) -> Self {
        let tmp_dir = Path::new("target/tmp");
        fs::create_dir_all(tmp_dir).expect("Failed to create target/tmp directory");

        let path = format!("target/tmp/{}", filename);
        let mut file = fs::File::create(&path).expect("Failed to create test file");
        file.write_all(content.as_bytes())
            .expect("Failed to write test file content");
        Self { path }
    }
}

impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

async fn start_mock_upstream(port: u16) {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await.unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0; 1024];
                    let _ = socket.read(&mut buf).await;
                    let req_str = String::from_utf8_lossy(&buf);
                    let first_line = req_str.lines().next().unwrap_or("");

                    let body = if first_line.contains("GET /admin") {
                        "Admin Area"
                    } else {
                        "Hello World"
                    };

                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(), body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    tokio::time::sleep(Duration::from_millis(5)).await;
                });
            }
        }
    });
}

fn generate_totp_code() -> String {
    let secret_bytes = Secret::Encoded(TEST_SECRET.to_string())
        .to_bytes()
        .expect("Failed to decode secret");
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, TOTP_STEP_SECS, secret_bytes)
        .expect("Failed to create TOTP");
    totp.generate_current().expect("Failed to generate TOTP code")
}

fn create_test_config(proxy_port: u16, upstream_port: u16) -> String {
    // Configure two routes:
    // - /public/* with protect=false (bypass security)
    // - /admin/* with protect=true (default)
    // Also use very small limits to speed up tests
    format!(
        r#"
[server]
bind_addr = "127.0.0.1:{proxy_port}"
default_upstream = "127.0.0.1:{upstream_port}"
trusted_proxies = [["127.0.0.1/32", "X-Forwarded-For"]]

[security]
enabled = true
blacklist_size = 100
blacklist_strategy = "overwrite"
max_retries = 1
ip_limit_duration = 10
ban_duration = {ban}
whitelist_duration = 60

[auth]
totp_secret = "{secret}"
session_duration = {session}

[[routes]]
path = "/public/*"
upstream_addr = "127.0.0.1:{upstream_port}"
protect = false

[[routes]]
path = "/admin/*"
upstream_addr = "127.0.0.1:{upstream_port}"
protect = true
"#,
        proxy_port = proxy_port,
        upstream_port = upstream_port,
        ban = SHORT_BAN_DURATION,
        secret = TEST_SECRET,
        session = SHORT_SESSION_DURATION
    )
}

async fn start_test_server(proxy_port: u16, upstream_port: u16) -> TestFile {
    let config_content = create_test_config(proxy_port, upstream_port);
    let config_filename = format!("protect_test_config_{}.toml", proxy_port);
    let config_file = TestFile::new(&config_filename, &config_content);

    let config_path = format!("target/tmp/{}", config_filename);
    thread::spawn(move || {
        let app = App::new(config_path);
        app.run();
    });

    // Give the server a bit of time to start
    std::thread::sleep(Duration::from_millis(300));
    config_file
}

#[tokio::test]
async fn test_unprotected_route_bypasses_auth() {
    let _ = env_logger::builder().is_test(true).try_init();
    let upstream_port = 26610;
    start_mock_upstream(upstream_port).await;

    let proxy_port = 26611;
    let _config = start_test_server(proxy_port, upstream_port).await;

    let base_url = format!("http://127.0.0.1:{}", proxy_port);
    let client = Client::builder().cookie_store(true).build().unwrap();

    // Should not redirect to login page; should return upstream response directly
    let resp = client
        .get(format!("{}/public/anything", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "Hello World");
}

#[tokio::test]
async fn test_protected_route_still_requires_auth() {
    let _ = env_logger::builder().is_test(true).try_init();
    let upstream_port = 26612;
    start_mock_upstream(upstream_port).await;

    let proxy_port = 26613;
    let _config = start_test_server(proxy_port, upstream_port).await;

    let base_url = format!("http://127.0.0.1:{}", proxy_port);
    let auth_url = format!("{}/auth", base_url);
    let client = Client::builder().cookie_store(true).build().unwrap();

    // Access protected path should show login page
    let resp = client
        .get(format!("{}/admin/secret", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert!(body.contains("Access Gateway"));

    // Authenticate, then access should succeed
    let code = generate_totp_code();
    client
        .post(&auth_url)
        .form(&[("code", &code)])
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{}/admin/secret", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "Admin Area");
}

#[tokio::test]
async fn test_default_upstream_is_protected() {
    let _ = env_logger::builder().is_test(true).try_init();
    let upstream_port = 26614;
    start_mock_upstream(upstream_port).await;

    let proxy_port = 26615;
    let _config = start_test_server(proxy_port, upstream_port).await;

    let base_url = format!("http://127.0.0.1:{}", proxy_port);
    let client = Client::builder().cookie_store(true).build().unwrap();

    let resp = client.get(format!("{}/nomatch", base_url)).send().await.unwrap();
    let body = resp.text().await.unwrap();
    assert!(body.contains("Access Gateway"), "default upstream must be protected");
}

#[tokio::test]
async fn test_unprotected_route_ignores_blacklist() {
    let _ = env_logger::builder().is_test(true).try_init();
    let upstream_port = 26616;
    start_mock_upstream(upstream_port).await;

    let proxy_port = 26617;
    let _config = start_test_server(proxy_port, upstream_port).await;

    let base_url = format!("http://127.0.0.1:{}", proxy_port);
    let auth_url = format!("{}/auth", base_url);
    let client = Client::builder().cookie_store(true).build().unwrap();

    // Trigger blacklist quickly by sending wrong code (max_retries = 1)
    client
        .post(&auth_url)
        .form(&[("code", &"000000")])
        .send()
        .await
        .unwrap();

    // Access to protected route should now be blocked (429), confirming blacklist took effect
    let resp = client
        .get(format!("{}/admin/secret", base_url))
        .send()
        .await
        .unwrap();
    // Could be a login page or 429 depending on implementation order; capture status then body
    let status = resp.status();
    let maybe_body = resp.text().await.unwrap_or_default();
    let blocked = maybe_body.is_empty() || status == 429 || maybe_body.contains("Too Many Requests");
    assert!(blocked, "Expected protected route to be blocked after blacklist");

    // But unprotected route must still pass through regardless of blacklist
    let resp = client
        .get(format!("{}/public/free", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "Hello World");
}
