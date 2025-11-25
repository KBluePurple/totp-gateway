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

const TEST_SECRET: &str = "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU";
const TOTP_STEP_SECS: u64 = 30;

// Use shorter durations for testing
const SHORT_BAN_DURATION: u64 = 1; // 1 second instead of 2
const SHORT_SESSION_DURATION: u64 = 2; // 2 seconds instead of 3

struct TestFile {
    path: String,
}

impl TestFile {
    fn new(filename: &str, content: &str) -> Self {
        // Create target/tmp directory if it doesn't exist
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
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    tokio::time::sleep(Duration::from_millis(5)).await;
                });
            }
        }
    });
}

fn create_test_config(
    proxy_port: u16,
    upstream_port: u16,
    ban_duration: u64,
    session_duration: u64,
) -> String {
    format!(
        "[server]\nbind_addr = \"127.0.0.1:{}\"\ndefault_upstream = \"127.0.0.1:{}\"\ntrusted_proxies = [[\"127.0.0.1/32\", \"X-Forwarded-For\"]]

[security]\nenabled = true\nblacklist_size = 100\nblacklist_strategy = \"overwrite\"\nmax_retries = 3\nban_duration = {}\nsession_duration = {}

[auth]\ntotp_secret = \"{}\"\nsession_duration = {}

[[routes]]
path_prefix = \"/admin\"
upstream_addr = \"127.0.0.1:{}\"\n",
        proxy_port, upstream_port, ban_duration, session_duration, TEST_SECRET, session_duration, upstream_port
    )
}

async fn start_test_server(
    proxy_port: u16,
    upstream_port: u16,
    ban_duration: u64,
    session_duration: u64,
) -> TestFile {
    let config_content =
        create_test_config(proxy_port, upstream_port, ban_duration, session_duration);
    let config_filename = format!("test_config_{}.toml", proxy_port);
    let config_file = TestFile::new(&config_filename, &config_content);

    let config_path = format!("target/tmp/{}", config_filename);
    thread::spawn(move || {
        let app = App::new(config_path);
        app.run();
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    config_file
}

fn generate_totp_code() -> String {
    let secret_bytes = Secret::Encoded(TEST_SECRET.to_string())
        .to_bytes()
        .expect("Failed to decode secret");
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, TOTP_STEP_SECS, secret_bytes)
        .expect("Failed to create TOTP");
    totp.generate_current()
        .expect("Failed to generate TOTP code")
}

#[tokio::test]
async fn test_basic_auth_and_replay_protection() {
    let _ = env_logger::builder().is_test(true).try_init();

    let upstream_port = 26100;
    start_mock_upstream(upstream_port).await;

    let proxy_port = 26101;
    let _config_file = start_test_server(
        proxy_port,
        upstream_port,
        SHORT_BAN_DURATION,
        SHORT_SESSION_DURATION,
    )
    .await;

    let client = Client::builder().cookie_store(true).build().unwrap();
    let auth_url = format!("http://127.0.0.1:{}/auth", proxy_port);

    let code = generate_totp_code();

    // Test successful authentication
    let resp = client
        .post(&auth_url)
        .form(&[("code", &code)])
        .header("X-Forwarded-For", "10.0.1.1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "Authentication should succeed");

    // Test replay attack protection
    let client2 = Client::builder().cookie_store(true).build().unwrap();
    let resp = client2
        .post(&auth_url)
        .form(&[("code", &code)])
        .header("X-Forwarded-For", "10.0.1.2")
        .send()
        .await
        .unwrap();
    assert!(
        resp.url().query().unwrap_or("").contains("error=1"),
        "Replay attack should fail"
    );
}

#[tokio::test]
async fn test_blacklist_and_ban_expiry() {
    let _ = env_logger::builder().is_test(true).try_init();

    let upstream_port = 26200;
    start_mock_upstream(upstream_port).await;

    let proxy_port = 26201;
    let _config_file = start_test_server(
        proxy_port,
        upstream_port,
        SHORT_BAN_DURATION,
        SHORT_SESSION_DURATION,
    )
    .await;

    let base_url = format!("http://127.0.0.1:{}", proxy_port);
    let auth_url = format!("{}/auth", base_url);
    let ip = "10.0.2.1";

    let client_fail = Client::builder().cookie_store(true).build().unwrap();

    // Trigger blacklist with multiple failed attempts
    // max_retries = 3, so attempts 1-3 should work, attempt 4+ should be banned
    for i in 0..6 {
        let resp = client_fail
            .post(&auth_url)
            .form(&[("code", "000000")])
            .header("X-Forwarded-For", ip)
            .send()
            .await
            .unwrap();

        // First 3 attempts should fail auth but not be banned (status 302 or 200)
        // 4th attempt onwards should be banned (status 429)
        if i >= 3 {
            assert_eq!(
                resp.status(),
                429,
                "Should be banned after {} attempts",
                i + 1
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Verify IP is blacklisted
    let resp = client_fail
        .get(&base_url)
        .header("X-Forwarded-For", ip)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        429,
        "IP should be blacklisted after failures"
    );

    // Wait for ban to expire
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Verify ban has expired
    let resp = client_fail
        .get(&base_url)
        .header("X-Forwarded-For", ip)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "Ban should have expired");
    assert!(resp.text().await.unwrap().contains("Access Gateway"));
}

#[tokio::test]
async fn test_session_expiry() {
    let _ = env_logger::builder().is_test(true).try_init();

    let upstream_port = 26300;
    start_mock_upstream(upstream_port).await;

    let proxy_port = 26301;
    let _config_file = start_test_server(
        proxy_port,
        upstream_port,
        SHORT_BAN_DURATION,
        SHORT_SESSION_DURATION,
    )
    .await;

    let base_url = format!("http://127.0.0.1:{}", proxy_port);
    let auth_url = format!("{}/auth", base_url);

    let code = generate_totp_code();
    let client = Client::builder().cookie_store(true).build().unwrap();

    // Authenticate
    let resp = client
        .post(&auth_url)
        .form(&[("code", &code)])
        .header("X-Forwarded-For", "10.0.3.1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Access should work immediately
    let resp = client.get(&base_url).send().await.unwrap();
    assert_eq!(resp.text().await.unwrap(), "Hello World");

    // Wait for session to expire (2 seconds + buffer)
    tokio::time::sleep(Duration::from_millis(2300)).await;

    // Access should redirect to login
    let resp = client.get(&base_url).send().await.unwrap();
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("Access Gateway"),
        "Session should have expired"
    );
}

#[tokio::test]
async fn test_route_matching() {
    let _ = env_logger::builder().is_test(true).try_init();

    let upstream_port = 26400;
    start_mock_upstream(upstream_port).await;

    let proxy_port = 26401;
    let _config_file = start_test_server(
        proxy_port,
        upstream_port,
        SHORT_BAN_DURATION,
        SHORT_SESSION_DURATION,
    )
    .await;

    let base_url = format!("http://127.0.0.1:{}", proxy_port);
    let auth_url = format!("{}/auth", base_url);

    let code = generate_totp_code();
    let client = Client::builder().cookie_store(true).build().unwrap();

    // Authenticate
    client
        .post(&auth_url)
        .form(&[("code", &code)])
        .send()
        .await
        .unwrap();

    // Test admin route
    let resp = client
        .get(format!("{}/admin", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "Admin Area");

    // Test default route
    let resp = client
        .get(format!("{}/other", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "Hello World");
}

#[tokio::test]
async fn test_concurrent_requests() {
    let _ = env_logger::builder().is_test(true).try_init();

    let upstream_port = 26500;
    start_mock_upstream(upstream_port).await;

    let proxy_port = 26501;
    let _config_file = start_test_server(
        proxy_port,
        upstream_port,
        SHORT_BAN_DURATION,
        SHORT_SESSION_DURATION,
    )
    .await;

    let base_url = format!("http://127.0.0.1:{}", proxy_port);
    let auth_url = format!("{}/auth", base_url);

    let code = generate_totp_code();
    let client = Client::builder().cookie_store(true).build().unwrap();

    // Authenticate once
    client
        .post(&auth_url)
        .form(&[("code", &code)])
        .send()
        .await
        .unwrap();

    // Send multiple concurrent requests
    let mut handles = vec![];
    for _ in 0..10 {
        let client_clone = client.clone();
        let url = base_url.clone();
        let handle = tokio::spawn(async move {
            client_clone
                .get(&url)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
        });
        handles.push(handle);
    }

    // All should succeed
    for handle in handles {
        let result = handle.await.unwrap();
        assert_eq!(result, "Hello World");
    }
}