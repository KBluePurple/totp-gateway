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
                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nHello, World!";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });
}

#[tokio::test]
async fn test_integration_flow() {
    let _ = env_logger::builder().is_test(true).try_init();
    let upstream_port = 25002;
    start_mock_upstream(upstream_port).await;

    let custom_login_page_filename = "custom_login_test.html";
    let _login_page_file = TestFile::new(custom_login_page_filename, "My Custom Login Page");

    let proxy_port = 25003;

    let config_content = format!(
        "[server]\nbind_addr = \"127.0.0.1:{}\"\ndefault_upstream = \"127.0.0.1:{}\"\ntrusted_proxies = [[\"127.0.0.1/32\", \"X-Forwarded-For\"]]

[auth]\ntotp_secret = \"{}\"\nlogin_page_file = \"target/tmp/{}\"\n
[[routes]]
path_prefix = \"/\"
upstream_addr = \"127.0.0.1:{}\"\n",
        proxy_port, upstream_port, TEST_SECRET, custom_login_page_filename, upstream_port
    );

    let config_filename = format!("test_config_{}.toml", proxy_port);
    let _config_file = TestFile::new(&config_filename, &config_content);

    let config_path = format!("target/tmp/{}", config_filename);
    thread::spawn(move || {
        let app = App::new(config_path);
        app.run();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let client = Client::builder().cookie_store(true).build().unwrap();
    let base_url = format!("http://127.0.0.1:{}", proxy_port);

    let resp = client
        .get(&base_url)
        .send()
        .await
        .expect("Failed to connect to proxy");
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("My Custom Login Page"));

    let params = [("code", "000000")];
    let resp = client
        .post(format!("{}/auth", base_url))
        .form(&params)
        .send()
        .await
        .expect("Failed to send login");

    assert_eq!(resp.status(), 200);
    assert!(resp.url().query().unwrap().contains("error=1"));

    let secret_bytes = Secret::Encoded(TEST_SECRET.to_string())
        .to_bytes()
        .expect("Failed to decode secret");
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, TOTP_STEP_SECS, secret_bytes)
        .expect("Failed to create TOTP");
    let code = totp
        .generate_current()
        .expect("Failed to generate TOTP code");

    let params = [("code", code)];
    let resp = client
        .post(format!("{}/auth", base_url))
        .form(&params)
        .send()
        .await
        .expect("Failed to send login");

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "Hello, World!");

    let resp = client
        .get(&base_url)
        .send()
        .await
        .expect("Failed to connect with session");
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "Hello, World!");
}

#[tokio::test]
async fn test_blacklist_flow() {
    let _ = env_logger::builder().is_test(true).try_init();
    let upstream_port = 25004;
    start_mock_upstream(upstream_port).await;

    let proxy_port = 25005;

    let config_content = format!(
        "[server]\nbind_addr = \"127.0.0.1:{}\"\ndefault_upstream = \"127.0.0.1:{}\"\ntrusted_proxies = [[\"127.0.0.1/32\", \"X-Forwarded-For\"]]

[security]\nenabled = true
blacklist_size = 100
blacklist_strategy = \"overwrite\"

[auth]\ntotp_secret = \"{}\"\n",
        proxy_port, upstream_port, TEST_SECRET
    );

    let config_filename = format!("test_config_{}.toml", proxy_port);
    let _config_file = TestFile::new(&config_filename, &config_content);

    let config_path = format!("target/tmp/{}", config_filename);
    thread::spawn(move || {
        let app = App::new(config_path);
        app.run();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let client = Client::builder().cookie_store(true).build().unwrap();
    let base_url = format!("http://127.0.0.1:{}", proxy_port);
    let auth_url = format!("{}/auth", base_url);

    for i in 1..=300 {
        let ip = format!("1.2.3.{}", i);
        for _ in 0..5 {
            client
                .post(&auth_url)
                .form(&[("code", "000000")])
                .header("X-Forwarded-For", &ip)
                .send()
                .await
                .unwrap();
        }
    }

    tokio::time::sleep(Duration::from_millis(1000)).await;

    let mut blacklisted_count = 0;
    for i in 1..=300 {
        let ip = format!("1.2.3.{}", i);
        let resp = client
            .get(&base_url)
            .header("X-Forwarded-For", &ip)
            .send()
            .await
            .unwrap();

        if resp.status() == 429 {
            blacklisted_count += 1;
        }
    }

    println!(
        "Total blacklisted IPs found: {} (Limit: 100)",
        blacklisted_count
    );

    assert!(
        blacklisted_count <= 250,
        "Blacklist size exceeded limit significantly. Found {} blacklisted IPs, limit is 100.",
        blacklisted_count
    );
    assert!(
        blacklisted_count >= 80,
        "Blacklist seems too empty? Found {} blacklisted IPs.",
        blacklisted_count
    );
}

#[tokio::test]
async fn test_blacklist_block_strategy() {
    let _ = env_logger::builder().is_test(true).try_init();
    let upstream_port = 25006;
    start_mock_upstream(upstream_port).await;

    let proxy_port = 25007;

    let config_content = format!(
        "[server]\nbind_addr = \"127.0.0.1:{}\"\ndefault_upstream = \"127.0.0.1:{}\"\ntrusted_proxies = [[\"127.0.0.1/32\", \"X-Forwarded-For\"]]

[security]\nenabled = true
blacklist_size = 1
blacklist_strategy = \"block\"

[auth]\ntotp_secret = \"{}\"\n",
        proxy_port, upstream_port, TEST_SECRET
    );

    let config_filename = format!("test_config_{}.toml", proxy_port);
    let _config_file = TestFile::new(&config_filename, &config_content);

    let config_path = format!("target/tmp/{}", config_filename);
    thread::spawn(move || {
        let app = App::new(config_path);
        app.run();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let client = Client::new();
    let base_url = format!("http://127.0.0.1:{}", proxy_port);
    let auth_url = format!("{}/auth", base_url);

    for _ in 0..5 {
        client
            .post(&auth_url)
            .form(&[("code", "000000")])
            .header("X-Forwarded-For", "1.1.1.1")
            .send()
            .await
            .unwrap();
    }
    let resp = client
        .get(&base_url)
        .header("X-Forwarded-For", "1.1.1.1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "IP 1.1.1.1 should be blacklisted");

    for _ in 0..5 {
        client
            .post(&auth_url)
            .form(&[("code", "000000")])
            .header("X-Forwarded-For", "2.2.2.2")
            .send()
            .await
            .unwrap();
    }
    let resp = client
        .get(&base_url)
        .header("X-Forwarded-For", "2.2.2.2")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "IP 2.2.2.2 should NOT be blacklisted");

    let resp = client
        .get(&base_url)
        .header("X-Forwarded-For", "1.1.1.1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "IP 1.1.1.1 should still be blacklisted");
}