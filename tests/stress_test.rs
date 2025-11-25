use reqwest::Client;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use totp_gateway::App;

async fn start_silent_upstream(port: u16) {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await.unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0; 1024];
                    let _ = socket.read(&mut buf).await;
                    let response =
                        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });
}

#[tokio::test]
async fn test_brute_force_blacklist() {
    let proxy_port = 25010;
    let upstream_port = 25011;

    start_silent_upstream(upstream_port).await;

    // Create target/tmp directory if it doesn't exist
    let tmp_dir = Path::new("target/tmp");
    fs::create_dir_all(tmp_dir).unwrap();

    // Start App
    let config_content = format!(
        r#"
[server]
bind_addr = "127.0.0.1:{}"
default_upstream = "127.0.0.1:{}"
trusted_proxies = [["127.0.0.1/32", "X-Forwarded-For"]]

[security]
enabled = true
blacklist_size = 100

[auth]
totp_secret = "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU"

[[routes]]
path_prefix = "/"
upstream_addr = "127.0.0.1:{}"
"#,
        proxy_port, upstream_port, upstream_port
    );

    let config_path = format!("target/tmp/stress_config_{}.toml", proxy_port);
    let mut file = fs::File::create(&config_path).unwrap();
    file.write_all(config_content.as_bytes()).unwrap();

    let path_for_thread = config_path.clone();
    thread::spawn(move || {
        let app = App::new(path_for_thread);
        app.run();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let client = Client::new();
    let url = format!("http://127.0.0.1:{}/auth", proxy_port);

    for i in 1..=4 {
        let params = [("code", "000000")];
        let resp = client
            .post(&url)
            .form(&params)
            .send()
            .await
            .expect("Failed to send request");

        assert_eq!(resp.status(), 200, "Attempt {} should be allowed", i);
        assert!(resp.url().query().unwrap_or("").contains("error=1"));
    }

    let params = [("code", "000000")];
    let resp = client
        .post(&url)
        .form(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        resp.status(),
        429,
        "IP should be blacklisted on 5th attempt"
    );

    let _ = fs::remove_file(config_path);
}

#[tokio::test]
async fn test_ddos_simulation() {
    let proxy_port = 25020;
    let upstream_port = 25021;

    start_silent_upstream(upstream_port).await;

    // Create target/tmp directory if it doesn't exist
    let tmp_dir = Path::new("target/tmp");
    fs::create_dir_all(tmp_dir).unwrap();

    let config_content = format!(
        r#"
[server]
bind_addr = "127.0.0.1:{}"
default_upstream = "127.0.0.1:{}"
trusted_proxies = [["127.0.0.1/32", "X-Forwarded-For"]]

[auth]
totp_secret = "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU"

[[routes]]
path_prefix = "/"
upstream_addr = "127.0.0.1:{}"
"#,
        proxy_port, upstream_port, upstream_port
    );

    let config_path = format!("target/tmp/stress_config_{}.toml", proxy_port);
    let mut file = fs::File::create(&config_path).unwrap();
    file.write_all(config_content.as_bytes()).unwrap();

    let path_for_thread = config_path.clone();
    thread::spawn(move || {
        let app = App::new(path_for_thread);
        app.run();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let client = Client::new();
    let url = format!("http://127.0.0.1:{}", proxy_port);

    let mut tasks = vec![];
    for i in 0..100 {
        let client = client.clone();
        let url = url.clone();

        let task = tokio::spawn(async move {
            let ip = format!("10.0.0.{}", i % 255);

            let resp = client.get(&url).header("X-Forwarded-For", ip).send().await;

            match resp {
                Ok(r) => r.status().as_u16(),
                Err(_) => 0,
            }
        });
        tasks.push(task);
    }

    let mut success_count = 0;
    for task in tasks {
        if let Ok(status) = task.await {
            if status == 200 {
                success_count += 1;
            }
        }
    }

    println!("DDoS Simulation: {}/100 requests succeeded", success_count);

    assert!(
        success_count > 90,
        "Server should handle concurrent requests under load"
    );

    let _ = fs::remove_file(config_path);
}