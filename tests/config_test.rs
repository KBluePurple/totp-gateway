use std::fs;
use std::path::Path;
use totp_gateway::config::load_config;

#[test]
fn test_config_generation() {
    // Create target/tmp directory if it doesn't exist
    let tmp_dir = Path::new("target/tmp");
    fs::create_dir_all(tmp_dir).unwrap();

    let config_path = "target/tmp/test_gen_config.toml";
    let path = Path::new(config_path);

    if path.exists() {
        fs::remove_file(path).unwrap();
    }

    let config = load_config(path).expect("Failed to load/generate config");

    assert!(path.exists(), "Config file should have been created");

    let content = fs::read_to_string(path).unwrap();
    assert!(content.contains("[server]"));
    assert!(content.contains("[auth]"));

    assert_eq!(config.server.bind_addr, "0.0.0.0:25000");
    assert!(config.auth.totp_secret.is_some());

    fs::remove_file(path).unwrap();
}