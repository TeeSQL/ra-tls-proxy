use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ra_tls_proxy::{run_proxy, ProxyConfig};
use rustls::RootCertStore;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

/// Install the `ring` CryptoProvider once for the whole test binary.
/// Both the proxy (via `ra-tls-proxy`) and the test TLS client need this.
fn install_crypto_provider() {
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ---------------------------------------------------------------------------
// Test 1: Default config has expected listen/backend addrs
// ---------------------------------------------------------------------------

#[test]
fn default_config_addrs() {
    let config = ProxyConfig::default();
    let expected_listen: SocketAddr = "0.0.0.0:5433".parse().unwrap();
    let expected_backend: SocketAddr = "127.0.0.1:5432".parse().unwrap();
    assert_eq!(config.listen_addr, expected_listen);
    assert_eq!(config.backend_addr, expected_backend);
}

// ---------------------------------------------------------------------------
// Test 2: run_proxy returns an error when given empty/invalid PEM
// ---------------------------------------------------------------------------

#[tokio::test]
async fn run_proxy_empty_pem_returns_error() {
    install_crypto_provider();
    let config = ProxyConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        backend_addr: "127.0.0.1:9999".parse().unwrap(),
        server_key_pem: String::new(),
        server_cert_chain_pem: vec![],
        require_client_cert: false,
    };
    let result = run_proxy(config).await;
    assert!(result.is_err(), "expected error for empty PEM");
}

// ---------------------------------------------------------------------------
// Test 3: Server-only TLS with echo backend
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_only_tls_echo() {
    install_crypto_provider();

    // Generate a self-signed cert for "localhost"
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let server_cert_pem = cert.cert.pem();
    let server_key_pem = cert.key_pair.serialize_pem();
    let server_cert_der = cert.cert.der().clone();

    // Start a plain TCP echo server on a random port
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = echo_listener.accept().await.unwrap();
        let (mut r, mut w) = conn.split();
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    // Start the proxy on a random port, no client cert required
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    // Drop the listener so run_proxy can bind the same port
    drop(proxy_listener);

    let config = ProxyConfig {
        listen_addr: proxy_addr,
        backend_addr: echo_addr,
        server_key_pem: server_key_pem.clone(),
        server_cert_chain_pem: vec![server_cert_pem.clone()],
        require_client_cert: false,
    };
    tokio::spawn(run_proxy(config));

    // Give the proxy a moment to bind
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Build a TLS client that trusts our self-signed cert
    let mut root_store = RootCertStore::empty();
    root_store.add(server_cert_der.clone()).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

    tls_stream.write_all(b"hello\n").await.unwrap();
    // Shutdown the write side so the echo server knows to stop and the copy
    // terminates, allowing us to read the full reply.
    tls_stream.shutdown().await.unwrap();

    let mut buf = Vec::new();
    tls_stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"hello\n");
}

// ---------------------------------------------------------------------------
// Test 4: Invalid key PEM returns Err
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_key_pem_returns_error() {
    install_crypto_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let server_cert_pem = cert.cert.pem();

    let config = ProxyConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        backend_addr: "127.0.0.1:9999".parse().unwrap(),
        server_key_pem: "not a valid pem key".to_string(),
        server_cert_chain_pem: vec![server_cert_pem],
        require_client_cert: false,
    };
    let result = run_proxy(config).await;
    assert!(result.is_err(), "expected error for invalid key PEM");
    let msg = format!("{:#}", result.unwrap_err());
    assert!(
        msg.contains("private key") || msg.contains("PEM") || msg.contains("key"),
        "unexpected error message: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Invalid cert PEM returns Err
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_cert_pem_returns_error() {
    install_crypto_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let server_key_pem = cert.key_pair.serialize_pem();

    let config = ProxyConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        backend_addr: "127.0.0.1:9999".parse().unwrap(),
        server_key_pem,
        server_cert_chain_pem: vec!["not a valid cert pem".to_string()],
        require_client_cert: false,
    };
    let result = run_proxy(config).await;
    assert!(result.is_err(), "expected error for invalid cert PEM");
    let msg = format!("{:#}", result.unwrap_err());
    assert!(
        msg.contains("certificate") || msg.contains("cert") || msg.contains("PEM"),
        "unexpected error message: {msg}"
    );
}
