// Spec: docs/specs/open-source-libs.md

//! Mutual RA-TLS TCP proxy.
//!
//! Listens on a TCP address, terminates TLS using a server RA-TLS certificate,
//! optionally requires client RA-TLS certificates (mutual TLS), and forwards
//! the decrypted stream to a backend address.
//!
//! In RA-TLS, both the server and client certificates are self-signed X.509
//! certs with a TDX attestation quote embedded in a custom extension. The
//! actual quote verification is done by the caller before constructing the
//! [`ProxyConfig`] — this crate handles only the TLS termination and forwarding.
//!
//! # Example
//!
//! ```no_run
//! use ra_tls_proxy::{ProxyConfig, run_proxy};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = ProxyConfig {
//!         listen_addr: "0.0.0.0:5433".parse()?,
//!         backend_addr: "127.0.0.1:5432".parse()?,
//!         server_key_pem: std::fs::read_to_string("server.key")?,
//!         server_cert_chain_pem: vec![std::fs::read_to_string("server.crt")?],
//!         require_client_cert: true,
//!     };
//!     run_proxy(config).await
//! }
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Configuration for the RA-TLS proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// TCP address to listen on.
    pub listen_addr: SocketAddr,
    /// Backend TCP address to forward accepted connections to.
    pub backend_addr: SocketAddr,
    /// Server private key in PEM format (PKCS#8, SEC1, or PKCS#1).
    pub server_key_pem: String,
    /// Server certificate chain in PEM format. One PEM string per cert,
    /// ordered leaf → intermediate → root (standard TLS chain order).
    pub server_cert_chain_pem: Vec<String>,
    /// When `true`, clients must present a valid certificate signed by the
    /// same CA as the server cert (mutual TLS / mTLS). Default: `true`.
    pub require_client_cert: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:5433".parse().expect("valid default addr"),
            backend_addr: "127.0.0.1:5432".parse().expect("valid default addr"),
            server_key_pem: String::new(),
            server_cert_chain_pem: Vec::new(),
            require_client_cert: true,
        }
    }
}

/// Run the RA-TLS proxy.
///
/// Binds to `config.listen_addr`, accepts TLS connections using the provided
/// server certificate, and forwards each connection to `config.backend_addr`.
/// Each connection is handled in a new `tokio::task`.
///
/// This function runs indefinitely until the listener is closed or an
/// unrecoverable error occurs on `accept()`.
///
/// # Errors
///
/// Returns an error if:
/// - The PEM key or certificate chain cannot be parsed.
/// - The TLS configuration cannot be built.
/// - Binding to `listen_addr` fails.
pub async fn run_proxy(config: ProxyConfig) -> Result<()> {
    let all_pem = config.server_cert_chain_pem.join("\n");
    let certs = ra_tls_parse::parse_certificates(&all_pem)
        .context("failed to parse server certificate chain")?;
    let private_key = ra_tls_parse::parse_private_key(&config.server_key_pem)
        .context("failed to parse server private key")?;

    let tls_config = build_tls_config(certs, private_key, config.require_client_cert)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("failed to bind to {}", config.listen_addr))?;

    tracing::info!(addr = %config.listen_addr, "RA-TLS proxy listening");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let backend_addr = config.backend_addr;

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = proxy_to_backend(tls_stream, backend_addr).await {
                        tracing::debug!(peer = %peer_addr, error = %e, "proxy connection ended");
                    }
                }
                Err(e) => {
                    tracing::warn!(peer = %peer_addr, error = %e, "TLS handshake failed");
                }
            }
        });
    }
}

fn build_tls_config(
    certs: Vec<rustls_pki_types::CertificateDer<'static>>,
    private_key: rustls_pki_types::PrivateKeyDer<'static>,
    require_client_cert: bool,
) -> Result<rustls::ServerConfig> {
    if require_client_cert {
        let root_store = ra_tls_parse::build_root_store(&certs)
            .context("failed to build root cert store for client verification")?;
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .context("failed to build client certificate verifier")?;
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, private_key)
            .context("failed to build mTLS ServerConfig")
    } else {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .context("failed to build TLS ServerConfig")
    }
}

async fn proxy_to_backend(
    mut tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    backend_addr: SocketAddr,
) -> Result<()> {
    let mut backend = TcpStream::connect(backend_addr)
        .await
        .with_context(|| format!("failed to connect to backend at {backend_addr}"))?;

    // copy_bidirectional runs both directions concurrently and returns only
    // when both sides have reached EOF. It properly propagates half-close so
    // that the TLS write side sends close_notify before the task exits.
    tokio::io::copy_bidirectional(&mut tls_stream, &mut backend)
        .await
        .context("bidirectional copy failed")?;

    Ok(())
}
