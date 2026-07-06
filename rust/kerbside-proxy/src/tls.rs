//! TLS acceptor construction for the secure SPICE listener.
//!
//! Loads a PEM certificate chain and private key and builds a
//! `tokio_rustls::TlsAcceptor` configured for the server role with no client
//! auth. This mirrors the PEM-load idiom ryll's `src/web/server.rs` uses via
//! `RustlsConfig::from_pem_file`, but builds a raw `rustls::ServerConfig`
//! directly: this proxy terminates the SPICE wire protocol over TLS, not
//! HTTP, so there is no axum-server layer to delegate the load to.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

/// Load the proxy's TLS host certificate chain and private key and build a
/// `TlsAcceptor` for the secure SPICE listener.
///
/// The process-wide rustls crypto provider (ring) must already be installed
/// before calling this (done once in `main`); `ServerConfig::builder()`
/// resolves to that default provider.
///
/// # Errors
///
/// Returns a clear, path-annotated error if either file cannot be read or
/// parsed, if the cert file contains no certificates, or if no private key
/// is found in the key file.
pub fn load_acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    if certs.is_empty() {
        bail!(
            "no certificates found in TLS cert file {}",
            cert_path.display()
        );
    }

    let key = load_key(key_path)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| {
            format!(
                "building TLS server config from cert {} / key {}",
                cert_path.display(),
                key_path.display()
            )
        })?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Read and parse a PEM certificate chain.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("opening TLS cert file {}", path.display()))?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing TLS cert file {}", path.display()))
}

/// Read and parse a single PEM private key (PKCS#1, PKCS#8, or SEC1).
fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file =
        File::open(path).with_context(|| format!("opening TLS key file {}", path.display()))?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parsing TLS key file {}", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in TLS key file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed cert/key pair (generated with rcgen) round-trips
    /// through `load_acceptor` without error.
    #[test]
    fn load_acceptor_from_self_signed_cert() {
        // The ring provider must be installed before building any TLS
        // config; idempotent via `let _`, mirroring main.rs.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed cert");

        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");

        let result = load_acceptor(&cert_path, &key_path);
        assert!(result.is_ok(), "load_acceptor failed: {:?}", result.err());
    }

    /// A missing cert file produces a clear, path-annotated error rather
    /// than a panic.
    #[test]
    fn load_acceptor_missing_cert_file_errors_clearly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("missing-cert.pem");
        let key_path = dir.path().join("missing-key.pem");

        // Use .err() rather than expect_err: the Ok type (TlsAcceptor) is not
        // Debug, which expect_err would require.
        let err = load_acceptor(&cert_path, &key_path)
            .err()
            .expect("expected an error for a missing cert file");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing-cert.pem"),
            "error should mention the cert path: {msg}"
        );
    }
}
