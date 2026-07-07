//! Certificate authority and leaf certificate generation.
//!
//! At startup the proxy generates a self-signed CA. For each allowlisted
//! domain it then signs a leaf certificate so the client (which trusts the
//! CA) sees a valid chain while the proxy performs MITM TLS.
//!
//! Carried over from ae-egress-proxy (Spike 1) unchanged — the cert path
//! was validated there.

use std::sync::Arc;

use rcgen::{CertificateParams, CertifiedIssuer, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ResolvesServerCertUsingSni;
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("rcgen key generation failed: {0}")]
    KeyGen(String),
    #[error("rcgen CA certificate generation failed: {0}")]
    CaGen(String),
    #[error("rcgen leaf certificate generation failed: {0}")]
    LeafGen(String),
    #[error("rustls key import failed: {0}")]
    KeyImport(String),
    #[error("rustls server config build failed: {0}")]
    ServerConfig(String),
}

/// A self-generated CA plus its DER-encoded certificate (for export to PEM).
pub struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
    pub ca_der: CertificateDer<'static>,
}

impl Ca {
    pub fn generate() -> Result<Self, CertError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| CertError::KeyGen(e.to_string()))?;

        let mut params = CertificateParams::new(Vec::new())
            .map_err(|e| CertError::CaGen(e.to_string()))?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "ae-poc MITM CA");
            dn.push(DnType::OrganizationName, "mintybasil");
            dn
        };
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after =
            time::OffsetDateTime::now_utc().checked_add(time::Duration::days(3650)).unwrap();

        let issuer =
            CertifiedIssuer::self_signed(params, key).map_err(|e| CertError::CaGen(e.to_string()))?;
        let ca_der = issuer.as_ref().der().clone();

        Ok(Self { issuer, ca_der })
    }

    pub fn ca_pem(&self) -> String {
        pem::encode(&pem::Pem::new("CERTIFICATE", self.ca_der.as_ref().to_vec()))
    }

    fn sign_leaf(&self, hostname: &str) -> Result<CertifiedKey, CertError> {
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| CertError::KeyGen(e.to_string()))?;

        let mut params = CertificateParams::new(vec![hostname.to_string()])
            .map_err(|e| CertError::LeafGen(e.to_string()))?;
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, hostname);
            dn
        };
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
        params.not_after =
            time::OffsetDateTime::now_utc().checked_add(time::Duration::days(7)).unwrap();

        let leaf = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|e| CertError::LeafGen(e.to_string()))?;

        let cert_der: CertificateDer<'static> = leaf.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| CertError::KeyImport(e.to_string()))?;

        Ok(CertifiedKey::new(vec![cert_der], signing_key))
    }

    pub fn server_config(&self, allowlist: &[String]) -> Result<Arc<ServerConfig>, CertError> {
        let mut resolver = ResolvesServerCertUsingSni::new();
        for host in allowlist {
            let ck = self.sign_leaf(host)?;
            resolver
                .add(host.as_str(), ck)
                .map_err(|e| CertError::ServerConfig(format!("SNI resolver add {host}: {e:?}")))?;
        }
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        Ok(Arc::new(config))
    }

    pub fn upstream_client_config() -> Result<Arc<rustls::ClientConfig>, CertError> {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    pub fn upstream_client_config_no_verify() -> Result<Arc<rustls::ClientConfig>, CertError> {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        Ok(Arc::new(config))
    }
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}