use crate::net::CertificateInput;
use rustls::{
    client::{ServerCertVerified, ServerCertVerifier, WebPkiVerifier},
    ClientConfig, Error as TlsError, OwnedTrustAnchor, RootCertStore, ServerName,
};
use std::io::{BufReader, Cursor};
use std::sync::Arc;
use std::time::SystemTime;

use crate::error::Error;

pub async fn configure_tls_connector(
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
    root_cert_path: Option<&CertificateInput>,
    client_cert_path: Option<&CertificateInput>,
    client_key_path: Option<&CertificateInput>,
) -> Result<sqlx_rt::TlsConnector, Error> {
    let config = ClientConfig::builder().with_safe_defaults();

    let config = if accept_invalid_certs {
        config
            .with_custom_certificate_verifier(Arc::new(DummyTlsVerifier))
            .with_no_client_auth()
    } else {
        let mut cert_store = RootCertStore::empty();
        cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        if let Some(ca) = root_cert_path {
            let data = ca.data().await?;
            let mut cursor = Cursor::new(data);

            for cert in rustls_pemfile::certs(&mut cursor)
                .map_err(|_| Error::Tls(format!("Invalid certificate {}", ca).into()))?
            {
                cert_store
                    .add(&rustls::Certificate(cert))
                    .map_err(|err| Error::Tls(err.into()))?;
            }
        }

        if let (Some(cert), Some(key)) = (client_cert_path, client_key_path) {
            let key_data = key.data().await?;
            let cert_data = cert.data().await?;
            let certs = to_certs(cert_data);
            let key = to_private_key(key_data)?;
            match config.set_single_client_cert(certs, key) {
                Ok(_) => (),
                Err(err) => {
                    return Err(Error::Configuration(
                        format!("no keys found in: {:?}", err).into(),
                    ))
                }
            }
        }

        if accept_invalid_hostnames {
            let verifier = WebPkiVerifier::new(cert_store, None);

            config
                .with_custom_certificate_verifier(Arc::new(NoHostnameTlsVerifier { verifier }))
                .with_no_client_auth()
        } else {
            config
                .with_root_certificates(cert_store)
                .with_no_client_auth()
        }
    };

    Ok(Arc::new(config).into())
}

struct DummyTlsVerifier;

impl ServerCertVerifier for DummyTlsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }
}

pub struct NoHostnameTlsVerifier {
    verifier: WebPkiVerifier,
}

impl ServerCertVerifier for NoHostnameTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match self.verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            scts,
            ocsp_response,
            now,
        ) {
            Err(TlsError::InvalidCertificateData(reason))
                if reason.contains("CertNotValidForName") =>
            {
                Ok(ServerCertVerified::assertion())
            }
            res => res,
        }
    }
}

fn to_certs(pem: Vec<u8>) -> Vec<rustls::Certificate> {
    let cur = Cursor::new(pem);
    let mut reader = BufReader::new(cur);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn to_private_key(pem: Vec<u8>) -> Result<rustls::PrivateKey, Error> {
    let cur = Cursor::new(pem);
    let mut reader = BufReader::new(cur);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(rustls::PrivateKey(key)),
            None => break,
            _ => {}
        }
    }

    Err(Error::Configuration("no keys found pem file".into()))
}
