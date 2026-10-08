#[allow(dead_code)]
#[path = "support/tls_fixtures.rs"]
mod tls_fixtures;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use h2::server;
use http::Response;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tiana_sdk::{Client, ConnectError, Protocol};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

const AUTHORITY: &[u8] =
    include_bytes!("../conformance/v1/fixtures/gateway/public-connect-authority-v1.json");
const ENDPOINT_ID: &str = "ep-01j5c9m7q2v8x4k6n3r0t1w2yz";

fn authority_suffix() -> &'static str {
    let authority = std::str::from_utf8(AUTHORITY).expect("authority fixture must be UTF-8");
    authority
        .split_once("\"endpoint_suffix\": \"")
        .and_then(|(_, value)| value.split_once('"'))
        .map(|(value, _)| value)
        .expect("authority suffix field")
}

fn authority_port() -> u16 {
    let authority = std::str::from_utf8(AUTHORITY).expect("authority fixture must be UTF-8");
    authority
        .split_once("\"default_port\": ")
        .and_then(|(_, value)| value.split_whitespace().next())
        .and_then(|value| value.trim_end_matches(',').parse().ok())
        .expect("authority port field")
}

fn endpoint_hostname() -> String {
    format!("{ENDPOINT_ID}{}", authority_suffix())
}

fn endpoint_authority() -> String {
    format!("{}:{}", endpoint_hostname(), authority_port())
}

#[derive(Debug)]
struct Observation {
    request_id: String,
    protocol: Option<String>,
    sni: Option<String>,
    authority: Option<String>,
}

struct TestGateway {
    address: String,
    certificate_der: Vec<u8>,
    observation: oneshot::Receiver<Observation>,
}

async fn start_gateway(certificate_name: &str) -> TestGateway {
    let (certificate_fixture, key_fixture) = match certificate_name {
        tls_fixtures::WILDCARD_NAME => (
            tls_fixtures::WILDCARD_CERTIFICATE_DER_B64,
            tls_fixtures::WILDCARD_KEY_DER_B64,
        ),
        tls_fixtures::WRONG_NAME => (
            tls_fixtures::WRONG_CERTIFICATE_DER_B64,
            tls_fixtures::WRONG_KEY_DER_B64,
        ),
        other => panic!("no static TLS fixture for certificate name {other}"),
    };
    let certificate_der = tls_fixtures::decode(certificate_fixture);
    let certificate = CertificateDer::from(certificate_der.clone());
    let private_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls_fixtures::decode(key_fixture)));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let (observation_tx, observation) = oneshot::channel();
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(tls_stream) = TlsAcceptor::from(Arc::new(tls)).accept(stream).await else {
            return;
        };
        let sni = tls_stream.get_ref().1.server_name().map(str::to_owned);
        let Ok(mut h2) = server::handshake(tls_stream).await else {
            return;
        };
        let Some(Ok((request, mut respond))) = h2.accept().await else {
            return;
        };
        let protocol = request
            .headers()
            .get("tiana-database-protocol")
            .map(|v| v.to_str().unwrap().to_owned());
        let authority = request.uri().authority().map(ToString::to_string);
        let request_id = request.headers().get("tiana-request-id").cloned().unwrap();
        let response = Response::builder()
            .status(200)
            .header("tiana-tunnel-version", "1")
            .header("tiana-auth-mode", "DISABLED")
            .header("tiana-request-id", &request_id)
            .body(())
            .unwrap();
        let _ = respond.send_response(response, true);
        let _ = observation_tx.send(Observation {
            request_id: request_id.to_str().unwrap().to_owned(),
            sni,
            authority,
            protocol,
        });
        // Keep polling the H2 connection so the successful HEADERS are
        // flushed. Dropping it here would synthesize an unrelated TLS
        // unexpected-EOF while the client is still receiving them.
        while h2.accept().await.is_some() {}
    });

    TestGateway {
        address,
        certificate_der,
        observation,
    }
}

fn pem(der: &[u8]) -> Vec<u8> {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        STANDARD.encode(der)
    )
    .into_bytes()
}

#[test]
fn invalid_pem_fails_even_with_public_roots_enabled() {
    let good = pem(&tls_fixtures::decode(
        tls_fixtures::WILDCARD_CERTIFICATE_DER_B64,
    ));
    let malformed = b"-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n".to_vec();
    let mixed = [good.clone(), malformed.clone()].concat();
    for input in [
        Vec::new(),
        b"not a certificate".to_vec(),
        malformed,
        mixed,
        pem(b"not an X509 certificate"),
        [good, pem(b"invalid second certificate")].concat(),
        b"-----BEGIN CERTIFICATE-----\nYWJj\n".to_vec(),
        tls_fixtures::decode(tls_fixtures::WILDCARD_CERTIFICATE_DER_B64),
    ] {
        assert!(matches!(
            Client::builder(endpoint_hostname())
                .add_root_certificates_pem(input)
                .build(),
            Err(ConnectError::InvalidRootCertificate)
        ));
    }
}

#[tokio::test]
async fn self_signed_wildcard_keeps_logical_sni_and_authority() {
    let endpoint = endpoint_hostname();
    let wildcard = format!("*{}", authority_suffix());
    let gateway = start_gateway(&wildcard).await;
    let client = Client::builder(&endpoint)
        .gateway_address(&gateway.address)
        .use_webpki_roots(false)
        .add_root_certificates_pem(
            [
                pem(&tls_fixtures::decode(
                    tls_fixtures::UNRELATED_CERTIFICATE_DER_B64,
                )),
                String::from_utf8(pem(&gateway.certificate_der))
                    .unwrap()
                    .replace('\n', "\r\n")
                    .into_bytes(),
            ]
            .concat(),
        )
        .build()
        .unwrap();
    let _tunnel = client
        .connect(Protocol::new("echo-http").unwrap())
        .await
        .unwrap();
    let observation = gateway.observation.await.unwrap();
    assert_eq!(observation.sni.as_deref(), Some(endpoint.as_str()));
    let expected_authority = endpoint_authority();
    assert_eq!(
        observation.authority.as_deref(),
        Some(expected_authority.as_str())
    );
}

#[tokio::test]
async fn custom_profile_uses_with_logical_endpoint_identity() {
    let endpoint = endpoint_hostname();
    let gateway = start_gateway(tls_fixtures::WILDCARD_NAME).await;
    let client = Client::builder(format!("{endpoint}:30080"))
        .gateway_address(&gateway.address)
        .use_webpki_roots(false)
        .add_root_certificate_der(gateway.certificate_der)
        .build()
        .unwrap();
    let mut observed_id = String::new();
    let tunnel = client
        .connect_with_diagnostic(Protocol::new("echo").unwrap(), |id| {
            observed_id = id.to_owned();
            panic!("diagnostic observer failure");
        })
        .await
        .unwrap();
    assert!(!observed_id.is_empty());
    assert_eq!(observed_id, tunnel.request_id());
    let observation = gateway.observation.await.unwrap();
    assert_eq!(observation.request_id, observed_id);
    assert_eq!(observation.protocol.as_deref(), Some("echo"));
    assert_eq!(observation.sni.as_deref(), Some(endpoint.as_str()));
    assert_eq!(
        observation.authority.as_deref(),
        Some(endpoint_authority().as_str())
    );
}

#[tokio::test]
async fn trusted_self_signed_certificate_with_wrong_name_is_rejected() {
    let endpoint = endpoint_hostname();
    let gateway = start_gateway("*.wrong.internal.tiana.com").await;
    let client = Client::builder(&endpoint)
        .gateway_address(&gateway.address)
        .use_webpki_roots(false)
        .add_root_certificates_pem(pem(&gateway.certificate_der))
        .build()
        .unwrap();
    let mut observed_id = String::new();
    assert!(matches!(
        client
            .connect_with_diagnostic(Protocol::new("echo-http").unwrap(), |id| observed_id =
                id.to_owned())
            .await,
        Err(ConnectError::Tls(_))
    ));
    assert!(!observed_id.is_empty());
}

#[tokio::test]
async fn unknown_self_signed_wildcard_is_rejected() {
    let endpoint = endpoint_hostname();
    let gateway = start_gateway(tls_fixtures::WILDCARD_NAME).await;
    let client = Client::builder(&endpoint)
        .gateway_address(&gateway.address)
        .use_webpki_roots(false)
        .add_root_certificates_pem(pem(&tls_fixtures::decode(
            tls_fixtures::UNRELATED_CERTIFICATE_DER_B64,
        )))
        .build()
        .unwrap();
    assert!(matches!(
        client.connect(Protocol::new("echo-http").unwrap()).await,
        Err(ConnectError::Tls(_))
    ));
}

#[test]
fn gateway_override_requires_host_port_and_at_least_one_root() {
    let endpoint = endpoint_hostname();
    for address in ["https://127.0.0.1:443", "127.0.0.1", "127.0.0.1:0"] {
        assert!(
            Client::builder(&endpoint)
                .gateway_address(address)
                .build()
                .is_err()
        );
    }
    assert!(
        Client::builder(&endpoint)
            .use_webpki_roots(false)
            .build()
            .is_err()
    );
}

#[cfg(feature = "internal-debug-tls")]
#[tokio::test]
async fn insecure_tls_accepts_untrusted_wrong_name_and_preserves_routing() {
    let endpoint = endpoint_hostname();
    let gateway = start_gateway(tls_fixtures::WRONG_NAME).await;
    let client = Client::builder(&endpoint)
        .gateway_address(&gateway.address)
        .use_webpki_roots(false)
        .insecure_tls(true)
        .build()
        .unwrap();
    let _tunnel = client
        .connect(Protocol::new("echo-http").unwrap())
        .await
        .unwrap();
    let observation = gateway.observation.await.unwrap();
    assert_eq!(observation.sni.as_deref(), Some(endpoint.as_str()));
    assert_eq!(
        observation.authority.as_deref(),
        Some(endpoint_authority().as_str())
    );
}

#[cfg(not(feature = "internal-debug-tls"))]
#[test]
fn release_build_rejects_insecure_tls() {
    assert!(matches!(
        Client::builder(endpoint_hostname())
            .insecure_tls(true)
            .build(),
        Err(ConnectError::Tls(_))
    ));
}
