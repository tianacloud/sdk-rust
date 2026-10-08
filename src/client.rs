use crate::error::{ConnectError, GatewayError};
use crate::protocol::{AuthMode, Endpoint, Protocol, SecretToken};
use crate::tunnel::Tunnel;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use h2::client::{Connection, SendRequest};
use http::header::{HeaderName, HeaderValue, PROXY_AUTHORIZATION, USER_AGENT};
use http::uri::Authority;
use http::{Method, Request, StatusCode, Uri};
#[cfg(feature = "internal-debug-tls")]
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
#[cfg(feature = "internal-debug-tls")]
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
#[cfg(feature = "internal-debug-tls")]
use rustls::pki_types::UnixTime;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
#[cfg(feature = "internal-debug-tls")]
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::future::poll_fn;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const ERROR_BODY_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

const TUNNEL_VERSION: HeaderName = HeaderName::from_static("tiana-tunnel-version");
const DATABASE_PROTOCOL: HeaderName = HeaderName::from_static("tiana-database-protocol");
const REQUEST_ID: HeaderName = HeaderName::from_static("tiana-request-id");
const AUTH_MODE: HeaderName = HeaderName::from_static("tiana-auth-mode");
const ERROR_CODE: HeaderName = HeaderName::from_static("tiana-error-code");
const RETRY_AFTER_MS: HeaderName = HeaderName::from_static("tiana-retry-after-ms");

/// A cloneable client. Clones share one HTTP/2 physical connection for this
/// exact Endpoint, credential, and TLS trust configuration.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    pub fn new(endpoint: impl AsRef<str>) -> Result<Self, ConnectError> {
        Self::builder(endpoint).build()
    }

    pub fn builder(endpoint: impl AsRef<str>) -> ClientBuilder {
        ClientBuilder::new(endpoint.as_ref().to_owned())
    }

    /// Opens one HTTP/2 CONNECT stream and returns a transparent application
    /// byte stream. No application bytes are sent before the successful response.
    pub async fn connect(&self, protocol: Protocol) -> Result<Tunnel, ConnectError> {
        self.connect_with_diagnostic(protocol, |_| {}).await
    }

    /// Reports the logical connection ID before DNS/TCP/TLS and CONNECT I/O.
    /// The observer must return promptly. Its panic does not fail the connection.
    pub async fn connect_with_diagnostic(
        &self,
        protocol: Protocol,
        observer: impl FnOnce(&str),
    ) -> Result<Tunnel, ConnectError> {
        let request_id = generate_request_id()?;
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| observer(&request_id)));
        self.connect_once(protocol, &request_id).await
    }

    async fn connect_once(
        &self,
        protocol: Protocol,
        request_id: &str,
    ) -> Result<Tunnel, ConnectError> {
        let request = self.build_request(&protocol, request_id)?;
        let (response, send, generation) = self.open_stream(request).await?;
        let response = match timeout(self.inner.response_timeout, response).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                self.invalidate(generation).await;
                return Err(ConnectError::Http2(error.to_string()));
            }
            Err(_) => {
                self.invalidate(generation).await;
                return Err(ConnectError::Timeout("CONNECT response"));
            }
        };

        if response.status() != StatusCode::OK {
            let gateway_error = gateway_error(&response);
            let _ = timeout(
                ERROR_BODY_DRAIN_TIMEOUT,
                drain_error_body(response.into_body()),
            )
            .await;
            return Err(gateway_error.into());
        }

        let auth_mode = validate_success_headers(&response, request_id)?;
        Ok(Tunnel::new(
            send,
            response.into_body(),
            self.inner.endpoint.clone(),
            protocol,
            request_id.to_owned(),
            auth_mode,
        ))
    }

    fn build_request(
        &self,
        protocol: &Protocol,
        request_id: &str,
    ) -> Result<Request<()>, ConnectError> {
        let uri = Uri::builder()
            .authority(self.inner.endpoint.authority())
            .build()
            .map_err(|_| ConnectError::InvalidConfiguration("invalid Endpoint authority"))?;
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header(TUNNEL_VERSION, "1")
            .header(DATABASE_PROTOCOL, protocol.as_str())
            .header(REQUEST_ID, request_id)
            .body(())
            .map_err(|_| ConnectError::InvalidConfiguration("invalid CONNECT request"))?;

        if let Some(user_agent) = &self.inner.user_agent {
            request.headers_mut().insert(USER_AGENT, user_agent.clone());
        }
        if let Some(token) = &self.inner.token {
            let mut bearer =
                zeroize::Zeroizing::new(Vec::with_capacity(7 + token.as_bytes().len()));
            bearer.extend_from_slice(b"Bearer ");
            bearer.extend_from_slice(token.as_bytes());
            let mut value = HeaderValue::from_bytes(&bearer)
                .map_err(|_| ConnectError::InvalidConfiguration("invalid credential"))?;
            value.set_sensitive(true);
            request.headers_mut().insert(PROXY_AUTHORIZATION, value);
        }
        Ok(request)
    }

    async fn open_stream(
        &self,
        request: Request<()>,
    ) -> Result<(h2::client::ResponseFuture, h2::SendStream<Bytes>, u64), ConnectError> {
        let mut pool = self.inner.pool.lock().await;
        if pool.session.is_none() {
            let generation = pool.next_generation;
            pool.next_generation = pool.next_generation.wrapping_add(1).max(1);
            pool.session = Some(self.open_session(generation).await?);
        }
        let session = pool.session.as_mut().expect("session installed");
        let generation = session.generation;
        if let Err(error) = poll_fn(|context| session.sender.poll_ready(context)).await {
            pool.session.take();
            return Err(ConnectError::Http2(error.to_string()));
        }
        match session.sender.send_request(request, false) {
            Ok((response, send)) => Ok((response, send, generation)),
            Err(error) => {
                pool.session.take();
                Err(ConnectError::Http2(error.to_string()))
            }
        }
    }

    async fn open_session(&self, generation: u64) -> Result<Session, ConnectError> {
        let address = self
            .inner
            .gateway_address
            .as_deref()
            .unwrap_or_else(|| self.inner.endpoint.hostname());
        let address = if self.inner.gateway_address.is_some() {
            address.to_owned()
        } else {
            format!("{address}:{}", self.inner.endpoint.port())
        };
        let tcp = timeout(self.inner.connect_timeout, TcpStream::connect(&address))
            .await
            .map_err(|_| ConnectError::Timeout("TCP connect"))?
            .map_err(ConnectError::Tcp)?;
        tcp.set_nodelay(true).map_err(ConnectError::Tcp)?;

        let server_name = ServerName::try_from(self.inner.endpoint.hostname().to_owned())
            .map_err(|_| ConnectError::InvalidEndpoint)?;
        let tls = timeout(
            self.inner.connect_timeout,
            self.inner.tls_connector.connect(server_name, tcp),
        )
        .await
        .map_err(|_| ConnectError::Timeout("TLS handshake"))?
        .map_err(|error| ConnectError::Tls(error.to_string()))?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(ConnectError::Tls(
                "Gateway did not negotiate ALPN h2".to_owned(),
            ));
        }

        let mut builder = h2::client::Builder::new();
        builder.header_table_size(0);
        builder.max_header_list_size(16 * 1024);
        let (sender, connection): (SendRequest<Bytes>, Connection<_, Bytes>) =
            timeout(self.inner.connect_timeout, builder.handshake(tls))
                .await
                .map_err(|_| ConnectError::Timeout("HTTP/2 handshake"))?
                .map_err(|error| ConnectError::Http2(error.to_string()))?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Session {
            generation,
            sender,
            _driver: driver,
        })
    }

    async fn invalidate(&self, generation: u64) {
        let mut pool = self.inner.pool.lock().await;
        if pool
            .session
            .as_ref()
            .is_some_and(|session| session.generation == generation)
        {
            pool.session.take();
        }
    }
}

fn validate_success_headers(
    response: &http::Response<h2::RecvStream>,
    request_id: &str,
) -> Result<AuthMode, ConnectError> {
    let headers = response.headers();
    if headers.len() != 3
        || headers.get_all(&TUNNEL_VERSION).iter().count() != 1
        || headers.get_all(&AUTH_MODE).iter().count() != 1
        || headers.get_all(&REQUEST_ID).iter().count() != 1
    {
        return Err(ConnectError::InvalidResponse(
            "success header set is not closed",
        ));
    }
    if headers.get(&TUNNEL_VERSION).map(HeaderValue::as_bytes) != Some(b"1") {
        return Err(ConnectError::InvalidResponse("invalid tunnel version"));
    }
    if headers.get(&REQUEST_ID).map(HeaderValue::as_bytes) != Some(request_id.as_bytes()) {
        return Err(ConnectError::InvalidResponse("request ID mismatch"));
    }
    headers
        .get(&AUTH_MODE)
        .and_then(|value| AuthMode::parse(value.as_bytes()))
        .ok_or(ConnectError::InvalidResponse("invalid auth mode"))
}

fn gateway_error(response: &http::Response<h2::RecvStream>) -> GatewayError {
    let code = response
        .headers()
        .get(&ERROR_CODE)
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte == b'_' || byte.is_ascii_uppercase())
        })
        .map(str::to_owned);
    let retry_after = response
        .headers()
        .get(&RETRY_AFTER_MS)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=60_000).contains(value))
        .map(Duration::from_millis);
    GatewayError::new(response.status(), code, retry_after)
}

async fn drain_error_body(mut body: h2::RecvStream) {
    let mut received = 0_usize;
    while let Some(result) = body.data().await {
        let Ok(data) = result else {
            return;
        };
        received = received.saturating_add(data.len());
        let _ = body.flow_control().release_capacity(data.len());
        if received >= MAX_ERROR_BODY_BYTES {
            return;
        }
    }
}

fn generate_request_id() -> Result<String, ConnectError> {
    let mut random = [0_u8; 18];
    getrandom::fill(&mut random).map_err(|_| ConnectError::RandomSource)?;
    Ok(format!("req-{}", URL_SAFE_NO_PAD.encode(random)))
}

struct ClientInner {
    endpoint: Endpoint,
    gateway_address: Option<String>,
    token: Option<SecretToken>,
    user_agent: Option<HeaderValue>,
    tls_connector: TlsConnector,
    connect_timeout: Duration,
    response_timeout: Duration,
    pool: Mutex<PoolState>,
}

struct PoolState {
    next_generation: u64,
    session: Option<Session>,
}

struct Session {
    generation: u64,
    sender: SendRequest<Bytes>,
    // Dropping a JoinHandle detaches it. This is intentional: established
    // streams must survive removal of the sender after GOAWAY or a failed new
    // stream.
    _driver: JoinHandle<()>,
}

pub struct ClientBuilder {
    endpoint: String,
    gateway_address: Option<String>,
    token: Option<SecretToken>,
    user_agent: Option<String>,
    webpki_roots: bool,
    insecure_tls: bool,
    root_certificates: Vec<Vec<u8>>,
    root_certificate_bundles: Vec<Vec<u8>>,
    connect_timeout: Duration,
    response_timeout: Duration,
}

impl ClientBuilder {
    fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            gateway_address: None,
            token: None,
            user_agent: Some(format!("tiana-sdk/{}", env!("CARGO_PKG_VERSION"))),
            webpki_roots: true,
            insecure_tls: false,
            root_certificates: Vec::new(),
            root_certificate_bundles: Vec::new(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            response_timeout: DEFAULT_RESPONSE_TIMEOUT,
        }
    }

    /// Overrides only the TCP dial target. SNI and `:authority` remain the
    /// validated Endpoint hostname, which is useful for local integration.
    pub fn gateway_address(mut self, value: impl Into<String>) -> Self {
        self.gateway_address = Some(value.into());
        self
    }

    pub fn token(mut self, token: SecretToken) -> Self {
        self.token = Some(token);
        self
    }

    pub fn user_agent(mut self, value: impl Into<String>) -> Self {
        self.user_agent = Some(value.into());
        self
    }

    pub fn without_user_agent(mut self) -> Self {
        self.user_agent = None;
        self
    }

    pub fn use_webpki_roots(mut self, enabled: bool) -> Self {
        self.webpki_roots = enabled;
        self
    }

    /// Adds a PEM CA bundle containing one or more certificates.
    /// Empty or malformed bundles fail with InvalidRootCertificate at build time.
    /// Public roots remain enabled unless use_webpki_roots(false) is selected.
    pub fn add_root_certificates_pem(mut self, certificates: Vec<u8>) -> Self {
        self.root_certificate_bundles.push(certificates);
        self
    }

    /// Adds an already decoded DER certificate. CA files normally use PEM.
    pub fn add_root_certificate_der(mut self, certificate: Vec<u8>) -> Self {
        self.root_certificates.push(certificate);
        self
    }

    /// Disables server certificate and hostname verification for internal testing.
    /// TLS encryption and handshake signature verification remain enabled.
    /// Requires the non-distributable `internal-debug-tls` feature; default builds
    /// return an error from `build()` when this option is enabled.
    pub fn insecure_tls(mut self, enabled: bool) -> Self {
        self.insecure_tls = enabled;
        self
    }

    pub fn connect_timeout(mut self, value: Duration) -> Self {
        self.connect_timeout = value;
        self
    }

    pub fn response_timeout(mut self, value: Duration) -> Self {
        self.response_timeout = value;
        self
    }

    pub fn build(self) -> Result<Client, ConnectError> {
        let endpoint = Endpoint::parse(self.endpoint).map_err(|_| ConnectError::InvalidEndpoint)?;
        if let Some(value) = &self.gateway_address {
            let authority = value.parse::<Authority>().map_err(|_| {
                ConnectError::InvalidConfiguration(
                    "Gateway address must be host:port without a URL scheme",
                )
            })?;
            if authority.host().is_empty()
                || authority.port_u16().filter(|port| *port != 0).is_none()
            {
                return Err(ConnectError::InvalidConfiguration(
                    "Gateway address must include a valid port",
                ));
            }
        }
        if self.connect_timeout.is_zero() || self.response_timeout.is_zero() {
            return Err(ConnectError::InvalidConfiguration(
                "connection timeouts must be non-zero",
            ));
        }

        let user_agent = self
            .user_agent
            .map(|value| HeaderValue::from_str(&value).map_err(|_| ConnectError::InvalidUserAgent))
            .transpose()?;
        let mut roots = RootCertStore::empty();
        if self.webpki_roots {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        for certificate in self.root_certificates {
            roots
                .add(CertificateDer::from(certificate))
                .map_err(|_| ConnectError::InvalidRootCertificate)?;
        }
        for bundle in self.root_certificate_bundles {
            let mut found = false;
            for certificate in CertificateDer::pem_slice_iter(&bundle) {
                let certificate = certificate.map_err(|_| ConnectError::InvalidRootCertificate)?;
                roots
                    .add(certificate)
                    .map_err(|_| ConnectError::InvalidRootCertificate)?;
                found = true;
            }
            if !found {
                return Err(ConnectError::InvalidRootCertificate);
            }
        }
        if roots.is_empty() && !self.insecure_tls {
            return Err(ConnectError::InvalidConfiguration(
                "at least one TLS root certificate is required",
            ));
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| ConnectError::Tls(error.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        #[cfg(not(feature = "internal-debug-tls"))]
        if self.insecure_tls {
            return Err(ConnectError::Tls(
                "insecure TLS is unavailable in release builds".into(),
            ));
        }
        #[cfg(feature = "internal-debug-tls")]
        if self.insecure_tls {
            tls.dangerous()
                .set_certificate_verifier(Arc::new(InsecureServerVerifier {
                    algorithms: provider.signature_verification_algorithms,
                }));
        }
        tls.alpn_protocols = vec![b"h2".to_vec()];
        tls.enable_early_data = false;

        Ok(Client {
            inner: Arc::new(ClientInner {
                endpoint,
                gateway_address: self.gateway_address,
                token: self.token,
                user_agent,
                tls_connector: TlsConnector::from(Arc::new(tls)),
                connect_timeout: self.connect_timeout,
                response_timeout: self.response_timeout,
                pool: Mutex::new(PoolState {
                    next_generation: 1,
                    session: None,
                }),
            }),
        })
    }
}

#[cfg(feature = "internal-debug-tls")]
#[derive(Debug)]
struct InsecureServerVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}

#[cfg(feature = "internal-debug-tls")]
impl ServerCertVerifier for InsecureServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
