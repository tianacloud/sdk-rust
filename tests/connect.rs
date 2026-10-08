#[allow(dead_code)]
#[path = "support/tls_fixtures.rs"]
mod tls_fixtures;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use h2::RecvStream;
use http::header::{HeaderValue, PROXY_AUTHENTICATE};
use http::{Method, Request, Response, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ProtocolVersion, ServerConfig};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tiana_sdk::{AuthMode, Client, ConnectError, GatewayError, Protocol, SecretToken};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

const ENDPOINT_HOSTNAME: &str = "ep-01j5c9m7q2v8x4k6n3r0t1w2yz.db.service.internal.tiana.com";
const SERVER_FIRST: &[u8] = b"server-first";

#[derive(Clone, Copy)]
enum Behavior {
    Echo(AuthMode),
    EchoWithoutServerFirst(AuthMode),
    RejectProfile,
    RetryableFailure,
    ExtraSuccessHeader,
}

#[derive(Debug)]
struct Observation {
    method: Method,
    authority: Option<String>,
    scheme: Option<String>,
    path_and_query: Option<String>,
    protocol: String,
    request_id: String,
    token_never_indexed: bool,
    authorization: String,
    client_header_table_size: Option<u32>,
    client_max_header_list_size: Option<u32>,
    pre_response_data: bool,
    sni: Option<String>,
    alpn: Option<Vec<u8>>,
    tls_version: Option<ProtocolVersion>,
}

#[derive(Clone)]
struct ConnectionDetails {
    sni: Option<String>,
    alpn: Option<Vec<u8>>,
    tls_version: Option<ProtocolVersion>,
    wire: Arc<Mutex<Vec<u8>>>,
}

struct FakeGateway {
    address: String,
    root_certificate: Vec<u8>,
    accepted_connections: Arc<AtomicUsize>,
    observations: mpsc::UnboundedReceiver<Observation>,
    task: JoinHandle<()>,
}

impl FakeGateway {
    async fn start(behavior: Behavior) -> Self {
        let root_certificate = tls_fixtures::decode(tls_fixtures::ENDPOINT_CERTIFICATE_DER_B64);
        let certificate = CertificateDer::from(root_certificate.clone());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls_fixtures::decode(
            tls_fixtures::ENDPOINT_KEY_DER_B64,
        )));
        let mut tls =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![certificate], private_key)
                .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let accepted_connections = Arc::new(AtomicUsize::new(0));
        let accept_counter = accepted_connections.clone();
        let (observations_tx, observations) = mpsc::unbounded_channel();

        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                accept_counter.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let observations_tx = observations_tx.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let (_, connection) = tls.get_ref();
                    let sni = connection.server_name().map(str::to_owned);
                    let alpn = connection.alpn_protocol().map(<[u8]>::to_vec);
                    let tls_version = connection.protocol_version();
                    let wire = Arc::new(Mutex::new(Vec::new()));
                    let captured = CaptureIo {
                        inner: tls,
                        inbound: wire.clone(),
                    };
                    let connection_details = ConnectionDetails {
                        sni,
                        alpn,
                        tls_version,
                        wire,
                    };
                    let Ok(mut http2) = h2::server::Builder::new()
                        .max_concurrent_streams(32)
                        .max_header_list_size(16 * 1024)
                        .handshake(captured)
                        .await
                    else {
                        return;
                    };
                    while let Some(result) = http2.accept().await {
                        let Ok((request, respond)) = result else {
                            return;
                        };
                        let observations_tx = observations_tx.clone();
                        tokio::spawn(handle_stream(
                            request,
                            respond,
                            behavior,
                            observations_tx,
                            connection_details.clone(),
                        ));
                    }
                });
            }
        });

        Self {
            address,
            root_certificate,
            accepted_connections,
            observations,
            task,
        }
    }

    fn client(&self, token: Option<SecretToken>) -> Client {
        let mut builder = Client::builder(ENDPOINT_HOSTNAME)
            .gateway_address(&self.address)
            .use_webpki_roots(false)
            .add_root_certificate_der(self.root_certificate.clone());
        if let Some(token) = token {
            builder = builder.token(token);
        }
        builder.build().unwrap()
    }

    async fn observation(&mut self) -> Observation {
        tokio::time::timeout(Duration::from_secs(2), self.observations.recv())
            .await
            .unwrap()
            .unwrap()
    }
}

impl Drop for FakeGateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle_stream(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    behavior: Behavior,
    observations: mpsc::UnboundedSender<Observation>,
    connection: ConnectionDetails,
) {
    let (parts, mut body) = request.into_parts();
    let protocol = header_text(parts.headers.get("tiana-database-protocol"));
    let request_id = header_text(parts.headers.get("tiana-request-id"));
    let pre_response_data = matches!(
        tokio::time::timeout(Duration::from_millis(30), body.data()).await,
        Ok(Some(_))
    );
    let wire_snapshot = connection.wire.lock().unwrap().clone();
    observations
        .send(Observation {
            method: parts.method,
            authority: parts.uri.authority().map(ToString::to_string),
            scheme: parts.uri.scheme_str().map(str::to_owned),
            path_and_query: parts.uri.path_and_query().map(ToString::to_string),
            protocol: protocol.clone(),
            request_id: request_id.clone(),
            token_never_indexed: proxy_authorization_is_never_indexed(&wire_snapshot),
            authorization: header_text(parts.headers.get("proxy-authorization")),
            client_header_table_size: client_setting(&wire_snapshot, 0x1),
            client_max_header_list_size: client_setting(&wire_snapshot, 0x6),
            pre_response_data,
            sni: connection.sni,
            alpn: connection.alpn,
            tls_version: connection.tls_version,
        })
        .unwrap();

    if matches!(behavior, Behavior::RejectProfile) && protocol == "echo-reject" {
        let response = Response::builder()
            .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            .header("tiana-error-code", "AUTH_REQUIRED")
            .header(PROXY_AUTHENTICATE, "Bearer realm=\"tiana\"")
            .body(())
            .unwrap();
        let _ = respond.send_response(response, true);
        return;
    }
    if matches!(behavior, Behavior::RetryableFailure) {
        let response = Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("tiana-error-code", "POLICY_UNAVAILABLE")
            .header("tiana-retry-after-ms", "250")
            .body(())
            .unwrap();
        let _ = respond.send_response(response, true);
        return;
    }

    let auth_mode = match behavior {
        Behavior::Echo(mode) | Behavior::EchoWithoutServerFirst(mode) => mode,
        _ => AuthMode::TokenRequired,
    };
    let auth_mode = match auth_mode {
        AuthMode::TokenRequired => "TOKEN_REQUIRED",
        AuthMode::Disabled => "DISABLED",
    };
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header("tiana-tunnel-version", "1")
        .header("tiana-auth-mode", auth_mode)
        .header("tiana-request-id", request_id);
    if matches!(behavior, Behavior::ExtraSuccessHeader) {
        response = response.header("x-not-allowed", "1");
    }
    let Ok(mut send) = respond.send_response(response.body(()).unwrap(), false) else {
        return;
    };
    if !matches!(behavior, Behavior::EchoWithoutServerFirst(_))
        && send
            .send_data(Bytes::from_static(SERVER_FIRST), false)
            .is_err()
    {
        return;
    }
    while let Some(result) = body.data().await {
        let Ok(data) = result else {
            return;
        };
        let length = data.len();
        if body.flow_control().release_capacity(length).is_err()
            || send.send_data(data, false).is_err()
        {
            return;
        }
    }
    let _ = send.send_data(Bytes::new(), true);
}

fn header_text(value: Option<&HeaderValue>) -> String {
    value
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

struct CaptureIo<T> {
    inner: T,
    inbound: Arc<Mutex<Vec<u8>>>,
}

impl<T: AsyncRead + Unpin> AsyncRead for CaptureIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let previous_length = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.inbound
                .lock()
                .unwrap()
                .extend_from_slice(&buffer.filled()[previous_length..]);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CaptureIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn client_setting(wire: &[u8], expected_id: u16) -> Option<u32> {
    for (frame_type, _flags, _stream_id, payload) in client_frames(wire) {
        if frame_type != 0x4 {
            continue;
        }
        for setting in payload.chunks_exact(6) {
            if u16::from_be_bytes([setting[0], setting[1]]) == expected_id {
                return Some(u32::from_be_bytes([
                    setting[2], setting[3], setting[4], setting[5],
                ]));
            }
        }
    }
    None
}

fn proxy_authorization_is_never_indexed(wire: &[u8]) -> bool {
    for (frame_type, flags, _stream_id, payload) in client_frames(wire) {
        if frame_type != 0x1 || flags & 0x4 == 0 {
            continue;
        }
        let mut position = 0;
        while position < payload.len() {
            let first = payload[position];
            if first & 0x80 != 0 {
                if decode_hpack_integer(payload, &mut position, 7).is_none() {
                    break;
                }
            } else if first & 0x40 != 0 {
                let Some(name) = decode_hpack_integer(payload, &mut position, 6) else {
                    break;
                };
                if name == 0 && !skip_hpack_string(payload, &mut position) {
                    break;
                }
                if !skip_hpack_string(payload, &mut position) {
                    break;
                }
            } else if first & 0x20 != 0 {
                if decode_hpack_integer(payload, &mut position, 5).is_none() {
                    break;
                }
            } else {
                let never_indexed = first & 0x10 != 0;
                let Some(name) = decode_hpack_integer(payload, &mut position, 4) else {
                    break;
                };
                if name == 0 && !skip_hpack_string(payload, &mut position) {
                    break;
                }
                if !skip_hpack_string(payload, &mut position) {
                    break;
                }
                // RFC 7541 static table index 49 is proxy-authorization.
                if never_indexed && name == 49 {
                    return true;
                }
            }
        }
    }
    false
}

fn client_frames(wire: &[u8]) -> Vec<(u8, u8, u32, &[u8])> {
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if !wire.starts_with(PREFACE) {
        return Vec::new();
    }
    let mut frames = Vec::new();
    let mut position = PREFACE.len();
    while wire.len().saturating_sub(position) >= 9 {
        let length = ((wire[position] as usize) << 16)
            | ((wire[position + 1] as usize) << 8)
            | wire[position + 2] as usize;
        if wire.len().saturating_sub(position + 9) < length {
            break;
        }
        let frame_type = wire[position + 3];
        let flags = wire[position + 4];
        let stream_id = u32::from_be_bytes([
            wire[position + 5],
            wire[position + 6],
            wire[position + 7],
            wire[position + 8],
        ]) & 0x7fff_ffff;
        let payload = &wire[position + 9..position + 9 + length];
        frames.push((frame_type, flags, stream_id, payload));
        position += 9 + length;
    }
    frames
}

fn decode_hpack_integer(input: &[u8], position: &mut usize, prefix: u8) -> Option<usize> {
    let first = *input.get(*position)?;
    *position += 1;
    let mask = (1_u16 << prefix) as u8 - 1;
    let mut value = usize::from(first & mask);
    if value < usize::from(mask) {
        return Some(value);
    }
    let mut shift = 0;
    loop {
        let byte = *input.get(*position)?;
        *position += 1;
        value = value.checked_add(usize::from(byte & 0x7f).checked_shl(shift)?)?;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift > 56 {
            return None;
        }
    }
}

fn skip_hpack_string(input: &[u8], position: &mut usize) -> bool {
    let Some(length) = decode_hpack_integer(input, position, 7) else {
        return false;
    };
    let Some(next) = position.checked_add(length) else {
        return false;
    };
    if next > input.len() {
        return false;
    }
    *position = next;
    true
}

fn token(byte: u8) -> SecretToken {
    SecretToken::parse(format!("tia_{}", URL_SAFE_NO_PAD.encode([byte; 32]))).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_uses_tls13_h2_regular_connect_and_never_indexed_token() {
    let mut gateway = FakeGateway::start(Behavior::Echo(AuthMode::TokenRequired)).await;
    let opaque = format!("tia_1{}", "A".repeat(43));
    let client = gateway.client(Some(SecretToken::parse(&opaque).unwrap()));
    let mut tunnel = client
        .connect(Protocol::new("echo-stream").unwrap())
        .await
        .unwrap();
    let observation = gateway.observation().await;

    assert_eq!(observation.method, Method::CONNECT);
    let expected_authority = format!("{ENDPOINT_HOSTNAME}:443");
    assert_eq!(
        observation.authority.as_deref(),
        Some(expected_authority.as_str())
    );
    assert_eq!(observation.scheme, None);
    assert_eq!(observation.path_and_query, None);
    assert_eq!(observation.protocol, "echo-stream");
    assert!(observation.request_id.starts_with("req-"));
    assert!(observation.token_never_indexed);
    assert_eq!(observation.authorization, format!("Bearer {opaque}"));
    assert_eq!(observation.client_header_table_size, Some(0));
    assert_eq!(observation.client_max_header_list_size, Some(16 * 1024));
    assert!(!observation.pre_response_data);
    assert_eq!(observation.sni.as_deref(), Some(ENDPOINT_HOSTNAME));
    assert_eq!(observation.alpn.as_deref(), Some(b"h2".as_slice()));
    assert_eq!(observation.tls_version, Some(ProtocolVersion::TLSv1_3));
    assert_eq!(tunnel.auth_mode(), AuthMode::TokenRequired);

    let mut first = vec![0; SERVER_FIRST.len()];
    tunnel.read_exact(&mut first[..3]).await.unwrap();
    tunnel.read_exact(&mut first[3..]).await.unwrap();
    assert_eq!(first, SERVER_FIRST);
    tunnel.write_all(b"first_stream-startup").await.unwrap();
    tunnel.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    tunnel.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"first_stream-startup");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn arbitrary_application_profiles_are_byte_transparent() {
    let mut gateway =
        FakeGateway::start(Behavior::EchoWithoutServerFirst(AuthMode::Disabled)).await;
    let client = gateway.client(None);
    let (http, websocket) = tokio::join!(
        client.connect(Protocol::new("echo-http").unwrap()),
        client.connect(Protocol::new("echo-websocket").unwrap())
    );
    let mut http = http.unwrap();
    let mut websocket = websocket.unwrap();

    let first_observation = gateway.observation().await;
    let second_observation = gateway.observation().await;
    let mut protocols = [first_observation.protocol, second_observation.protocol];
    protocols.sort();
    assert_eq!(protocols, ["echo-http", "echo-websocket"]);
    assert_eq!(gateway.accepted_connections.load(Ordering::SeqCst), 1);

    let pipeline = b"opaque application payload\x00\xff";
    let upgrade = b"another independently routed payload";
    http.write_all(pipeline).await.unwrap();
    websocket.write_all(upgrade).await.unwrap();
    http.shutdown().await.unwrap();
    websocket.shutdown().await.unwrap();

    let mut http_echo = Vec::new();
    let mut websocket_echo = Vec::new();
    let (http_result, websocket_result) = tokio::join!(
        http.read_to_end(&mut http_echo),
        websocket.read_to_end(&mut websocket_echo)
    );
    http_result.unwrap();
    websocket_result.unwrap();
    assert_eq!(http_echo, pipeline);
    assert_eq!(websocket_echo, upgrade);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_streams_share_one_physical_connection_and_remain_isolated() {
    let mut gateway = FakeGateway::start(Behavior::Echo(AuthMode::Disabled)).await;
    let client = gateway.client(None);
    let (first_stream, second_stream) = tokio::join!(
        client.connect(Protocol::new("echo-stream").unwrap()),
        client.connect(Protocol::new("echo-reject").unwrap())
    );
    let mut first_stream = first_stream.unwrap();
    let mut second_stream = second_stream.unwrap();
    let first_observation = gateway.observation().await;
    let second_observation = gateway.observation().await;

    assert_eq!(gateway.accepted_connections.load(Ordering::SeqCst), 1);
    assert_ne!(first_observation.request_id, second_observation.request_id);
    assert_eq!(first_stream.auth_mode(), AuthMode::Disabled);
    assert_eq!(second_stream.auth_mode(), AuthMode::Disabled);

    let mut greeting = vec![0; SERVER_FIRST.len()];
    first_stream.read_exact(&mut greeting).await.unwrap();
    second_stream.read_exact(&mut greeting).await.unwrap();
    drop(first_stream);
    second_stream
        .write_all(b"second-session-survives")
        .await
        .unwrap();
    second_stream.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    second_stream.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"second-session-survives");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_stream_does_not_break_its_sibling() {
    let mut gateway = FakeGateway::start(Behavior::RejectProfile).await;
    let client = gateway.client(Some(token(9)));
    let (second_stream, first_stream) = tokio::join!(
        client.connect(Protocol::new("echo-reject").unwrap()),
        client.connect(Protocol::new("echo-stream").unwrap())
    );
    let second_stream = match second_stream {
        Ok(_) => panic!("rejected stream unexpectedly succeeded"),
        Err(error) => error,
    };
    let mut first_stream = first_stream.unwrap();
    let _ = gateway.observation().await;
    let _ = gateway.observation().await;

    match second_stream {
        ConnectError::Gateway(error) => {
            assert_eq!(error.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
            assert_eq!(error.code(), Some("AUTH_REQUIRED"));
            assert!(!error.is_retryable());
        }
        other => panic!("unexpected rejected failure: {other}"),
    }
    assert_eq!(gateway.accepted_connections.load(Ordering::SeqCst), 1);
    let mut greeting = vec![0; SERVER_FIRST.len()];
    first_stream.read_exact(&mut greeting).await.unwrap();
    first_stream.write_all(b"still-open").await.unwrap();
    first_stream.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    first_stream.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"still-open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_metadata_is_exposed_but_not_automatically_replayed() {
    let mut gateway = FakeGateway::start(Behavior::RetryableFailure).await;
    let client = gateway.client(None);
    let error = match client.connect(Protocol::new("echo-stream").unwrap()).await {
        Ok(_) => panic!("CONNECT unexpectedly succeeded"),
        Err(error) => error,
    };
    let _ = gateway.observation().await;

    let ConnectError::Gateway(GatewayError { .. }) = &error else {
        panic!("unexpected error: {error}");
    };
    let ConnectError::Gateway(error) = error else {
        unreachable!();
    };
    assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error.code(), Some("POLICY_UNAVAILABLE"));
    assert_eq!(error.retry_after(), Some(Duration::from_millis(250)));
    assert!(error.is_retryable());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(gateway.accepted_connections.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn success_response_header_set_is_closed() {
    let mut gateway = FakeGateway::start(Behavior::ExtraSuccessHeader).await;
    let client = gateway.client(None);
    let error = match client.connect(Protocol::new("echo-stream").unwrap()).await {
        Ok(_) => panic!("CONNECT unexpectedly succeeded"),
        Err(error) => error,
    };
    let _ = gateway.observation().await;
    assert!(matches!(
        error,
        ConnectError::InvalidResponse("success header set is not closed")
    ));
}
