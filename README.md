# Tiana Rust transport

`tiana-sdk` provides authenticated, encrypted, byte-transparent channels to a
Tiana Gateway. It owns Endpoint identity, TLS 1.3/ALPN h2, regular HTTP/2 CONNECT,
stream multiplexing, flow control, bidirectional half-close and diagnostics.
Application adapters own their protocol identifiers and payloads.

## Usage

The current API is unreleased; use this source checkout when developing dependent
crates. Older release tags do not contain this API. Publication is disabled.

```rust,no_run
use tiana_sdk::{Client, Protocol, SecretToken};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let token = SecretToken::parse(std::env::var("TIANA_TOKEN")?.as_bytes())?;
let client = Client::builder(
    "ep-00000000000000000000000000.db.example.com",
).token(token).build()?;
let profile = Protocol::new("my-application-v1")?;
let tunnel = client.connect(profile).await?;
// The Gateway must support the application's profile.
// tunnel implements Tokio AsyncRead + AsyncWrite; it does not interpret payloads.
# drop(tunnel);
# Ok(())
# }
```

`Protocol` is an owned identifier of 1–64 ASCII letters, digits, dots, underscores
or hyphens. It is forwarded in the existing `tiana-database-protocol` CONNECT
header. The Gateway alone decides which profiles are supported. There is no
built-in application protocol enumeration, socket naming or companion executable.
Neither failed CONNECT requests nor application bytes are automatically replayed.
Dropping a tunnel releases that stream; sibling streams stay independent.

Endpoint accepts a deployed hostname, `hostname:port`, or an HTTPS URL without a
path. The supplied port selects TCP dialing; the default is `443`. TLS SNI uses
the hostname and CONNECT uses that hostname with logical port `443`.
`gateway_address("127.0.0.1:18443")` overrides only TCP dialing. Custom trust uses
`add_root_certificates_pem(std::fs::read("ca.pem")?)` for a PEM file containing
one or more CA certificates; no DER conversion is needed.
`use_webpki_roots(false)` disables public roots. Empty or malformed CA bundles
fail when building the client. `add_root_certificate_der` remains available for
already decoded certificates.
The `internal-debug-tls` feature exposes `insecure_tls(true)` for local debugging;
normal clients validate certificate chains and hostnames.

`SecretToken` accepts an opaque credential of 1–4096 visible ASCII bytes
(no whitespace/control characters). It does not enforce a prefix, version, exact
length or Base64 encoding, and never trims or rewrites the value. The Gateway
decides validity and scope. Debug output is redacted. Credential bytes are zeroized on drop and sent only in the sensitive
CONNECT Proxy-Authorization header. This crate does not acquire or refresh tokens.

`connect_with_diagnostic(profile, observer)` reports the request ID before
DNS/TCP/TLS/CONNECT. Retain it for failed or cancelled connection attempts;
`Tunnel::request_id()` returns the same ID after success. The observer must return
promptly; observer panics do not fail the connection.

## Verification

```sh
cargo test --locked
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --check
```

Tests use local TLS/H2 peers to verify routing, trust, credential header handling,
transparent payloads, half-close, stream isolation and no replay. Frozen authority
conformance artifacts retain their original provenance. Build a source artifact
from a clean revision with `scripts/build-source-package.sh OUTPUT.crate`.
