use sha2::{Digest, Sha256};
use std::str;
use tiana_sdk::Endpoint;

const MANIFEST: &[u8] = include_bytes!("../conformance/v1/manifest.json");
const PROVENANCE: &[u8] = include_bytes!("../conformance/v1/consumer-provenance.json");
const AUTHORITY: &[u8] =
    include_bytes!("../conformance/v1/fixtures/gateway/public-connect-authority-v1.json");
const CONNECT_PROTOCOL: &[u8] = include_bytes!("../conformance/v1/protocols/public-connect-v1.md");

const EXPECTED_CONTRACT_IDENTITY: &str = "tiana.fetch-v1-conformance.1";
const EXPECTED_SOURCE_COMMIT: &str = "d252fd7bf689657e50b6caf36298f8c57860df6b";
const EXPECTED_MANIFEST_SHA256: &str =
    "73cd9539f85a00be78a6b311af3941b5b554ee19e480bfc18f8056e3cff460cc";
const EXPECTED_AUTHORITY_SHA256: &str =
    "683229edc8886b985ff6b29a99dd34da90bec9db15f6012aa12b07623d2658dc";
const EXPECTED_CONNECT_PROTOCOL_SHA256: &str =
    "b9e6fcecb4e09b5c36e025377ee1288d976dde5b8300ff18fa56a07f2f790a3d";
const EXPECTED_PROVENANCE: &str = "{\n  \"contracts_distribution_commit\": \"59b3b4654511eb01b6d0c350fff8b7e22bbb0268\",\n  \"contract_identity\": \"tiana.fetch-v1-conformance.1\",\n  \"source_commit\": \"d252fd7bf689657e50b6caf36298f8c57860df6b\",\n  \"manifest_sha256\": \"73cd9539f85a00be78a6b311af3941b5b554ee19e480bfc18f8056e3cff460cc\",\n  \"role\": \"sdk-rust-connect\",\n  \"consumer_repository\": \"sdk-rust\",\n  \"consumer_baseline\": \"19c9c7da28f17c11700d515153cdecea600efe44\"\n}\n";

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

fn manifest_text() -> &'static str {
    str::from_utf8(MANIFEST).expect("conformance manifest must be UTF-8")
}

fn authority_suffix() -> &'static str {
    let authority = str::from_utf8(AUTHORITY).expect("authority fixture must be UTF-8");
    authority
        .split_once("\"endpoint_suffix\": \"")
        .and_then(|(_, value)| value.split_once('"'))
        .map(|(value, _)| value)
        .expect("authority suffix field")
}

fn authority_port() -> u16 {
    let authority = str::from_utf8(AUTHORITY).expect("authority fixture must be UTF-8");
    authority
        .split_once("\"default_port\": ")
        .and_then(|(_, value)| value.split_whitespace().next())
        .and_then(|value| value.trim_end_matches(',').parse().ok())
        .expect("authority port field")
}

#[test]
fn sdk_rust_connect_role_is_pinned_to_the_frozen_manifest_and_authority() {
    let manifest = manifest_text();
    assert_eq!(
        str::from_utf8(PROVENANCE).expect("consumer provenance must be UTF-8"),
        EXPECTED_PROVENANCE
    );
    assert!(manifest.contains(&format!(
        "\"contract_identity\": \"{EXPECTED_CONTRACT_IDENTITY}\""
    )));
    assert!(manifest.contains(&format!("\"source_commit\": \"{EXPECTED_SOURCE_COMMIT}\"")));
    assert!(manifest.contains(&format!(
        "\"manifest_sha256\": \"{EXPECTED_MANIFEST_SHA256}\""
    )));
    assert!(manifest.contains(
        "\"sdk-rust\": {\n      \"repository\": \"sdk-rust\",\n      \"commit\": \"19c9c7da28f17c11700d515153cdecea600efe44\",\n      \"role\": \"sdk-rust-connect\""
    ));
    assert!(manifest.contains(
        "\"sdk-rust-connect\": [\n      \"public-connect-authority\",\n      \"public-connect-protocol\"\n    ]"
    ));
    assert!(manifest.contains(&format!(
        "\"public-connect-authority\": {{\n      \"path\": \"fixtures/gateway/public-connect-authority-v1.json\",\n      \"sha256\": \"{EXPECTED_AUTHORITY_SHA256}\""
    )));
    assert!(manifest.contains(&format!(
        "\"public-connect-protocol\": {{\n      \"path\": \"protocols/public-connect-v1.md\",\n      \"sha256\": \"{EXPECTED_CONNECT_PROTOCOL_SHA256}\""
    )));

    assert_eq!(sha256_hex(AUTHORITY), EXPECTED_AUTHORITY_SHA256);
    assert_eq!(
        sha256_hex(CONNECT_PROTOCOL),
        EXPECTED_CONNECT_PROTOCOL_SHA256
    );

    let marker = "\"manifest_sha256\": \"";
    let marker_start = manifest.find(marker).expect("manifest self-hash marker");
    let value_start = marker_start + marker.len();
    assert_eq!(
        &manifest[value_start..value_start + 64],
        EXPECTED_MANIFEST_SHA256
    );
    let mut zeroed = MANIFEST.to_vec();
    zeroed[value_start..value_start + 64].fill(b'0');
    assert_eq!(sha256_hex(&zeroed), EXPECTED_MANIFEST_SHA256);

    assert!(manifest.contains("\"public_authority_suffix\": \".db.service.internal.tiana.com\""));
    assert!(manifest.contains("\"public_authority_port\": 443"));
    assert!(manifest.contains("\"tls_version\": \"1.3\""));
    assert!(manifest.contains("\"alpn\": [\n      \"h2\",\n      \"http/1.1\"\n    ]"));
}

#[test]
fn public_connect_authority_artifact_drives_endpoint_constants() {
    let authority = str::from_utf8(AUTHORITY).expect("authority fixture must be UTF-8");
    assert_eq!(
        authority,
        "{\n  \"authority_version\": 1,\n  \"endpoint_suffix\": \".db.service.internal.tiana.com\",\n  \"default_port\": 443\n}\n"
    );
    let protocol = str::from_utf8(CONNECT_PROTOCOL).expect("protocol fixture must be UTF-8");
    assert!(protocol.contains("Public CONNECT authority v1"));
    assert!(protocol.contains("TLS 1.3 with ALPN `h2`"));
    assert!(protocol.contains("regular HTTP/2 CONNECT stream"));
    assert!(protocol.contains("An omitted authority\nport means 443"));
    assert!(protocol.contains("only allowed explicit port is `:443`"));

    let endpoint_id = "ep-01j5c9m7q2v8x4k6n3r0t1w2yz";
    let endpoint_hostname = format!("{endpoint_id}{}", authority_suffix());
    let endpoint = Endpoint::parse(&endpoint_hostname).expect("authority-derived endpoint");
    assert_eq!(endpoint.id(), endpoint_id);
    assert_eq!(endpoint.hostname(), endpoint_hostname);
    assert_eq!(authority_port(), 443);
}
