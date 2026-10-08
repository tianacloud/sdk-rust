use core::fmt;
use core::str::FromStr;
use zeroize::Zeroizing;

const ENDPOINT_PREFIX: &str = "ep-";
const ENDPOINT_ID_LENGTH: usize = 29;
const MAX_TOKEN_BYTES: usize = 4096;

/// A validated public Endpoint identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Endpoint {
    id: String,
    hostname: String,
    port: u16,
}

impl Endpoint {
    /// Accepts a deployed Endpoint hostname or HTTPS connection URL.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, EndpointParseError> {
        let value = value.as_ref();
        let address = value.strip_prefix("https://").unwrap_or(value);
        let authority: http::uri::Authority = address.parse().map_err(|_| EndpointParseError)?;
        let hostname = authority.host();
        let (id, _) = hostname.split_once('.').ok_or(EndpointParseError)?;
        if !valid_endpoint_id(id.as_bytes()) || hostname.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(EndpointParseError);
        }
        rustls::pki_types::DnsName::try_from(hostname).map_err(|_| EndpointParseError)?;
        let port = authority.port_u16().unwrap_or(443);
        let expected = if authority.port().is_some() {
            format!("{hostname}:{port}")
        } else {
            hostname.to_owned()
        };
        if port == 0 || expected != address {
            return Err(EndpointParseError);
        }
        Ok(Self {
            id: id.to_owned(),
            hostname: hostname.to_owned(),
            port,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub(crate) fn authority(&self) -> String {
        format!("{}:443", self.hostname)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.hostname)
    }
}

impl FromStr for Endpoint {
    type Err = EndpointParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointParseError;

impl fmt::Display for EndpointParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid Tiana Endpoint")
    }
}

impl std::error::Error for EndpointParseError {}

fn valid_endpoint_id(value: &[u8]) -> bool {
    value.len() == ENDPOINT_ID_LENGTH
        && value.starts_with(ENDPOINT_PREFIX.as_bytes())
        && matches!(value[3], b'0'..=b'7')
        && value[4..].iter().copied().all(valid_crockford_lower)
}

const fn valid_crockford_lower(value: u8) -> bool {
    matches!(
        value,
        b'0'..=b'9' | b'a'..=b'h' | b'j' | b'k' | b'm' | b'n' | b'p'..=b't' | b'v'..=b'z'
    )
}

/// A bounded, application-defined routing profile for a CONNECT stream.
///
/// The Gateway decides which profiles it supports. This crate does not interpret
/// the bytes carried by a profile or provide protocol-specific adapters.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Protocol(String);

impl Protocol {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ProtocolParseError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(ProtocolParseError);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Protocol {
    type Err = ProtocolParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolParseError;
impl fmt::Display for ProtocolParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid CONNECT protocol identifier")
    }
}
impl std::error::Error for ProtocolParseError {}

/// Gateway authentication mode used for the successful stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMode {
    TokenRequired,
    Disabled,
}

impl AuthMode {
    pub(crate) fn parse(value: &[u8]) -> Option<Self> {
        match value {
            b"TOKEN_REQUIRED" => Some(Self::TokenRequired),
            b"DISABLED" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// Opaque, bounded HTTP Bearer credential. Debug output is redacted and owned bytes
/// are zeroized on drop.
pub struct SecretToken(Zeroizing<Vec<u8>>);

impl SecretToken {
    pub fn parse(value: impl AsRef<[u8]>) -> Result<Self, SecretTokenParseError> {
        let value = value.as_ref();
        // Do not infer format, version, owner or scope from credential bytes.
        // Validate before allocating an owned secret; never normalize its value.
        if value.is_empty()
            || value.len() > MAX_TOKEN_BYTES
            || !value.iter().all(|byte| (0x21..=0x7e).contains(byte))
        {
            return Err(SecretTokenParseError);
        }
        Ok(Self(Zeroizing::new(value.to_vec())))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretToken([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretTokenParseError;

impl fmt::Display for SecretTokenParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid Tiana token")
    }
}

impl std::error::Error for SecretTokenParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINT_ID: &str = "ep-01j5c9m7q2v8x4k6n3r0t1w2yz";

    #[test]
    fn endpoint_preserves_deployed_hostname_and_port() {
        for domain in ["db.service.internal.tiana.com", "db.env123.tiana.test"] {
            let hostname = format!("{ENDPOINT_ID}.{domain}");
            let endpoint = Endpoint::parse(&hostname).unwrap();
            assert_eq!(endpoint.id(), ENDPOINT_ID);
            assert_eq!(endpoint.hostname(), hostname);
            assert_eq!(endpoint.port(), 443);
            let endpoint = Endpoint::parse(format!("https://{hostname}:18445")).unwrap();
            assert_eq!(endpoint.hostname(), hostname);
            assert_eq!(endpoint.port(), 18445);
            assert_eq!(endpoint.authority(), format!("{hostname}:443"));
        }
    }

    #[test]
    fn endpoint_rejects_invalid_id_and_address() {
        for value in [
            "EP-01j5c9m7q2v8x4k6n3r0t1w2yz.db.env.test".to_string(),
            "ep-81j5c9m7q2v8x4k6n3r0t1w2yz.db.env.test".to_string(),
            "ep-01j5c9m7q2v8x4k6n3r0t1w2yu.db.env.test".to_string(),
            format!("{ENDPOINT_ID}.db.env.test:65536"),
            format!("https://{ENDPOINT_ID}.db.env.test/path"),
        ] {
            assert!(Endpoint::parse(value).is_err());
        }
    }

    #[test]
    fn tokens_are_opaque_bounded_and_unchanged() {
        for value in [
            "tia_".to_owned() + &"A".repeat(43),
            "tia_1".to_owned() + &"A".repeat(43),
            "session.other-format_+/==".to_owned(),
            "tia_noncanonical".to_owned(),
            "!".to_owned(),
            "x".repeat(MAX_TOKEN_BYTES),
        ] {
            let token = SecretToken::parse(&value).unwrap();
            assert_eq!(token.as_bytes(), value.as_bytes());
            assert_eq!(format!("{token:?}"), "SecretToken([REDACTED])");
        }
    }

    #[test]
    fn tokens_reject_unsafe_or_oversized_input_without_exposing_it() {
        for value in [
            Vec::new(),
            b" leading".to_vec(),
            b"trailing ".to_vec(),
            b"secret\r\nx-injected: yes".to_vec(),
            b"secret\n".to_vec(),
            b"secret\t".to_vec(),
            b"secret\0".to_vec(),
            vec![0x7f],
            vec![0xff],
            "secret-é".as_bytes().to_vec(),
            vec![b'x'; MAX_TOKEN_BYTES + 1],
        ] {
            let error = SecretToken::parse(&value).unwrap_err();
            assert_eq!(error.to_string(), "invalid Tiana token");
            assert_eq!(format!("{error:?}"), "SecretTokenParseError");
        }
    }

    #[test]
    fn owned_opaque_token_bytes_can_be_zeroized() {
        use zeroize::Zeroize;
        let value = "session.".to_owned() + &"A".repeat(400);
        let mut token = SecretToken::parse(&value).unwrap();
        token.0.as_mut_slice().zeroize();
        assert_eq!(token.as_bytes(), vec![0; value.len()]);
        // The same Zeroizing owner clears its buffer on Drop.
    }

    #[test]
    fn protocols_are_generic_bounded_header_tokens() {
        for value in ["echo", "custom-stream-v2", "Application_1.0"] {
            assert_eq!(value.parse::<Protocol>().unwrap().as_str(), value);
        }
        for value in [
            "",
            " x",
            "x y",
            "x\r\nx-injected: 1",
            "é",
            "x/y",
            &"x".repeat(65),
        ] {
            assert!(Protocol::new(value).is_err());
        }
        assert!(Protocol::new("x".repeat(64)).is_ok());
    }
}
