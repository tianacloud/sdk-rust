use core::fmt;
use http::StatusCode;
use std::time::Duration;

/// A stable Gateway refusal observed before a tunnel reached HTTP 200.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayError {
    status: StatusCode,
    code: Option<String>,
    retry_after: Option<Duration>,
}

impl GatewayError {
    pub(crate) fn new(
        status: StatusCode,
        code: Option<String>,
        retry_after: Option<Duration>,
    ) -> Self {
        Self {
            status,
            code,
            retry_after,
        }
    }

    pub const fn status(&self) -> StatusCode {
        self.status
    }

    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    pub const fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    pub fn is_retryable(&self) -> bool {
        self.retry_after.is_some()
            && matches!(
                (self.status, self.code()),
                (StatusCode::TOO_MANY_REQUESTS, Some("CONNECTION_LIMIT"))
                    | (StatusCode::SERVICE_UNAVAILABLE, Some("POLICY_UNAVAILABLE"))
                    | (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Some("INSTANCE_UNAVAILABLE")
                    )
                    | (StatusCode::GATEWAY_TIMEOUT, Some("ACTIVATION_TIMEOUT"))
            )
    }
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Gateway rejected CONNECT with {}", self.status)?;
        if let Some(code) = &self.code {
            write!(formatter, " ({code})")?;
        }
        Ok(())
    }
}

impl std::error::Error for GatewayError {}

/// Redacted failures from building or opening a database tunnel.
#[derive(Debug)]
pub enum ConnectError {
    InvalidEndpoint,
    InvalidConfiguration(&'static str),
    InvalidRootCertificate,
    InvalidUserAgent,
    RandomSource,
    Tcp(std::io::Error),
    Timeout(&'static str),
    Tls(String),
    Http2(String),
    InvalidResponse(&'static str),
    Gateway(GatewayError),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint => formatter.write_str("invalid Tiana Endpoint"),
            Self::InvalidConfiguration(message) => formatter.write_str(message),
            Self::InvalidRootCertificate => formatter.write_str("invalid TLS root certificate"),
            Self::InvalidUserAgent => formatter.write_str("invalid User-Agent value"),
            Self::RandomSource => formatter.write_str("secure request ID generation failed"),
            Self::Tcp(error) => write!(formatter, "Gateway TCP connection failed: {error}"),
            Self::Timeout(stage) => write!(formatter, "Gateway {stage} timed out"),
            Self::Tls(error) => write!(formatter, "Gateway TLS failed: {error}"),
            Self::Http2(error) => write!(formatter, "Gateway HTTP/2 failed: {error}"),
            Self::InvalidResponse(message) => {
                write!(formatter, "invalid Gateway response: {message}")
            }
            Self::Gateway(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tcp(error) => Some(error),
            Self::Gateway(error) => Some(error),
            _ => None,
        }
    }
}

impl From<GatewayError> for ConnectError {
    fn from(value: GatewayError) -> Self {
        Self::Gateway(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryability_requires_a_frozen_status_code_pair_and_hint() {
        let retry_after = Some(Duration::from_millis(1));
        for (status, code) in [
            (StatusCode::TOO_MANY_REQUESTS, "CONNECTION_LIMIT"),
            (StatusCode::SERVICE_UNAVAILABLE, "POLICY_UNAVAILABLE"),
            (StatusCode::SERVICE_UNAVAILABLE, "INSTANCE_UNAVAILABLE"),
            (StatusCode::GATEWAY_TIMEOUT, "ACTIVATION_TIMEOUT"),
        ] {
            assert!(GatewayError::new(status, Some(code.to_owned()), retry_after).is_retryable());
        }

        assert!(
            !GatewayError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                Some("AUTH_REQUIRED".to_owned()),
                retry_after,
            )
            .is_retryable()
        );
        assert!(
            !GatewayError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                Some("POLICY_UNAVAILABLE".to_owned()),
                None,
            )
            .is_retryable()
        );
    }
}
