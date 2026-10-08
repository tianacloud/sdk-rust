#![doc = include_str!("../README.md")]

mod client;
mod error;
mod protocol;
mod tunnel;

pub use client::{Client, ClientBuilder};
pub use error::{ConnectError, GatewayError};
pub use protocol::{AuthMode, Endpoint, Protocol, ProtocolParseError, SecretToken};
pub use tunnel::Tunnel;
