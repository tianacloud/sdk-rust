use crate::protocol::{AuthMode, Endpoint, Protocol};
use bytes::Bytes;
use h2::{Reason, RecvStream, SendStream};
use std::cmp;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_WRITE_CHUNK: usize = 16 * 1024;

/// One accepted application session carried by one HTTP/2 CONNECT stream.
///
/// `Tunnel` is byte-transparent and implements Tokio `AsyncRead` and
/// `AsyncWrite`. Dropping it resets only its own HTTP/2 stream.
pub struct Tunnel {
    send: SendStream<Bytes>,
    receive: RecvStream,
    read_buffer: Bytes,
    local_closed: bool,
    remote_closed: bool,
    endpoint: Endpoint,
    protocol: Protocol,
    request_id: String,
    auth_mode: AuthMode,
}

impl Tunnel {
    pub(crate) fn new(
        send: SendStream<Bytes>,
        receive: RecvStream,
        endpoint: Endpoint,
        protocol: Protocol,
        request_id: String,
        auth_mode: AuthMode,
    ) -> Self {
        Self {
            send,
            receive,
            read_buffer: Bytes::new(),
            local_closed: false,
            remote_closed: false,
            endpoint,
            protocol,
            request_id,
            auth_mode,
        }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub const fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }
}

impl AsyncRead for Tunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            let count = cmp::min(output.remaining(), self.read_buffer.len());
            self.receive
                .flow_control()
                .release_capacity(count)
                .map_err(|error| io::Error::other(error.to_string()))?;
            output.put_slice(&self.read_buffer.split_to(count));
            return Poll::Ready(Ok(()));
        }
        if self.remote_closed || output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        match self.receive.poll_data(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                self.remote_closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(error))) => {
                self.remote_closed = true;
                Poll::Ready(Err(io::Error::other(error.to_string())))
            }
            Poll::Ready(Some(Ok(mut data))) => {
                let count = cmp::min(output.remaining(), data.len());
                self.receive
                    .flow_control()
                    .release_capacity(count)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                output.put_slice(&data.split_to(count));
                self.read_buffer = data;
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.local_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tunnel write side is closed",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if self.send.capacity() == 0 {
            self.send
                .reserve_capacity(cmp::min(input.len(), MAX_WRITE_CHUNK));
            match self.send.poll_capacity(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "tunnel stream is closed",
                    )));
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(io::Error::other(error.to_string())));
                }
                Poll::Ready(Some(Ok(_))) => {}
            }
        }

        let count = cmp::min(input.len(), cmp::min(self.send.capacity(), MAX_WRITE_CHUNK));
        if count == 0 {
            return Poll::Pending;
        }
        self.send
            .send_data(Bytes::copy_from_slice(&input[..count]), false)
            .map_err(|error| io::Error::other(error.to_string()))?;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.local_closed {
            self.local_closed = true;
            self.send
                .send_data(Bytes::new(), true)
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        if !self.local_closed {
            self.send.send_reset(Reason::CANCEL);
        }
    }
}
