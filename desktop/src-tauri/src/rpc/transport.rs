//! How the app reaches the helper. The client only needs a byte stream, so the
//! Windows named pipe (`pipe_transport`) is another `Transport` beside the unix
//! socket.

use std::io;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

/// A connected duplex byte stream to the helper.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub type BoxStream = Box<dyn Stream>;

/// Opens connections to the helper.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    async fn connect(&self) -> io::Result<BoxStream>;
}

/// The helper's unix domain socket.
#[cfg(unix)]
pub struct UnixTransport {
    path: std::path::PathBuf,
}

#[cfg(unix)]
impl UnixTransport {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[cfg(unix)]
#[async_trait]
impl Transport for UnixTransport {
    async fn connect(&self) -> io::Result<BoxStream> {
        let stream = tokio::net::UnixStream::connect(&self.path).await?;
        Ok(Box::new(stream))
    }
}
