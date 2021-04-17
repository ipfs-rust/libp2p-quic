mod endpoint;
mod muxer;
mod noise;
mod transport;

pub use crate::muxer::{QuicMuxer, QuicMuxerError};
pub use crate::noise::ToLibp2p;
pub use crate::transport::{QuicDial, QuicTransport};
pub use quinn_noise::{Keypair, PublicKey};
pub use quinn_proto::{ConfigError, ConnectError, ConnectionError, TransportConfig};

use libp2p::core::transport::TransportError;
use libp2p::Multiaddr;
use thiserror::Error;

pub fn generate_keypair() -> Keypair {
    Keypair::generate(&mut rand_core::OsRng {})
}

/// Quic configuration.
pub struct QuicConfig {
    pub keypair: Keypair,
    pub psk: Option<[u8; 32]>,
    pub transport: TransportConfig,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            keypair: Keypair::generate(&mut rand_core::OsRng {}),
            psk: None,
            transport: TransportConfig::default(),
        }
    }
}

impl std::fmt::Debug for QuicConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("QuicConfig")
            .field("keypair", &self.keypair.public)
            .field("psk", &self.psk)
            .field("transport", &self.transport)
            .finish()
    }
}

impl QuicConfig {
    /// Creates a new config from a keypair.
    pub fn new(keypair: Keypair) -> Self {
        Self {
            keypair,
            ..Default::default()
        }
    }

    /// Spawns a new endpoint.
    pub async fn listen_on(
        self,
        addr: Multiaddr,
    ) -> Result<QuicTransport, TransportError<QuicError>> {
        QuicTransport::new(self, addr).await
    }
}

#[derive(Debug, Error)]
pub enum QuicError {
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("{0}")]
    Connect(#[from] ConnectError),
    #[error("{0}")]
    Muxer(#[from] QuicMuxerError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("a `StreamMuxerEvent` was generated before the handshake was complete.")]
    UpgradeError,
}
