mod endpoint;
mod muxer;
mod noise;
mod transport;

pub use crate::muxer::{QuicMuxer, QuicMuxerError};
pub use crate::transport::{QuicDial, QuicTransport};
pub use libp2p::core::identity::Keypair;
pub use quinn_proto::{ConfigError, ConnectError, ConnectionError, TransportConfig};
pub use snow::params::NoiseParams;

use libp2p::core::transport::TransportError;
use libp2p::Multiaddr;
use thiserror::Error;

/// Quic configuration.
pub struct QuicConfig {
    pub keypair: Keypair,
    pub noise: NoiseParams,
    pub prologue: Vec<u8>,
    pub transport: TransportConfig,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            keypair: Keypair::generate_ed25519(),
            noise: "Noise_XX_25519_AESGCM_SHA256".parse().unwrap(),
            prologue: vec![],
            transport: TransportConfig::default(),
        }
    }
}

impl std::fmt::Debug for QuicConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("QuicConfig")
            .field("keypair", &self.keypair.public())
            .field("noise", &self.noise)
            .field("prologue", &self.prologue)
            .field("transport", &self.transport)
            .finish()
    }
}

impl QuicConfig {
    /// Creates a new config from a keypair.
    pub fn new(keypair: &Keypair) -> Self {
        Self {
            keypair: keypair.clone(),
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
