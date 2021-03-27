use bytes::BytesMut;
use libp2p::PeerId;
use quinn_proto::crypto::{
    AeadKey, ClientConfig, CryptoError, ExportKeyingMaterialError, HandshakeTokenKey, HeaderKey,
    HmacKey, KeyPair, Keys, PacketKey, ServerConfig, Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConfigError, ConnectError, ConnectionId, Side};

pub struct NoiseSession {}

impl Session for NoiseSession {
    type HandshakeData = ();
    type Identity = PeerId;
    type ClientConfig = NoiseConfig;
    type HmacKey = NoiseHmacKey;
    type HandshakeTokenKey = NoiseHandshakeTokenKey;
    type HeaderKey = NoiseHeaderKey;
    type PacketKey = NoisePacketKey;
    type ServerConfig = NoiseConfig;

    fn initial_keys(_: &ConnectionId, _: Side) -> Keys<Self> {
        todo!()
    }

    fn handshake_data(&self) -> Option<Self::HandshakeData> {
        todo!()
    }

    fn peer_identity(&self) -> Option<Self::Identity> {
        todo!()
    }

    fn early_crypto(&self) -> Option<(Self::HeaderKey, Self::PacketKey)> {
        todo!()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        todo!()
    }

    fn is_handshaking(&self) -> bool {
        true
    }

    fn read_handshake(&mut self, _: &[u8]) -> Result<bool, quinn_proto::TransportError> {
        todo!()
    }

    fn transport_parameters(
        &self,
    ) -> Result<Option<TransportParameters>, quinn_proto::TransportError> {
        todo!()
    }

    fn write_handshake(&mut self, _: &mut Vec<u8>) -> Option<Keys<Self>> {
        todo!()
    }

    fn next_1rtt_keys(&mut self) -> KeyPair<Self::PacketKey> {
        todo!()
    }

    fn retry_tag(_: &ConnectionId, _: &[u8]) -> [u8; 16] {
        todo!()
    }

    fn is_valid_retry(_: &ConnectionId, _: &[u8], _: &[u8]) -> bool {
        todo!()
    }

    fn export_keying_material(
        &self,
        _: &mut [u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        todo!()
    }
}

#[derive(Clone)]
pub struct NoiseConfig {}

impl ClientConfig<NoiseSession> for NoiseConfig {
    fn new() -> Self {
        Self {}
    }

    fn start_session(
        &self,
        _: &str,
        _: &TransportParameters,
    ) -> Result<NoiseSession, ConnectError> {
        Ok(NoiseSession {})
    }
}

impl ServerConfig<NoiseSession> for NoiseConfig {
    fn new() -> Self {
        Self {}
    }

    fn start_session(&self, _: &TransportParameters) -> NoiseSession {
        NoiseSession {}
    }
}

pub struct NoiseHmacKey {}

impl HmacKey for NoiseHmacKey {
    const KEY_LEN: usize = 42;
    type Signature = [u8; 32];
    fn new(_: &[u8]) -> Result<Self, ConfigError> {
        todo!()
    }

    fn sign(&self, _: &[u8]) -> Self::Signature {
        todo!()
    }

    fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), CryptoError> {
        todo!()
    }
}

pub struct NoiseHandshakeTokenKey {}

impl HandshakeTokenKey for NoiseHandshakeTokenKey {
    type AeadKey = NoiseAeadKey;
    fn aead_from_hkdf(&self, _: &[u8]) -> Self::AeadKey {
        todo!()
    }
    fn from_secret(_: &[u8]) -> Self {
        todo!()
    }
}

pub struct NoiseAeadKey {}

impl AeadKey for NoiseAeadKey {
    const KEY_LEN: usize = 42;
    fn seal(&self, _: &mut Vec<u8>, _: &[u8]) -> Result<(), CryptoError> {
        todo!()
    }
    fn open<'a>(&self, _: &'a mut [u8], _: &[u8]) -> Result<&'a mut [u8], CryptoError> {
        todo!()
    }
}

pub struct NoiseHeaderKey {}

impl HeaderKey for NoiseHeaderKey {
    fn decrypt(&self, _: usize, _: &mut [u8]) {
        todo!()
    }
    fn encrypt(&self, _: usize, _: &mut [u8]) {
        todo!()
    }
    fn sample_size(&self) -> usize {
        todo!()
    }
}

pub struct NoisePacketKey {}

impl PacketKey for NoisePacketKey {
    fn encrypt(&self, _: u64, _: &mut [u8], _: usize) {
        todo!()
    }
    fn decrypt(&self, _: u64, _: &[u8], _: &mut BytesMut) -> Result<(), CryptoError> {
        todo!()
    }
    fn tag_len(&self) -> usize {
        todo!()
    }
    fn confidentiality_limit(&self) -> u64 {
        todo!()
    }
    fn integrity_limit(&self) -> u64 {
        todo!()
    }
}
