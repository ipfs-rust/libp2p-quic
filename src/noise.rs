use crate::endpoint::QuicError;
use crate::muxer::QuicMuxer;
use bytes::BytesMut;
use libp2p::core::StreamMuxer;
use libp2p::PeerId;
use quinn_proto::crypto::{
    ClientConfig, CryptoError, ExportKeyingMaterialError, KeyPair, Keys, PacketKey, ServerConfig,
    Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side};
use ring::aead;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;

pub struct NoiseUpgrade(Option<QuicMuxer>);

impl NoiseUpgrade {
    pub fn new(muxer: QuicMuxer) -> Self {
        Self(Some(muxer))
    }
}

impl Future for NoiseUpgrade {
    type Output = Result<(PeerId, QuicMuxer), QuicError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let muxer = self.0.as_ref().unwrap();
        match muxer.poll_event(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Err(NoiseUpgradeError.into())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
            Poll::Pending => {
                if !muxer.is_handshaking() {
                    if let Some(peer_id) = muxer.peer_id() {
                        return Poll::Ready(Ok((peer_id, self.0.take().unwrap())));
                    }
                }
                Poll::Pending
            }
        }
    }
}

#[derive(Debug, Error)]
#[error("a `StreamMuxerEvent` was generated before the handshake was complete.")]
pub struct NoiseUpgradeError;

pub struct NoiseSession {}

impl Session for NoiseSession {
    type HandshakeData = ();
    type Identity = PeerId;
    type ClientConfig = NoiseConfig;
    type ServerConfig = NoiseConfig;
    type HmacKey = ring::hmac::Key;
    type HandshakeTokenKey = ring::hkdf::Prk;
    type HeaderKey = ring::aead::quic::HeaderProtectionKey;
    type PacketKey = NoisePacketKey;

    fn initial_keys(_: &ConnectionId, _: Side) -> Keys<Self> {
        todo!()
    }

    fn next_1rtt_keys(&mut self) -> KeyPair<Self::PacketKey> {
        todo!()
    }

    fn peer_identity(&self) -> Option<Self::Identity> {
        todo!()
    }

    fn is_handshaking(&self) -> bool {
        true
    }

    fn read_handshake(&mut self, _: &[u8]) -> Result<bool, quinn_proto::TransportError> {
        todo!()
    }

    fn write_handshake(&mut self, _: &mut Vec<u8>) -> Option<Keys<Self>> {
        todo!()
    }

    fn transport_parameters(
        &self,
    ) -> Result<Option<TransportParameters>, quinn_proto::TransportError> {
        todo!()
    }

    fn handshake_data(&self) -> Option<Self::HandshakeData> {
        // TODO optional
        None
    }

    fn export_keying_material(
        &self,
        _: &mut [u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        // TODO optional
        Err(ExportKeyingMaterialError)
    }

    fn early_crypto(&self) -> Option<(Self::HeaderKey, Self::PacketKey)> {
        // 0-rtt is unsupported
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        // 0-rtt is unsupported
        None
    }

    // TODO: add default implementation to quinn
    fn retry_tag(orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(packet);

        let nonce = aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE);
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_INTEGRITY_KEY).unwrap(),
        );

        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(pseudo_packet), &mut [])
            .unwrap();
        let mut result = [0; 16];
        result.copy_from_slice(tag.as_ref());
        result
    }

    // TODO: add default implementation to quinn
    fn is_valid_retry(orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let tag_start = match payload.len().checked_sub(16) {
            Some(x) => x,
            None => return false,
        };

        let mut pseudo_packet =
            Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);

        let nonce = aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE);
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_INTEGRITY_KEY).unwrap(),
        );

        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        key.open_in_place(nonce, aead::Aad::from(aad), tag).is_ok()
    }
}

const RETRY_INTEGRITY_KEY: [u8; 16] = [
    0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1,
];
const RETRY_INTEGRITY_NONCE: [u8; 12] = [
    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
];

#[derive(Clone, Debug, Default)]
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
