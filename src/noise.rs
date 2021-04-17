use crate::{QuicError, QuicMuxer};
use libp2p::core::StreamMuxer;
use libp2p::PeerId;
use quinn_noise::{Keypair, PublicKey};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

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
            Poll::Ready(Ok(_)) => Poll::Ready(Err(QuicError::UpgradeError)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
            Poll::Pending => {
                if !muxer.is_handshaking() {
                    if let Some(peer_id) = muxer.peer_id() {
                        tracing::trace!("noise upgrade complete");
                        return Poll::Ready(Ok((peer_id, self.0.take().unwrap())));
                    }
                }
                Poll::Pending
            }
        }
    }
}

pub trait ToLibp2p {
    fn to_keypair(&self) -> libp2p::identity::Keypair;
    fn to_public(&self) -> libp2p::identity::PublicKey;
    fn to_peer_id(&self) -> PeerId {
        self.to_public().into_peer_id()
    }
}

impl ToLibp2p for Keypair {
    fn to_keypair(&self) -> libp2p::identity::Keypair {
        let mut secret_key = self.secret.to_bytes();
        let secret_key = libp2p::identity::ed25519::SecretKey::from_bytes(&mut secret_key).unwrap();
        libp2p::identity::Keypair::Ed25519(secret_key.into())
    }

    fn to_public(&self) -> libp2p::identity::PublicKey {
        self.public.to_public()
    }
}

impl ToLibp2p for PublicKey {
    fn to_keypair(&self) -> libp2p::identity::Keypair {
        panic!("wtf?");
    }

    fn to_public(&self) -> libp2p::identity::PublicKey {
        let public_key = self.to_bytes();
        let public_key = libp2p::identity::ed25519::PublicKey::decode(&public_key[..]).unwrap();
        libp2p::identity::PublicKey::Ed25519(public_key.into())
    }
}
