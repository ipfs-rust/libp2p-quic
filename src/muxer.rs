use crate::noise::NoiseSession;
use fnv::FnvHashMap;
use libp2p::core::muxing::{StreamMuxer, StreamMuxerEvent};
use quinn_proto::generic::Connection;
use quinn_proto::ConnectionId;
use std::task::{Context, Poll};
use thiserror::Error;

pub struct QuicMuxer {
    _connections: FnvHashMap<ConnectionId, Connection<NoiseSession>>,
}

impl StreamMuxer for QuicMuxer {
    type Substream = ConnectionId;
    type OutboundSubstream = ();
    type Error = QuicMuxerError;

    fn poll_event(
        &self,
        _cx: &mut Context,
    ) -> Poll<Result<StreamMuxerEvent<Self::Substream>, Self::Error>> {
        todo!()
    }

    fn open_outbound(&self) -> Self::OutboundSubstream {
        todo!()
    }

    fn poll_outbound(
        &self,
        _cx: &mut Context,
        _: &mut Self::OutboundSubstream,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        todo!()
    }

    fn destroy_outbound(&self, _: Self::OutboundSubstream) {
        todo!()
    }

    fn read_substream(
        &self,
        _: &mut Context,
        _: &mut Self::Substream,
        _: &mut [u8],
    ) -> Poll<Result<usize, Self::Error>> {
        todo!()
    }

    fn write_substream(
        &self,
        _: &mut Context,
        _: &mut Self::Substream,
        _: &[u8],
    ) -> Poll<Result<usize, Self::Error>> {
        todo!()
    }

    fn flush_substream(
        &self,
        _: &mut Context,
        _: &mut Self::Substream,
    ) -> Poll<Result<(), Self::Error>> {
        todo!()
    }

    fn shutdown_substream(
        &self,
        _: &mut Context,
        _: &mut Self::Substream,
    ) -> Poll<Result<(), Self::Error>> {
        todo!()
    }

    fn destroy_substream(&self, _: Self::Substream) {
        todo!()
    }

    fn close(&self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        todo!()
    }

    fn flush_all(&self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        todo!()
    }
}

#[derive(Debug, Error)]
pub enum QuicMuxerError {}

impl From<QuicMuxerError> for std::io::Error {
    fn from(err: QuicMuxerError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, err)
    }
}
