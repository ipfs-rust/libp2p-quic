use crate::endpoint::ConnectionChannel;
use crate::noise::ToLibp2p;
use async_io::Timer;
use fnv::FnvHashMap;
use futures::prelude::*;
use libp2p::core::muxing::{StreamMuxer, StreamMuxerEvent};
use libp2p::{Multiaddr, PeerId};
use parking_lot::Mutex;
use quinn_noise::NoiseSession;
use quinn_proto::crypto::Session;
use quinn_proto::generic::Connection;
use quinn_proto::{
    ConnectionError, Dir, Event, FinishError, ReadError, ReadableError, StreamEvent, StreamId,
    VarInt, WriteError,
};
use std::collections::VecDeque;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Instant;
use thiserror::Error;

/// State for a single opened QUIC connection.
#[derive(Debug)]
pub struct QuicMuxer {
    inner: Mutex<QuicMuxerInner>,
}

/// Mutex protected fields of [`QuicMuxer`].
#[derive(Debug)]
struct QuicMuxerInner {
    /// Endpoint channel.
    endpoint: ConnectionChannel,
    /// Inner connection object that yields events.
    connection: Connection<NoiseSession>,
    /// Connection waker.
    waker: Option<Waker>,
    /// Connection timer.
    timer: Option<Timer>,
    /// State of all open substreams.
    substreams: FnvHashMap<StreamId, SubstreamState>,
    /// Pending substreams.
    pending_substreams: VecDeque<Waker>,
    /// Close waker.
    close_waker: Option<Waker>,
}

/// State of a single substream.
#[derive(Debug, Default)]
struct SubstreamState {
    /// Waker to wake if the substream becomes readable.
    read_waker: Option<Waker>,
    /// Waker to wake if the substream becomes writable.
    write_waker: Option<Waker>,
}

impl QuicMuxer {
    pub fn new(endpoint: ConnectionChannel, connection: Connection<NoiseSession>) -> Self {
        Self {
            inner: Mutex::new(QuicMuxerInner {
                endpoint,
                connection,
                waker: None,
                timer: None,
                substreams: Default::default(),
                pending_substreams: Default::default(),
                close_waker: None,
            }),
        }
    }

    pub fn is_handshaking(&self) -> bool {
        self.inner.lock().connection.is_handshaking()
    }

    pub fn peer_id(&self) -> Option<PeerId> {
        self.inner
            .lock()
            .connection
            .crypto_session()
            .peer_identity()
            .map(|pk| pk.to_peer_id())
    }

    pub fn local_addr(&self) -> Multiaddr {
        let inner = self.inner.lock();
        let ip = inner
            .connection
            .local_ip()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let addr = SocketAddr::new(ip, inner.endpoint.port());
        crate::transport::socketaddr_to_multiaddr(&addr)
    }

    pub fn remote_addr(&self) -> Multiaddr {
        let inner = self.inner.lock();
        let addr = inner.connection.remote_address();
        crate::transport::socketaddr_to_multiaddr(&addr)
    }
}

impl StreamMuxer for QuicMuxer {
    type Substream = StreamId;
    type OutboundSubstream = ();
    type Error = QuicMuxerError;

    fn poll_event(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<StreamMuxerEvent<Self::Substream>, Self::Error>> {
        let mut inner = self.inner.lock();
        let now = Instant::now();

        while let Poll::Ready(event) = inner.endpoint.poll_channel_events(cx) {
            inner.connection.handle_event(event);
        }

        let max_datagrams = inner.endpoint.max_datagrams();
        while let Some(transmit) = inner.connection.poll_transmit(now, max_datagrams) {
            inner.endpoint.send_transmit(transmit);
        }

        loop {
            if let Some(timer) = inner.timer.as_mut() {
                match Pin::new(timer).poll(cx) {
                    Poll::Ready(expired) => {
                        inner.connection.handle_timeout(expired);
                        inner.timer = None;
                    }
                    Poll::Pending => break,
                }
            } else if let Some(when) = inner.connection.poll_timeout() {
                inner.timer = Some(Timer::at(when));
            } else {
                break;
            }
        }

        while let Some(event) = inner.connection.poll_endpoint_events() {
            inner.endpoint.send_endpoint_event(event);
        }

        while let Some(event) = inner.connection.poll() {
            match event {
                Event::HandshakeDataReady => {}
                Event::Connected => {
                    // Break here so that the noise upgrade can finish.
                    return Poll::Pending;
                }
                Event::ConnectionLost { reason } => {
                    tracing::debug!("connection lost because of {}", reason);
                    inner.substreams.clear();
                    if let Some(waker) = inner.close_waker.take() {
                        waker.wake();
                    }
                    return Poll::Ready(Err(QuicMuxerError::ConnectionLost { reason }));
                }
                Event::Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
                    // handled at end.
                }
                Event::Stream(StreamEvent::Readable { id }) => {
                    tracing::trace!("stream readable {}", id);
                    if let Some(substream) = inner.substreams.get_mut(&id) {
                        if let Some(waker) = substream.read_waker.take() {
                            waker.wake();
                        }
                    }
                }
                Event::Stream(StreamEvent::Writable { id }) => {
                    tracing::trace!("stream writable {}", id);
                    if let Some(substream) = inner.substreams.get_mut(&id) {
                        if let Some(waker) = substream.write_waker.take() {
                            waker.wake();
                        }
                    }
                }
                Event::Stream(StreamEvent::Finished { id }) => {
                    tracing::trace!("stream finished {}", id);
                    if let Some(substream) = inner.substreams.get_mut(&id) {
                        if let Some(waker) = substream.read_waker.take() {
                            waker.wake();
                        }
                        if let Some(waker) = substream.write_waker.take() {
                            waker.wake();
                        }
                    }
                }
                Event::Stream(StreamEvent::Stopped { id, error_code }) => {
                    tracing::debug!("substream {} stopped with error {}", id, error_code);
                    inner.substreams.remove(&id);
                    return Poll::Ready(Err(QuicMuxerError::StreamStopped { id, error_code }));
                }
                Event::Stream(StreamEvent::Available { dir: Dir::Bi }) => {
                    tracing::trace!("stream available");
                    if let Some(waker) = inner.pending_substreams.pop_front() {
                        waker.wake();
                    }
                }
                Event::Stream(StreamEvent::Opened { dir: Dir::Uni })
                | Event::Stream(StreamEvent::Available { dir: Dir::Uni })
                | Event::DatagramReceived => {
                    // We don't use datagrams or unidirectional streams. If these events
                    // happen, it is by some code not compatible with libp2p-quic.
                    inner
                        .connection
                        .close(Instant::now(), From::from(0u32), Default::default());
                    return Poll::Ready(Err(QuicMuxerError::ProtocolViolation));
                }
            }
        }

        // TODO quinn doesn't support `StreamMuxerEvent::AddressChange`.

        if let Some(id) = inner.connection.streams().accept(Dir::Bi) {
            inner.substreams.insert(id, Default::default());
            tracing::trace!("opened incoming substream {}", id);
            return Poll::Ready(Ok(StreamMuxerEvent::InboundSubstream(id)));
        }

        if inner.substreams.is_empty() {
            if let Some(waker) = inner.close_waker.take() {
                waker.wake();
            }
        }

        inner.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn open_outbound(&self) -> Self::OutboundSubstream {}

    fn poll_outbound(
        &self,
        cx: &mut Context,
        _: &mut Self::OutboundSubstream,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let mut inner = self.inner.lock();
        if let Some(id) = inner.connection.streams().open(Dir::Bi) {
            tracing::trace!("opened outgoing substream {}", id);
            inner.substreams.insert(id, Default::default());
            if let Some(waker) = inner.pending_substreams.pop_front() {
                waker.wake();
            }
            Poll::Ready(Ok(id))
        } else {
            inner.pending_substreams.push_back(cx.waker().clone());
            Poll::Pending
        }
    }

    fn destroy_outbound(&self, _: Self::OutboundSubstream) {}

    fn read_substream(
        &self,
        cx: &mut Context,
        id: &mut Self::Substream,
        mut buf: &mut [u8],
    ) -> Poll<Result<usize, Self::Error>> {
        let mut inner = self.inner.lock();
        let mut stream = inner.connection.recv_stream(*id);
        let mut chunks = match stream.read(true) {
            Ok(chunks) => chunks,
            Err(ReadableError::UnknownStream) => {
                return Poll::Ready(Err(QuicMuxerError::UnknownStream { id: *id }))
            }
            Err(ReadableError::IllegalOrderedRead) => {
                panic!("Illegal ordered read can only happen if `stream.read(false)` is used.");
            }
        };
        let mut bytes = 0;
        let mut pending = false;
        loop {
            if buf.is_empty() {
                break;
            }
            match chunks.next(buf.len()) {
                Ok(Some(chunk)) => {
                    buf.write_all(&chunk.bytes).expect("enough buffer space");
                    bytes += chunk.bytes.len();
                }
                Ok(None) => break,
                Err(ReadError::Reset(error_code)) => {
                    tracing::debug!("substream {} was reset with error code {}", id, error_code);
                    bytes = 0;
                    break;
                }
                Err(ReadError::Blocked) => {
                    pending = true;
                    break;
                }
            }
        }
        if chunks.finalize().should_transmit() {
            if let Some(waker) = inner.waker.take() {
                waker.wake();
            }
        }
        let substream = inner.substreams.get_mut(&id).unwrap();
        if pending && bytes == 0 {
            substream.read_waker = Some(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(Ok(bytes))
        }
    }

    fn write_substream(
        &self,
        cx: &mut Context,
        id: &mut Self::Substream,
        buf: &[u8],
    ) -> Poll<Result<usize, Self::Error>> {
        let mut inner = self.inner.lock();
        match inner.connection.send_stream(*id).write(buf) {
            Ok(bytes) => Poll::Ready(Ok(bytes)),
            Err(WriteError::Blocked) => {
                let mut substream = inner.substreams.get_mut(id).unwrap();
                substream.write_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Err(WriteError::Stopped(_)) => Poll::Ready(Ok(0)),
            Err(WriteError::UnknownStream) => {
                Poll::Ready(Err(QuicMuxerError::UnknownStream { id: *id }))
            }
        }
    }

    fn shutdown_substream(
        &self,
        _: &mut Context,
        id: &mut Self::Substream,
    ) -> Poll<Result<(), Self::Error>> {
        tracing::trace!("closing substream {}", id);
        // closes the write end of the substream without waiting for the remote to receive the
        // event. use flush substream to wait for the remote to receive the event.
        let mut inner = self.inner.lock();
        match inner.connection.send_stream(*id).finish() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(FinishError::Stopped(_)) => Poll::Ready(Ok(())),
            Err(FinishError::UnknownStream) => {
                Poll::Ready(Err(QuicMuxerError::UnknownStream { id: *id }))
            }
        }
    }

    fn destroy_substream(&self, id: Self::Substream) {
        tracing::trace!("destroying substream {}", id);
        let mut inner = self.inner.lock();
        inner.substreams.remove(&id);
        let mut stream = inner.connection.recv_stream(id);
        let should_transmit = if let Ok(mut chunks) = stream.read(true) {
            while let Ok(Some(_)) = chunks.next(usize::MAX) {}
            chunks.finalize().should_transmit()
        } else {
            false
        };
        if should_transmit {
            if let Some(waker) = inner.waker.take() {
                waker.wake();
            }
        }
    }

    fn flush_substream(
        &self,
        _cx: &mut Context,
        _id: &mut Self::Substream,
    ) -> Poll<Result<(), Self::Error>> {
        // quinn doesn't support flushing, calling close will flush all substreams.
        Poll::Ready(Ok(()))
    }

    fn flush_all(&self, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        // quinn doesn't support flushing, calling close will flush all substreams.
        Poll::Ready(Ok(()))
    }

    fn close(&self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        tracing::trace!("closing muxer");
        let mut inner = self.inner.lock();
        if inner.substreams.is_empty() {
            return Poll::Ready(Ok(()));
        }
        inner.close_waker = Some(cx.waker().clone());
        let inner = &mut *inner;
        for id in inner.substreams.keys() {
            let _ = inner.connection.send_stream(*id).finish();
        }
        Poll::Pending
    }
}

#[derive(Debug, Error)]
pub enum QuicMuxerError {
    #[error("connection was lost because of {reason}")]
    ConnectionLost { reason: ConnectionError },
    #[error("unsupported quic feature used")]
    ProtocolViolation,
    #[error("stream {id} stopped with error {error_code}")]
    StreamStopped { id: StreamId, error_code: VarInt },
    #[error("unknown stream {id}")]
    UnknownStream { id: StreamId },
}

impl From<QuicMuxerError> for std::io::Error {
    fn from(err: QuicMuxerError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, err)
    }
}
