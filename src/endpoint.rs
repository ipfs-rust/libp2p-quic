use crate::crypto::{Crypto, CryptoConfig};
use crate::muxer::QuicMuxer;
use crate::{QuicConfig, QuicError};
use ed25519_dalek::PublicKey;
use fnv::FnvHashMap;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use quinn_proto::crypto::Session;
use quinn_proto::generic::{ClientConfig, ServerConfig};
use quinn_proto::{
    ConnectionEvent, ConnectionHandle, DatagramEvent, EcnCodepoint, EndpointEvent, Transmit,
};
use std::collections::VecDeque;
use std::io::IoSliceMut;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use udp_socket::{RecvMeta, SocketType, UdpCapabilities, UdpSocket, BATCH_SIZE};

/// Message sent to the endpoint background task.
#[derive(Debug)]
enum ToEndpoint<C: Crypto> {
    /// Instructs the endpoint to start connecting to the given address.
    Dial {
        /// UDP address to connect to.
        addr: SocketAddr,
        /// The remotes public key.
        public_key: PublicKey,
        /// Channel to return the result of the dialing to.
        tx: oneshot::Sender<Result<QuicMuxer<C>, QuicError>>,
    },
    /// Sent by a `quinn_proto` connection when the endpoint needs to process an event generated
    /// by a connection. The event itself is opaque to us.
    ConnectionEvent {
        connection_id: ConnectionHandle,
        event: EndpointEvent,
    },
    /// Instruct the endpoint to transmit a packet on its UDP socket.
    Transmit(Transmit),
}

#[derive(Debug)]
pub struct TransportChannel<C: Crypto> {
    tx: mpsc::UnboundedSender<ToEndpoint<C>>,
    rx: mpsc::UnboundedReceiver<Result<QuicMuxer<C>, QuicError>>,
    port: u16,
    ty: SocketType,
}

impl<C: Crypto> TransportChannel<C> {
    pub fn dial(
        &mut self,
        addr: SocketAddr,
        public_key: PublicKey,
    ) -> oneshot::Receiver<Result<QuicMuxer<C>, QuicError>> {
        let (tx, rx) = oneshot::channel();
        let msg = ToEndpoint::Dial {
            addr,
            public_key,
            tx,
        };
        self.tx.unbounded_send(msg).expect("endpoint has crashed");
        rx
    }

    pub fn poll_incoming(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Option<Result<QuicMuxer<C>, QuicError>>> {
        Pin::new(&mut self.rx).poll_next(cx)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn ty(&self) -> SocketType {
        self.ty
    }
}

#[derive(Debug)]
pub struct ConnectionChannel<C: Crypto> {
    id: ConnectionHandle,
    tx: mpsc::UnboundedSender<ToEndpoint<C>>,
    rx: mpsc::UnboundedReceiver<ConnectionEvent>,
    port: u16,
    max_datagrams: usize,
}

impl<C: Crypto> ConnectionChannel<C> {
    pub fn poll_channel_events(&mut self, cx: &mut Context) -> Poll<ConnectionEvent> {
        match Pin::new(&mut self.rx).poll_next(cx) {
            Poll::Ready(Some(event)) => Poll::Ready(event),
            Poll::Ready(None) => panic!("endpoint has crashed"),
            Poll::Pending => Poll::Pending,
        }
    }

    pub fn send_endpoint_event(&mut self, event: EndpointEvent) {
        let msg = ToEndpoint::ConnectionEvent {
            connection_id: self.id,
            event,
        };
        self.tx.unbounded_send(msg).expect("endpoint has crashed")
    }

    pub fn send_transmit(&mut self, transmit: Transmit) {
        let msg = ToEndpoint::Transmit(transmit);
        self.tx.unbounded_send(msg).expect("endpoint has crashed")
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn max_datagrams(&self) -> usize {
        self.max_datagrams
    }
}

#[derive(Debug)]
struct EndpointChannel<C: Crypto> {
    rx: mpsc::UnboundedReceiver<ToEndpoint<C>>,
    tx: mpsc::UnboundedSender<Result<QuicMuxer<C>, QuicError>>,
    port: u16,
    max_datagrams: usize,
    connection_tx: mpsc::UnboundedSender<ToEndpoint<C>>,
}

impl<C: Crypto> EndpointChannel<C> {
    pub fn send_incoming(&mut self, muxer: QuicMuxer<C>) {
        self.tx.unbounded_send(Ok(muxer)).ok();
    }

    pub fn poll_next_event(&mut self, cx: &mut Context) -> Poll<Option<ToEndpoint<C>>> {
        Pin::new(&mut self.rx).poll_next(cx)
    }

    pub fn create_connection(
        &self,
        id: ConnectionHandle,
    ) -> (ConnectionChannel<C>, mpsc::UnboundedSender<ConnectionEvent>) {
        let (tx, rx) = mpsc::unbounded();
        let channel = ConnectionChannel {
            id,
            tx: self.connection_tx.clone(),
            rx,
            port: self.port,
            max_datagrams: self.max_datagrams,
        };
        (channel, tx)
    }
}

type QuinnEndpointConfig<S> = quinn_proto::generic::EndpointConfig<S>;
type QuinnEndpoint<S> = quinn_proto::generic::Endpoint<S>;

pub struct EndpointConfig<C: Crypto> {
    socket: UdpSocket,
    endpoint: QuinnEndpoint<C::Session>,
    port: u16,
    crypto_config: Arc<CryptoConfig<C::Keylogger>>,
    capabilities: UdpCapabilities,
}

impl<C: Crypto> EndpointConfig<C> {
    pub fn new(mut config: QuicConfig<C>, addr: SocketAddr) -> Result<Self, QuicError> {
        config.transport.max_concurrent_uni_streams(0)?;
        config.transport.datagram_receive_buffer_size(None);
        let transport = Arc::new(config.transport);

        let crypto_config = Arc::new(CryptoConfig {
            keypair: config.keypair,
            psk: config.psk,
            keylogger: config.keylogger,
            transport: transport.clone(),
        });

        let mut server_config = ServerConfig::<C::Session>::default();
        server_config.transport = transport;
        server_config.crypto = C::new_server_config(&crypto_config);

        let mut endpoint_config = QuinnEndpointConfig::default();
        endpoint_config
            .supported_versions(C::supported_quic_versions(), C::default_quic_version())?;

        let socket = UdpSocket::bind(addr)?;
        let port = socket.local_addr()?.port();
        let endpoint = quinn_proto::generic::Endpoint::new(
            Arc::new(endpoint_config),
            Some(Arc::new(server_config)),
        );
        let capabilities = UdpSocket::capabilities()?;
        Ok(Self {
            socket,
            endpoint,
            port,
            crypto_config,
            capabilities,
        })
    }

    pub fn spawn(self) -> TransportChannel<C>
    where
        <C::Session as Session>::ClientConfig: Send + Unpin,
    {
        let (tx1, rx1) = mpsc::unbounded();
        let (tx2, rx2) = mpsc::unbounded();
        let transport = TransportChannel {
            tx: tx1,
            rx: rx2,
            port: self.port,
            ty: self.socket.socket_type(),
        };
        let endpoint = EndpointChannel {
            tx: tx2,
            rx: rx1,
            port: self.port,
            max_datagrams: self.capabilities.max_gso_segments,
            connection_tx: transport.tx.clone(),
        };
        async_global_executor::spawn(Endpoint::new(endpoint, self)).detach();
        transport
    }
}

struct Endpoint<C: Crypto> {
    channel: EndpointChannel<C>,
    endpoint: QuinnEndpoint<C::Session>,
    socket: UdpSocket,
    crypto_config: Arc<CryptoConfig<C::Keylogger>>,
    connections: FnvHashMap<ConnectionHandle, mpsc::UnboundedSender<ConnectionEvent>>,
    outgoing: VecDeque<udp_socket::Transmit>,
    recv_buf: Box<[u8]>,
}

impl<C: Crypto> Endpoint<C> {
    pub fn new(channel: EndpointChannel<C>, config: EndpointConfig<C>) -> Self {
        let max_udp_payload_size = config
            .endpoint
            .config()
            .get_max_udp_payload_size()
            .min(u16::MAX as _) as usize;
        let recv_buf = vec![0; max_udp_payload_size * BATCH_SIZE].into_boxed_slice();
        Self {
            channel,
            endpoint: config.endpoint,
            socket: config.socket,
            crypto_config: config.crypto_config,
            connections: Default::default(),
            outgoing: Default::default(),
            recv_buf,
        }
    }

    pub fn transmit(&mut self, transmit: Transmit) {
        let ecn = transmit
            .ecn
            .map(|ecn| udp_socket::EcnCodepoint::from_bits(ecn as u8))
            .unwrap_or_default();
        let transmit = udp_socket::Transmit {
            destination: transmit.destination,
            contents: transmit.contents,
            ecn,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        };
        self.outgoing.push_back(transmit);
    }
}

impl<C: Crypto> Future for Endpoint<C>
where
    <C::Session as Session>::ClientConfig: Unpin,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let me = Pin::into_inner(self);

        while let Some(transmit) = me.endpoint.poll_transmit() {
            me.transmit(transmit);
        }

        while let Poll::Ready(event) = me.channel.poll_next_event(cx) {
            match event {
                Some(ToEndpoint::Dial {
                    addr,
                    public_key,
                    tx,
                }) => {
                    let crypto = C::new_client_config(&me.crypto_config, public_key);
                    let client_config = ClientConfig {
                        transport: me.crypto_config.transport.clone(),
                        crypto,
                    };
                    let (id, connection) =
                        match me.endpoint.connect(client_config, addr, "server_name") {
                            Ok(c) => c,
                            Err(err) => {
                                tracing::error!("dial failure: {}", err);
                                let _ = tx.send(Err(err.into()));
                                continue;
                            }
                        };
                    let (channel, conn) = me.channel.create_connection(id);
                    me.connections.insert(id, conn);
                    let muxer = QuicMuxer::new(channel, connection);
                    tx.send(Ok(muxer)).ok();
                }
                Some(ToEndpoint::ConnectionEvent {
                    connection_id,
                    event,
                }) => {
                    let is_drained_event = event.is_drained();
                    if is_drained_event {
                        me.connections.remove(&connection_id);
                    }
                    if let Some(event) = me.endpoint.handle_event(connection_id, event) {
                        me.connections
                            .get_mut(&connection_id)
                            .unwrap()
                            .unbounded_send(event)
                            .ok();
                    }
                }
                Some(ToEndpoint::Transmit(transmit)) => {
                    me.transmit(transmit);
                }
                None => {
                    me.endpoint.reject_new_connections();
                    return Poll::Ready(());
                }
            }
        }

        while !me.outgoing.is_empty() {
            me.outgoing.make_contiguous();
            match me.socket.poll_send(cx, me.outgoing.as_slices().0) {
                Poll::Ready(Ok(n)) => {
                    me.outgoing.drain(..n);
                }
                Poll::Ready(Err(err)) => tracing::error!("send_to: {}", err),
                Poll::Pending => break,
            }
        }

        let mut metas = [RecvMeta::default(); BATCH_SIZE];
        let mut iovs = MaybeUninit::<[IoSliceMut; BATCH_SIZE]>::uninit();
        me.recv_buf
            .chunks_mut(me.recv_buf.len() / BATCH_SIZE)
            .enumerate()
            .for_each(|(i, buf)| unsafe {
                iovs.as_mut_ptr()
                    .cast::<IoSliceMut>()
                    .add(i)
                    .write(IoSliceMut::new(buf));
            });
        let mut iovs = unsafe { iovs.assume_init() };
        while let Poll::Ready(result) = me.socket.poll_recv(cx, &mut iovs, &mut metas) {
            let n = match result {
                Ok(n) => n,
                Err(err) => {
                    tracing::error!("recv_from: {}", err);
                    continue;
                }
            };
            for i in 0..n {
                let meta = &metas[i];
                let packet = From::from(&iovs[i][..meta.len]);
                let ecn = meta
                    .ecn
                    .map(|ecn| EcnCodepoint::from_bits(ecn as u8))
                    .unwrap_or_default();
                match me
                    .endpoint
                    .handle(Instant::now(), meta.source, meta.dst_ip, ecn, packet)
                {
                    None => {}
                    Some((id, DatagramEvent::ConnectionEvent(event))) => {
                        me.connections
                            .get_mut(&id)
                            .unwrap()
                            .unbounded_send(event)
                            .ok();
                    }
                    Some((id, DatagramEvent::NewConnection(connection))) => {
                        let (channel, tx) = me.channel.create_connection(id);
                        me.connections.insert(id, tx);
                        let muxer = QuicMuxer::new(channel, connection);
                        let _ = me.channel.send_incoming(muxer);
                    }
                }
            }
        }

        Poll::Pending
    }
}
