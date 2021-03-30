use crate::muxer::QuicMuxer;
use crate::noise::NoiseSession;
use crate::transport::QuicConfig;
use async_io::Async;
use fnv::FnvHashMap;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use quinn_proto::generic::{ClientConfig, EndpointConfig, ServerConfig};
use quinn_proto::{
    ConfigError, ConnectError, ConnectionEvent, ConnectionHandle, DatagramEvent, EndpointEvent,
    Transmit, TransportConfig,
};
use std::net::{SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use thiserror::Error;

/// Message sent to the endpoint background task.
#[derive(Debug)]
enum ToEndpoint {
    /// Instructs the endpoint to start connecting to the given address.
    Dial {
        /// UDP address to connect to.
        addr: SocketAddr,
        /// Channel to return the result of the dialing to.
        tx: oneshot::Sender<Result<QuicMuxer, QuicError>>,
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
pub struct TransportChannel {
    tx: mpsc::UnboundedSender<ToEndpoint>,
    rx: mpsc::UnboundedReceiver<Result<QuicMuxer, QuicError>>,
    port: u16,
}

impl TransportChannel {
    pub fn dial(&mut self, addr: SocketAddr) -> oneshot::Receiver<Result<QuicMuxer, QuicError>> {
        let (tx, rx) = oneshot::channel();
        let msg = ToEndpoint::Dial { addr, tx };
        self.tx.unbounded_send(msg).expect("endpoint has crashed");
        rx
    }

    pub fn poll_incoming(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Option<Result<QuicMuxer, QuicError>>> {
        Pin::new(&mut self.rx).poll_next(cx)
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Debug)]
pub struct ConnectionChannel {
    id: ConnectionHandle,
    tx: mpsc::UnboundedSender<ToEndpoint>,
    rx: mpsc::UnboundedReceiver<ConnectionEvent>,
    port: u16,
}

impl ConnectionChannel {
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
}

#[derive(Debug)]
struct EndpointChannel {
    rx: mpsc::UnboundedReceiver<ToEndpoint>,
    tx: mpsc::UnboundedSender<Result<QuicMuxer, QuicError>>,
    port: u16,
}

impl EndpointChannel {
    pub fn send_incoming(&mut self, muxer: QuicMuxer) {
        self.tx.unbounded_send(Ok(muxer)).ok();
    }

    pub async fn next_event(&mut self) -> Option<ToEndpoint> {
        self.rx.next().await
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

type QuinnEndpoint = quinn_proto::generic::Endpoint<NoiseSession>;

#[derive(Debug)]
pub struct Endpoint {
    socket: Async<UdpSocket>,
    endpoint: QuinnEndpoint,
    port: u16,
    client_config: ClientConfig<NoiseSession>,
}

impl Endpoint {
    pub fn new(_config: QuicConfig, addr: SocketAddr) -> Result<Self, QuicError> {
        let mut transport = TransportConfig::default();
        transport.max_concurrent_uni_streams(0)?;
        let transport = Arc::new(transport);

        let mut server_config = ServerConfig::default();
        server_config.transport = transport.clone();

        let mut client_config = ClientConfig::default();
        client_config.transport = transport;

        let endpoint_config = EndpointConfig::default();

        let socket = UdpSocket::bind(addr)?;
        let port = socket.local_addr()?.port();
        let socket = Async::new(socket)?;
        let endpoint = quinn_proto::generic::Endpoint::new(
            Arc::new(endpoint_config),
            Some(Arc::new(server_config)),
        );
        Ok(Self {
            socket,
            endpoint,
            port,
            client_config,
        })
    }

    pub fn spawn(self) -> TransportChannel {
        let (tx1, rx1) = mpsc::unbounded();
        let (tx2, rx2) = mpsc::unbounded();
        let transport = TransportChannel {
            tx: tx1,
            rx: rx2,
            port: self.port,
        };
        let endpoint = EndpointChannel {
            tx: tx2,
            rx: rx1,
            port: self.port,
        };
        let connection_tx = transport.tx.clone();
        async_global_executor::spawn(background_task(
            endpoint,
            self.endpoint,
            self.socket,
            self.client_config,
            connection_tx,
        ))
        .detach();
        transport
    }
}

#[derive(Debug, Error)]
pub enum QuicError {
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("{0}")]
    Connect(#[from] ConnectError),
    #[error("{0}")]
    Muxer(#[from] crate::muxer::QuicMuxerError),
    #[error("{0}")]
    Noise(#[from] crate::noise::NoiseUpgradeError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

async fn background_task(
    mut endpoint_channel: EndpointChannel,
    mut endpoint: QuinnEndpoint,
    socket: Async<UdpSocket>,
    client_config: ClientConfig<NoiseSession>,
    connection_tx: mpsc::UnboundedSender<ToEndpoint>,
) {
    let mut connections = FnvHashMap::<ConnectionHandle, mpsc::UnboundedSender<_>>::default();
    let mut socket_recv_buffer = vec![0; 65536];

    loop {
        if let Some(transmit) = endpoint.poll_transmit() {
            tracing::trace!("sending endpoint packet");
            // TODO: set ECN
            // TODO: set src_ip
            // TODO: segment_size
            match socket
                .send_to(&transmit.contents, transmit.destination)
                .await
            {
                Ok(n) if n == transmit.contents.len() => {}
                Ok(_) => tracing::error!("send_to: partially transfered packet"),
                Err(err) => tracing::error!("send_to: {}", err),
            }
        }

        futures::select! {
            message = endpoint_channel.next_event().fuse() => {
                match message {
                    Some(ToEndpoint::Dial { addr, tx: dial_tx }) => {
                        tracing::trace!("dial");
                        let (id, connection) =
                            match endpoint.connect(client_config.clone(), addr, "server_name") {
                                Ok(c) => c,
                                Err(err) => {
                                    tracing::error!("dial failure: {}", err);
                                    let _ = dial_tx.send(Err(err.into()));
                                    continue;
                                }
                            };
                        let (tx, rx) = mpsc::unbounded();
                        connections.insert(id, tx);
                        let channel = ConnectionChannel {
                            id,
                            tx: connection_tx.clone(),
                            rx,
                            port: endpoint_channel.port(),
                        };
                        let muxer = QuicMuxer::new(channel, connection);
                        let _ = dial_tx.send(Ok(muxer));
                    }
                    Some(ToEndpoint::ConnectionEvent { connection_id, event }) => {
                        tracing::trace!("connection event");
                        let is_drained_event = event.is_drained();
                        if is_drained_event {
                            connections.remove(&connection_id);
                        }
                        if let Some(event) = endpoint.handle_event(connection_id, event) {
                            connections.get_mut(&connection_id).unwrap().unbounded_send(event).ok();
                        }
                    }
                    Some(ToEndpoint::Transmit(transmit)) => {
                        tracing::trace!("send connection packet");
                        // TODO: set ECN
                        // TODO: set src_ip
                        // TODO: segment_size
                        match socket.send_to(&transmit.contents, transmit.destination).await {
                            Ok(n) if n == transmit.contents.len() => {}
                            Ok(_) => tracing::error!("send_to: partially transfered packet"),
                            Err(err) => tracing::error!("send_to: {}", err),
                        }
                    }
                    None => return,
                }
            }
            result = socket.recv_from(&mut socket_recv_buffer).fuse() => {
                tracing::trace!("received packet");
                let (packet_len, packet_src) = match result {
                    Ok(v) => v,
                    Err(err) => {
                        tracing::error!("recv_from: {}", err);
                        continue;
                    },
                };
                let packet = From::from(&socket_recv_buffer[..packet_len]);
                // TODO: ECN
                // TODO: destination address
                match endpoint.handle(Instant::now(), packet_src, None, None, packet) {
                    None => {},
                    Some((id, DatagramEvent::ConnectionEvent(event))) => {
                        tracing::trace!("endpoint event");
                        connections.get_mut(&id).unwrap().unbounded_send(event).ok();
                    },
                    Some((id, DatagramEvent::NewConnection(connection))) => {
                        tracing::trace!("new connection");
                        let (tx, rx) = mpsc::unbounded();
                        connections.insert(id, tx);
                        let channel = ConnectionChannel {
                            id,
                            tx: connection_tx.clone(),
                            rx,
                            port: endpoint_channel.port(),
                        };
                        let muxer = QuicMuxer::new(channel, connection);
                        let _ = endpoint_channel.send_incoming(muxer);
                    },
                }
            }
        }
    }
}
