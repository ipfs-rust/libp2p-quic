use crate::muxer::QuicMuxer;
use crate::noise::{NoiseConfig, NoiseSession};
use crate::{QuicConfig, QuicError};
use fnv::FnvHashMap;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use quinn_proto::generic::{ClientConfig, EndpointConfig, ServerConfig};
use quinn_proto::{
    ConnectionEvent, ConnectionHandle, DatagramEvent, EcnCodepoint, EndpointEvent, Transmit,
};
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use udp_socket::{RecvMeta, UdpCapabilities, UdpSocket};

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
    max_datagrams: usize,
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

    pub fn max_datagrams(&self) -> usize {
        self.max_datagrams
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

pub struct Endpoint {
    socket: UdpSocket,
    endpoint: QuinnEndpoint,
    port: u16,
    client_config: ClientConfig<NoiseSession>,
    capabilities: UdpCapabilities,
}

impl Endpoint {
    pub fn new(mut config: QuicConfig, addr: SocketAddr) -> Result<Self, QuicError> {
        config.transport.max_concurrent_uni_streams(0)?;
        config.transport.datagram_receive_buffer_size(None);
        let transport = Arc::new(config.transport);

        let mut server_config = ServerConfig::<NoiseSession>::default();
        server_config.transport = transport.clone();
        server_config.crypto = NoiseConfig {
            params: config.noise.clone(),
            keypair: config.keypair.clone(),
            prologue: config.prologue.clone(),
        };

        let client_config = ClientConfig::<NoiseSession> {
            transport,
            crypto: NoiseConfig {
                params: config.noise,
                keypair: config.keypair,
                prologue: config.prologue,
            },
        };

        let endpoint_config = EndpointConfig::default();

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
            client_config,
            capabilities,
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
            self.capabilities,
        ))
        .detach();
        transport
    }
}

async fn background_task(
    mut endpoint_channel: EndpointChannel,
    mut endpoint: QuinnEndpoint,
    socket: UdpSocket,
    client_config: ClientConfig<NoiseSession>,
    connection_tx: mpsc::UnboundedSender<ToEndpoint>,
    capabilities: UdpCapabilities,
) {
    let mut connections = FnvHashMap::<ConnectionHandle, mpsc::UnboundedSender<_>>::default();
    let mut recv_buffer = vec![0; 65536];
    let buffers = &mut [IoSliceMut::new(&mut recv_buffer[..])][..];
    let meta = &mut [RecvMeta::default()][..];

    loop {
        if let Some(transmit) = endpoint.poll_transmit() {
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
            match socket.send(&[transmit]).await {
                Ok(1) => {}
                Ok(_) => tracing::error!("send_to: partially transfered packet"),
                Err(err) => tracing::error!("send_to: {}", err),
            }
        }

        futures::select! {
            message = endpoint_channel.next_event().fuse() => {
                match message {
                    Some(ToEndpoint::Dial { addr, tx: dial_tx }) => {
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
                            max_datagrams: capabilities.max_gso_segments,
                        };
                        let muxer = QuicMuxer::new(channel, connection);
                        let _ = dial_tx.send(Ok(muxer));
                    }
                    Some(ToEndpoint::ConnectionEvent { connection_id, event }) => {
                        let is_drained_event = event.is_drained();
                        if is_drained_event {
                            connections.remove(&connection_id);
                        }
                        if let Some(event) = endpoint.handle_event(connection_id, event) {
                            connections.get_mut(&connection_id).unwrap().unbounded_send(event).ok();
                        }
                    }
                    Some(ToEndpoint::Transmit(transmit)) => {
                        tracing::trace!(
                            "transmit: dst: {} src: {:?} ecn: {:?} segment_size: {:?} len: {}",
                            transmit.destination, transmit.src_ip, transmit.ecn,
                            transmit.segment_size, transmit.contents.len());
                        let ecn = transmit.ecn.map(|ecn| udp_socket::EcnCodepoint::from_bits(ecn as u8)).unwrap_or_default();
                        let transmit = udp_socket::Transmit {
                            destination: transmit.destination,
                            contents: transmit.contents,
                            ecn,
                            segment_size: transmit.segment_size,
                            src_ip: transmit.src_ip,
                        };
                        match socket.send(&[transmit]).await {
                            Ok(1) => {}
                            Ok(_) => tracing::error!("send_to: partially transfered packet"),
                            Err(err) => {
                                tracing::error!("send_to: {}", err);
                            }
                        }
                    }
                    None => return,
                }
            }
            result = socket.recv(buffers, meta).fuse() => {
                let n = match result {
                    Ok(n) => n,
                    Err(err) => {
                        tracing::error!("recv_from: {}", err);
                        continue;
                    },
                };
                for i in 0..n {
                    let meta = &meta[i];
                    let packet = From::from(&buffers[i][..meta.len]);
                    let ecn = meta.ecn.map(|ecn| EcnCodepoint::from_bits(ecn as u8)).unwrap_or_default();
                    match endpoint.handle(Instant::now(), meta.source, meta.dst_ip, ecn, packet) {
                        None => {},
                        Some((id, DatagramEvent::ConnectionEvent(event))) => {
                            connections.get_mut(&id).unwrap().unbounded_send(event).ok();
                        },
                        Some((id, DatagramEvent::NewConnection(connection))) => {
                            let (tx, rx) = mpsc::unbounded();
                            connections.insert(id, tx);
                            let channel = ConnectionChannel {
                                id,
                                tx: connection_tx.clone(),
                                rx,
                                port: endpoint_channel.port(),
                                max_datagrams: capabilities.max_gso_segments,
                            };
                            let muxer = QuicMuxer::new(channel, connection);
                            let _ = endpoint_channel.send_incoming(muxer);
                        }
                    }
                }
            }
        }
    }
}
