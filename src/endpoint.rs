use crate::muxer::QuicMuxer;
use crate::noise::NoiseSession;
use crate::transport::QuicConfig;
use async_io::Async;
use fnv::FnvHashMap;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use quinn_proto::generic::{ClientConfig, EndpointConfig, ServerConfig};
use quinn_proto::{
    ConfigError, ConnectError, ConnectionEvent, ConnectionHandle, EndpointEvent, Transmit,
    TransportConfig, Side, DatagramEvent,
};
use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use thiserror::Error;

/// Message sent to the endpoint background task.
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

struct EndpointChannel {
    rx: mpsc::UnboundedReceiver<ToEndpoint>,
    tx: mpsc::UnboundedSender<Result<QuicMuxer, QuicError>>,
    port: u16,
}

impl EndpointChannel {
    pub fn send_incoming(&mut self, muxer: QuicMuxer) {
        self.tx.unbounded_send(Ok(muxer)).ok();
    }

    pub fn poll_event(&mut self, cx: &mut Context) -> Poll<Option<ToEndpoint>> {
        Pin::new(&mut self.rx).poll_next(cx)
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

type QuinnEndpoint = quinn_proto::generic::Endpoint<NoiseSession>;

pub struct Endpoint {
    socket: Async<UdpSocket>,
    endpoint: QuinnEndpoint,
    port: u16,
    client_config: ClientConfig<NoiseSession>,
}

impl Endpoint {
    pub fn new(config: QuicConfig, addr: SocketAddr) -> Result<Self, QuicError> {
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
        async_global_executor::spawn(background_task(endpoint, self.endpoint, self.socket, self.client_config))
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
    Io(#[from] std::io::Error),
}

async fn background_task(
    channel: EndpointChannel,
    endpoint: QuinnEndpoint,
    socket: Async<UdpSocket>,
    client_config: ClientConfig<NoiseSession>,
) {
    /*
    // List of all active connections, with a sender to notify them of events.
    let mut alive_connections = FnvHashMap::<ConnectionHandle, mpsc::Sender<_>>::new();

    // Buffer where we write packets received from the UDP socket.
    let mut socket_recv_buffer = vec![0; 65536];

    loop {
        // Start by flushing `next_packet_out`.
        if let Some((destination, data)) = next_packet_out.take() {
            // We block the current task until the packet is sent. This way, if the
            // network interface is too busy, we back-pressure all of our internal
            // channels.
            // TODO: set ECN bits; there is no support for them in the ecosystem right now
            match udp_socket.send_to(&data, destination).await {
                Ok(n) if n == data.len() => {}
                Ok(_) => tracing::error!(
                    "QUIC UDP socket violated expectation that packets are always fully \
                      transferred"
                ),

                // Errors on the socket are expected to never happen, and we handle them by simply
                // printing a log message. The packet gets discarded in case of error, but we are
                // robust to packet losses and it is consequently not a logic error to process with
                // normal operations.
                Err(err) => tracing::error!("Error while sending on QUIC UDP socket: {:?}", err),
            }
        }

        // The endpoint might request packets to be sent out. This is handled in priority to avoid
        // buffering up packets.
        if let Some(packet) = endpoint.poll_transmit() {
            debug_assert!(next_packet_out.is_none());
            next_packet_out = Some((packet.destination, packet.contents.into_boxed_slice()));
            continue;
        }

        futures::select! {
            message = receiver.next() => {
                // Received a message from a different part of the code requesting us to
                // do something.
                match message {
                    // Shut down if the endpoint has shut down.
                    None => return,

                    Some(ToEndpoint::Dial { addr, tx }) => {
                        tracing::trace!("ToEndpoint::Dial({})", addr);
                        // This `"l"` seems necessary because an empty string is an invalid domain
                        // name. While we don't use domain names, the underlying rustls library
                        // is based upon the assumption that we do.
                        let (connection_id, connection) =
                            match endpoint.connect(config.client_config.clone(), addr, "l") {
                                Ok(c) => c,
                                Err(err) => {
                                    let _ = result.send(Err(err));
                                    continue;
                                }
                            };

                        let endpoint_arc = match endpoint_weak.upgrade() {
                            Some(ep) => ep,
                            None => return, // Shut down the task if the endpoint is dead.
                        };

                        debug_assert_eq!(connection.side(), Side::Client);
                        let (tx, rx) = mpsc::channel(16);
                        let connection = Connection::from_quinn_connection(endpoint_arc, connection, connection_id, rx);
                        alive_connections.insert(connection_id, tx);
                        let _ = result.send(Ok(connection));
                    }

                    // A connection wants to notify the endpoint of something.
                    Some(ToEndpoint::ConnectionEvent { connection_id, event }) => {
                        tracing::trace!("ToEndpoint::ProcessConnectionEvent({:?})", event);
                        debug_assert!(alive_connections.contains_key(&connection_id));
                        // We "drained" event indicates that the connection no longer exists and
                        // its ID can be reclaimed.
                        let is_drained_event = event.is_drained();
                        if is_drained_event {
                            alive_connections.remove(&connection_id);
                        }
                        if let Some(event_back) = endpoint.handle_event(connection_id, event) {
                            debug_assert!(!is_drained_event);
                            // TODO: don't await here /!\
                            alive_connections.get_mut(&connection_id).unwrap().send(event_back).await.ok();
                        }
                    }

                    // Data needs to be sent on the UDP socket.
                    Some(ToEndpoint::Transmit { destination, data }) => {
                        tracing::trace!("ToEndpoint::SendUdpPacket({})", destination);
                        debug_assert!(next_packet_out.is_none());
                        next_packet_out = Some((destination, data));
                        continue;
                    }
                }
            }

            // The future we create here wakes up if two conditions are fulfilled:
            //
            // - The `new_connections` channel is ready to accept a new element.
            // - `queued_new_connections` is not empty.
            //
            // When this happens, we pop an element from `queued_new_connections`, put it on the
            // channel, and call `endpoint.accept()`, thereby allowing the QUIC state machine to
            // feed a new incoming connection to us.
            readiness = {
                let active = !queued_new_connections.is_empty();
                let new_connections = &mut new_connections;
                future::poll_fn(move |cx| {
                    if active { new_connections.poll_ready(cx) } else { Poll::Pending }
                }).fuse()
            } => {
                if readiness.is_err() {
                    // new_connections channel has been dropped, meaning that the endpoint has
                    // been destroyed.
                    return;
                }

                let elem = queued_new_connections.pop_front()
                    .expect("if queue is empty, the future above is always Pending; qed");
                new_connections.start_send(elem)
                    .expect("future is waken up only if poll_ready returned Ready; qed");
            }

            result = udp_socket.recv_from(&mut socket_recv_buffer).fuse() => {
                let (packet_len, packet_src) = match result {
                    Ok(v) => v,
                    // Errors on the socket are expected to never happen, and we handle them by
                    // simply printing a log message.
                    Err(err) => {
                        log::error!("Error while receive on QUIC UDP socket: {:?}", err);
                        continue;
                    },
                };

                // Received a UDP packet from the socket.
                debug_assert!(packet_len <= socket_recv_buffer.len());
                let packet = From::from(&socket_recv_buffer[..packet_len]);
                // TODO: ECN bits aren't handled
                // TODO: destination address isn't handled (used when binding to 0.0.0.0)
                match endpoint.handle(Instant::now(), packet_src, None, None, packet) {
                    None => {},
                    Some((connec_id, DatagramEvent::ConnectionEvent(event))) => {
                        tracing::trace!("quinn_proto::DatagramEvent::ConnectionEvent");
                        // Event to send to an existing connection.
                        if let Some(sender) = alive_connections.get_mut(&connec_id) {
                            let _ = sender.send(event).await; // TODO: don't await here /!\
                        } else {
                            tracing::error!("State mismatch: event for closed connection");
                        }
                    },
                    Some((connec_id, DatagramEvent::NewConnection(connec))) => {
                        tracing::trace!("quinn_proto::DatagramEvent::NewConnection");
                        // A new connection has been received. `connec_id` is a newly-allocated
                        // identifier.
                        debug_assert_eq!(connec.side(), Side::Server);
                        let (tx, rx) = mpsc::channel(16);
                        alive_connections.insert(connec_id, tx);
                        let endpoint_arc = match endpoint_weak.upgrade() {
                            Some(ep) => ep,
                            None => return, // Shut down the task if the endpoint is dead.
                        };
                        let connection = Connection::from_quinn_connection(endpoint_arc, connec, connec_id, rx);

                        // As explained in the documentation, we put this new connection in an
                        // intermediary buffer. At the next loop iteration we will try to move it
                        // to the `new_connections` channel. We call `endpoint.accept()` only once
                        // the element has successfully been sent on `new_connections`.
                        queued_new_connections.push_back(connection);
                    },
                }
            }
        }
    }*/
}
