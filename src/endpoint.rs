use crate::muxer::QuicMuxer;
use crate::noise::NoiseSession;
use crate::transport::QuicConfig;
use async_io::Async;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use quinn_proto::generic::{ClientConfig, Connection, ServerConfig};
use quinn_proto::{
    ConfigError, ConnectError, ConnectionEvent, ConnectionHandle, EndpointEvent, Transmit,
    TransportConfig,
};
use std::net::{SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
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

pub struct EndpointChannel {
    rx: mpsc::UnboundedReceiver<ToEndpoint>,
    tx: mpsc::UnboundedSender<Result<QuicMuxer, QuicError>>,
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

pub struct Endpoint {
    config: QuicConfig,
    addr: SocketAddr,
}

impl Endpoint {
    pub fn new(config: QuicConfig, addr: SocketAddr) -> Result<Self, QuicError> {
        Ok(Endpoint { config, addr })
    }

    pub fn spawn(self) -> Result<TransportChannel, QuicError> {
        /*let mut transport = TransportConfig::default();
        transport.max_concurrent_uni_streams(0)?;
        let transport = Arc::new(transport);
        let server_config = ServerConfig {
            transport: transport.clone(),
            crypto: (),
        };
        let client_config = ClientConfig {
            transport,
            crypto: (),
        };

        let socket = UdpSocket::bind(self.addr)?;
        let local_socket_addr = socket.local_addr()?;
        let socket = Async::new(socket)?;*/
        todo!()
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
