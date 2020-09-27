// Copyright 2017-2020 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Implementation of the [`Transport`] trait for QUIC.
//!
//! Combines all the objects in the other modules to implement the trait.

use crate::{endpoint::Endpoint, muxer::QuicMuxer, upgrade::Upgrade, x509};
use futures::prelude::*;
use get_if_addrs::{get_if_addrs, IfAddr};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use libp2p_core::{
    multiaddr::{Multiaddr, Protocol},
    transport::{ListenerEvent, TransportError},
    Dialer, PeerId, Transport,
};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

// We reexport the errors that are exposed in the API.
// All of these types use one another.
pub use crate::connection::Error as Libp2pQuicConnectionError;
pub use quinn_proto::{
    ApplicationClose, ConfigError, ConnectError, ConnectionClose, ConnectionError,
    TransportError as QuinnTransportError, TransportErrorCode,
};

/// Represents the configuration for the [`Endpoint`].
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// The client configuration to pass to `quinn_proto`.
    pub(crate) client_config: quinn_proto::ClientConfig,
    /// The server configuration to pass to `quinn_proto`.
    pub(crate) server_config: Arc<quinn_proto::ServerConfig>,
    /// The endpoint configuration to pass to `quinn_proto`.
    pub(crate) endpoint_config: Arc<quinn_proto::EndpointConfig>,
}

impl QuicConfig {
    /// Creates a new configuration object with default values.
    pub fn new(keypair: &libp2p_core::identity::Keypair) -> Result<Self, x509::ConfigError> {
        let mut transport = quinn_proto::TransportConfig::default();
        transport.stream_window_uni(0);
        transport.datagram_receive_buffer_size(None);
        transport.keep_alive_interval(Some(Duration::from_millis(10)));
        let transport = Arc::new(transport);
        let (client_tls_config, server_tls_config) = x509::make_tls_config(keypair)?;
        let mut server_config = quinn_proto::ServerConfig::default();
        server_config.transport = transport.clone();
        server_config.crypto = Arc::new(server_tls_config);
        let mut client_config = quinn_proto::ClientConfig::default();
        client_config.transport = transport;
        client_config.crypto = Arc::new(client_tls_config);
        Ok(Self {
            client_config,
            server_config: Arc::new(server_config),
            endpoint_config: Default::default(),
        })
    }
}

/// Error that can happen on the transport.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error while trying to bind a port.
    #[error("{0}")]
    Listen(io::Error),
    /// Error while trying to reach a remote.
    #[error("{0}")]
    Reach(ConnectError),
    /// Error after the remote has been reached.
    #[error("{0}")]
    Established(Libp2pQuicConnectionError),
}

pub struct QuicListener {
    endpoint: Arc<Endpoint>,
    addresses: Vec<ListeningAddress>,
    pending: VecDeque<ListenerEvent<Upgrade, Error>>,
}

impl QuicListener {
    pub fn new(
        config: QuicConfig,
        addr: Multiaddr,
    ) -> Result<
        Pin<Box<dyn Future<Output = Result<(PeerId, QuicMuxer), Error>> + Send>>,
        TransportError<Error>,
    > {
        let ip4: Multiaddr = "/ip4/0.0.0.0/udp/0/quic".parse().unwrap();
        if ip4.can_dial(&addr) {
            return Self::listen_on(config, ip4)?.dial(addr);
        }
        let ip6: Multiaddr = "/ip6/::/udp/0/quic".parse().unwrap();
        if ip6.can_dial(&addr) {
            return Self::listen_on(config, ip6)?.dial(addr);
        }
        let ip4: Multiaddr = "/ip4/127.0.0.1/udp/0/quic".parse().unwrap();
        if ip4.can_dial(&addr) {
            return Self::listen_on(config, ip4)?.dial(addr);
        }
        let ip6: Multiaddr = "/ip6/::1/udp/0/quic".parse().unwrap();
        if ip6.can_dial(&addr) {
            return Self::listen_on(config, ip6)?.dial(addr);
        }
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    pub fn listen_on(config: QuicConfig, addr: Multiaddr) -> Result<Self, TransportError<Error>> {
        let local_socket_addr = if let Ok(addr) = multiaddr_to_socketaddr(&addr) {
            addr
        } else {
            return Err(TransportError::MultiaddrNotSupported(addr));
        };
        let endpoint = Endpoint::new(config, local_socket_addr)
            .map_err(|e| TransportError::Other(Error::Listen(e)))?;

        let socket_addr = endpoint.local_addr();
        let mut pending = VecDeque::new();
        if !socket_addr.ip().is_unspecified() {
            let addr = socketaddr_to_multiaddr(&socket_addr);
            pending.push_back(ListenerEvent::NewAddress(addr));
        }
        Ok(Self {
            endpoint,
            addresses: Default::default(),
            pending,
        })
    }

    // If we listen on all interfaces, find out to which interface the given
    // socket address belongs. In case we think the address is new, check
    // all host interfaces again and report new and expired listen addresses.
    pub fn check_for_interface_changes(&mut self) -> Result<(), io::Error> {
        let socket_addr = self.endpoint.local_addr();
        if !socket_addr.ip().is_unspecified() {
            return Ok(());
        }

        // Check for exact match:
        if self
            .addresses
            .iter()
            .find(|addr| addr.ip == socket_addr.ip())
            .is_some()
        {
            return Ok(());
        }

        // No exact match => check netmask
        if self
            .addresses
            .iter()
            .find(|addr| addr.net.contains(&socket_addr.ip()))
            .is_some()
        {
            return Ok(());
        }

        let new_addresses: Vec<_> = get_if_addrs()?
            .into_iter()
            .map(|iface| ListeningAddress::new(iface.addr, socket_addr.port()))
            .collect();

        // Check for addresses no longer in use.
        for addr in self.addresses.iter() {
            if new_addresses
                .iter()
                .find(|addr2| addr2.ip == addr.ip)
                .is_none()
            {
                log::debug!("Expired listen address: {}", addr.multiaddr);
                self.pending
                    .push_back(ListenerEvent::AddressExpired(addr.multiaddr.clone()));
            }
        }

        // Check for new addresses.
        for addr in new_addresses.iter() {
            if self
                .addresses
                .iter()
                .find(|addr2| addr2.ip == addr.ip)
                .is_none()
            {
                log::debug!("New listen address: {}", addr.multiaddr);
                self.pending
                    .push_back(ListenerEvent::NewAddress(addr.multiaddr.clone()));
            }
        }

        self.addresses = new_addresses;

        Ok(())
    }
}

impl Dialer for QuicListener {
    type Output = (PeerId, QuicMuxer);
    type Error = Error;
    type Dial = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn dial(self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        let socket_addr = if let Ok(socket_addr) = multiaddr_to_socketaddr(&addr) {
            if socket_addr.port() == 0 || socket_addr.ip().is_unspecified() {
                return Err(TransportError::MultiaddrNotSupported(addr));
            }
            socket_addr
        } else {
            return Err(TransportError::MultiaddrNotSupported(addr));
        };
        let endpoint = self.endpoint.clone();
        Ok(async move {
            let conn = endpoint.dial(socket_addr).await.map_err(Error::Reach)?;
            let final_conn = Upgrade::from_connection(conn).await?;
            Ok(final_conn)
        }
        .boxed())
    }
}

impl Stream for QuicListener {
    type Item = Result<ListenerEvent<Upgrade, Error>, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if let Err(err) = self.check_for_interface_changes() {
            return Poll::Ready(Some(Ok(ListenerEvent::Error(Error::Listen(err)))));
        }

        if let Some(event) = self.pending.pop_front() {
            return Poll::Ready(Some(Ok(event)));
        }

        let mut incoming = self.endpoint.next_incoming().boxed();
        let conn = match Pin::new(&mut incoming).poll(cx) {
            Poll::Ready(conn) => conn,
            Poll::Pending => return Poll::Pending,
        };
        let remote_addr = socketaddr_to_multiaddr(&conn.remote_addr());
        let local_addr = socketaddr_to_multiaddr(&self.endpoint.local_addr());
        Poll::Ready(Some(Ok(ListenerEvent::Upgrade {
            upgrade: Upgrade::from_connection(conn),
            local_addr,
            remote_addr,
        })))
    }
}

impl Dialer for QuicConfig {
    type Output = (PeerId, QuicMuxer);
    type Error = Error;
    type Dial = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn dial(self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        QuicListener::new(self, addr)
    }
}

impl Transport for QuicConfig {
    type Listener = QuicListener;
    type ListenerUpgrade = Upgrade;

    fn listen_on(self, addr: Multiaddr) -> Result<Self::Listener, TransportError<Self::Error>> {
        QuicListener::listen_on(self, addr)
    }
}

/// Tries to turn a QUIC multiaddress into a UDP [`SocketAddr`]. Returns an error if the format
/// of the multiaddr is wrong.
pub(crate) fn multiaddr_to_socketaddr(addr: &Multiaddr) -> Result<SocketAddr, ()> {
    let mut iter = addr.iter();
    let proto1 = iter.next().ok_or(())?;
    let proto2 = iter.next().ok_or(())?;
    let proto3 = iter.next().ok_or(())?;

    if iter.next().is_some() {
        return Err(());
    }

    match (proto1, proto2, proto3) {
        (Protocol::Ip4(ip), Protocol::Udp(port), Protocol::Quic) => {
            Ok(SocketAddr::new(ip.into(), port))
        }
        (Protocol::Ip6(ip), Protocol::Udp(port), Protocol::Quic) => {
            Ok(SocketAddr::new(ip.into(), port))
        }
        _ => Err(()),
    }
}

/// Turns an IP address and port into the corresponding QUIC multiaddr.
pub(crate) fn socketaddr_to_multiaddr(socket_addr: &SocketAddr) -> Multiaddr {
    Multiaddr::empty()
        .with(socket_addr.ip().into())
        .with(Protocol::Udp(socket_addr.port()))
        .with(Protocol::Quic)
}

#[derive(Debug)]
struct ListeningAddress {
    ip: IpAddr,
    net: IpNet,
    multiaddr: Multiaddr,
}

impl ListeningAddress {
    pub fn new(iface: IfAddr, port: u16) -> Self {
        let ip = iface.ip();
        let multiaddr = socketaddr_to_multiaddr(&SocketAddr::new(ip, port));
        let net = match iface {
            IfAddr::V4(ip4) => {
                let prefix_len = (!u32::from_be_bytes(ip4.netmask.octets())).leading_zeros();
                let ipnet = Ipv4Net::new(ip4.ip, prefix_len as u8)
                    .expect("prefix_len is the number of bits in a u32, so can not exceed 32");
                IpNet::V4(ipnet)
            }
            IfAddr::V6(ip6) => {
                let prefix_len = (!u128::from_be_bytes(ip6.netmask.octets())).leading_zeros();
                let ipnet = Ipv6Net::new(ip6.ip, prefix_len as u8)
                    .expect("prefix_len is the number of bits in a u128, so can not exceed 128");
                IpNet::V6(ipnet)
            }
        };
        Self { ip, net, multiaddr }
    }
}

#[cfg(test)]
#[test]
fn multiaddr_to_udp_conversion() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    assert!(
        multiaddr_to_socketaddr(&"/ip4/127.0.0.1/udp/1234".parse::<Multiaddr>().unwrap()).is_err()
    );

    assert_eq!(
        multiaddr_to_socketaddr(
            &"/ip4/127.0.0.1/udp/12345/quic"
                .parse::<Multiaddr>()
                .unwrap()
        ),
        Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            12345,
        ))
    );
    assert_eq!(
        multiaddr_to_socketaddr(
            &"/ip4/255.255.255.255/udp/8080/quic"
                .parse::<Multiaddr>()
                .unwrap()
        ),
        Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            8080,
        ))
    );
    assert_eq!(
        multiaddr_to_socketaddr(&"/ip6/::1/udp/12345/quic".parse::<Multiaddr>().unwrap()),
        Ok(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            12345,
        ))
    );
    assert_eq!(
        multiaddr_to_socketaddr(
            &"/ip6/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/udp/8080/quic"
                .parse::<Multiaddr>()
                .unwrap()
        ),
        Ok(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(
                65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            )),
            8080,
        ))
    );
}
