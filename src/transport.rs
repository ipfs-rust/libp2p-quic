use crate::config::QuicConfig;
use crate::muxer::QuicMuxer;
use futures::prelude::*;
use libp2p::core::transport::{ListenerEvent, Transport, TransportError};
use libp2p::multiaddr::{Multiaddr, Protocol};
use libp2p::PeerId;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;

pub struct QuicTransport {
    //endpoints: Arc<Mutex<Vec<Arc<Endpoint>>>>,
}

impl Transport for QuicConfig {
    type Output = (PeerId, QuicMuxer);
    type Error = QuicTransportError;
    type Listener = QuicListener;
    type ListenerUpgrade = QuicListenerUpgrade;
    type Dial = QuicDial;

    fn listen_on(self, addr: Multiaddr) -> Result<Self::Listener, TransportError<Self::Error>> {
        let socket_addr = multiaddr_to_socketaddr(&addr)
            .map_err(|_| TransportError::MultiaddrNotSupported(addr))?;
        tracing::debug!("listening on {}", socket_addr);
        unimplemented!()
    }

    fn dial(self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        let socket_addr = multiaddr_to_socketaddr(&addr)
            .map_err(|_| TransportError::MultiaddrNotSupported(addr.clone()))?;
        if socket_addr.port() == 0 || socket_addr.ip().is_unspecified() {
            return Err(TransportError::MultiaddrNotSupported(addr));
        }
        tracing::debug!("dialing {}", socket_addr);
        unimplemented!()
    }

    fn address_translation(&self, _listen: &Multiaddr, observed: &Multiaddr) -> Option<Multiaddr> {
        Some(observed.clone())
    }
}

#[derive(Debug, Error)]
pub enum QuicTransportError {}

pub struct QuicListener {
    //endpoint: Endpoint,
}

impl Stream for QuicListener {
    type Item = Result<ListenerEvent<QuicListenerUpgrade, QuicTransportError>, QuicTransportError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Option<Self::Item>> {
        unimplemented!()
    }
}

pub struct QuicListenerUpgrade {}

impl Future for QuicListenerUpgrade {
    type Output = Result<(PeerId, QuicMuxer), QuicTransportError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Self::Output> {
        unimplemented!()
    }
}

pub struct QuicDial {}

impl Future for QuicDial {
    type Output = Result<(PeerId, QuicMuxer), QuicTransportError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Self::Output> {
        unimplemented!()
    }
}

/// Tries to turn a QUIC multiaddress into a UDP [`SocketAddr`]. Returns an error if the format
/// of the multiaddr is wrong.
fn multiaddr_to_socketaddr(addr: &Multiaddr) -> Result<SocketAddr, ()> {
    let mut iter = addr.iter().peekable();
    let proto1 = iter.next().ok_or(())?;
    let proto2 = iter.next().ok_or(())?;
    let proto3 = iter.next().ok_or(())?;

    if let Some(Protocol::P2p(_)) = iter.peek() {
        iter.next();
    }

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
fn socketaddr_to_multiaddr(socket_addr: &SocketAddr) -> Multiaddr {
    Multiaddr::empty()
        .with(socket_addr.ip().into())
        .with(Protocol::Udp(socket_addr.port()))
        .with(Protocol::Quic)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiaddr_to_udp_conversion() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        assert!(
            multiaddr_to_socketaddr(&"/ip4/127.0.0.1/udp/1234".parse::<Multiaddr>().unwrap())
                .is_err()
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
}
