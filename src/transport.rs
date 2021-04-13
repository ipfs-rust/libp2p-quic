use crate::endpoint::{EndpointConfig, TransportChannel};
use crate::muxer::QuicMuxer;
use crate::noise::NoiseUpgrade;
use crate::{QuicConfig, QuicError};
use futures::channel::oneshot;
use futures::prelude::*;
use if_watch::{IfEvent, IfWatcher};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{Boxed, ListenerEvent, Transport, TransportError};
use libp2p::multiaddr::{Multiaddr, Protocol};
use libp2p::PeerId;
use parking_lot::Mutex;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use udp_socket::SocketType;

#[derive(Clone)]
pub struct QuicTransport {
    inner: Arc<Mutex<QuicTransportInner>>,
}

impl QuicTransport {
    /// Creates a new quic transport.
    pub async fn new(
        config: QuicConfig,
        addr: Multiaddr,
    ) -> Result<Self, TransportError<QuicError>> {
        let socket_addr = multiaddr_to_socketaddr(&addr)
            .map_err(|_| TransportError::MultiaddrNotSupported(addr.clone()))?;
        let addresses = if socket_addr.ip().is_unspecified() {
            let watcher = IfWatcher::new()
                .await
                .map_err(|err| TransportError::Other(err.into()))?;
            Addresses::Unspecified(watcher)
        } else {
            Addresses::Ip(Some(socket_addr.ip()))
        };
        let endpoint = EndpointConfig::new(config, socket_addr).map_err(TransportError::Other)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(QuicTransportInner {
                channel: endpoint.spawn(),
                addresses,
            })),
        })
    }

    /// Creates a boxed libp2p transport.
    pub fn boxed(self) -> Boxed<(PeerId, StreamMuxerBox)> {
        Transport::map(self, |(peer_id, muxer), _| {
            (peer_id, StreamMuxerBox::new(muxer))
        })
        .boxed()
    }
}

impl std::fmt::Debug for QuicTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("QuicTransport").finish()
    }
}

struct QuicTransportInner {
    channel: TransportChannel,
    addresses: Addresses,
}

enum Addresses {
    Unspecified(IfWatcher),
    Ip(Option<IpAddr>),
}

impl Transport for QuicTransport {
    type Output = (PeerId, QuicMuxer);
    type Error = QuicError;
    type Listener = Self;
    type ListenerUpgrade = NoiseUpgrade;
    type Dial = QuicDial;

    fn listen_on(self, addr: Multiaddr) -> Result<Self::Listener, TransportError<Self::Error>> {
        multiaddr_to_socketaddr(&addr).map_err(|_| TransportError::MultiaddrNotSupported(addr))?;
        Ok(self)
    }

    fn dial(self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        let socket_addr = multiaddr_to_socketaddr(&addr)
            .map_err(|_| TransportError::MultiaddrNotSupported(addr.clone()))?;
        if socket_addr.port() == 0 || socket_addr.ip().is_unspecified() {
            return Err(TransportError::MultiaddrNotSupported(addr));
        }
        tracing::debug!("dialing {}", socket_addr);
        let rx = self.inner.lock().channel.dial(socket_addr);
        Ok(QuicDial::Connecting(rx))
    }

    fn address_translation(&self, _listen: &Multiaddr, observed: &Multiaddr) -> Option<Multiaddr> {
        Some(observed.clone())
    }
}

impl Stream for QuicTransport {
    type Item = Result<ListenerEvent<NoiseUpgrade, QuicError>, QuicError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut inner = self.inner.lock();
        match &mut inner.addresses {
            Addresses::Ip(ip) => {
                if let Some(ip) = ip.take() {
                    let addr = socketaddr_to_multiaddr(&SocketAddr::new(ip, inner.channel.port()));
                    return Poll::Ready(Some(Ok(ListenerEvent::NewAddress(addr))));
                }
            }
            Addresses::Unspecified(watcher) => match Pin::new(watcher).poll(cx) {
                Poll::Ready(Ok(IfEvent::Up(net))) => {
                    if inner.channel.ty() == SocketType::Ipv4 && net.addr().is_ipv4()
                        || inner.channel.ty() != SocketType::Ipv4 && net.addr().is_ipv6()
                    {
                        let addr = socketaddr_to_multiaddr(&SocketAddr::new(
                            net.addr(),
                            inner.channel.port(),
                        ));
                        return Poll::Ready(Some(Ok(ListenerEvent::NewAddress(addr))));
                    }
                }
                Poll::Ready(Ok(IfEvent::Down(net))) => {
                    if inner.channel.ty() == SocketType::Ipv4 && net.addr().is_ipv4()
                        || inner.channel.ty() != SocketType::Ipv4 && net.addr().is_ipv6()
                    {
                        let addr = socketaddr_to_multiaddr(&SocketAddr::new(
                            net.addr(),
                            inner.channel.port(),
                        ));
                        return Poll::Ready(Some(Ok(ListenerEvent::AddressExpired(addr))));
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err.into()))),
                Poll::Pending => {}
            },
        }
        match inner.channel.poll_incoming(cx) {
            Poll::Ready(Some(Ok(muxer))) => Poll::Ready(Some(Ok(ListenerEvent::Upgrade {
                local_addr: muxer.local_addr(),
                remote_addr: muxer.remote_addr(),
                upgrade: NoiseUpgrade::new(muxer),
            }))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum QuicDial {
    Connecting(oneshot::Receiver<Result<QuicMuxer, QuicError>>),
    Upgrading(NoiseUpgrade),
}

impl Future for QuicDial {
    type Output = Result<(PeerId, QuicMuxer), QuicError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match &mut *self {
                Self::Connecting(rx) => match Pin::new(rx).poll(cx) {
                    Poll::Ready(Ok(Ok(muxer))) => {
                        *self = QuicDial::Upgrading(NoiseUpgrade::new(muxer));
                    }
                    Poll::Ready(Ok(Err(err))) => return Poll::Ready(Err(err)),
                    Poll::Ready(Err(_)) => panic!("endpoint crashed"),
                    Poll::Pending => return Poll::Pending,
                },
                Self::Upgrading(upgrade) => return Pin::new(upgrade).poll(cx),
            }
        }
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
pub(crate) fn socketaddr_to_multiaddr(socket_addr: &SocketAddr) -> Multiaddr {
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
