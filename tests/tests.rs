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

use async_macros::ready;
use async_std::future::poll_fn;
use futures::prelude::*;
use libp2p_core::{
    multiaddr::{Multiaddr, Protocol},
    muxing::StreamMuxerEvent,
    transport::ListenerEvent,
    Dialer, StreamMuxer, Transport,
};
use libp2p_quic::{Error, QuicConfig, QuicMuxer};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

#[test]
fn wildcard_expansion() {
    env_logger::try_init().ok();
    let addr: Multiaddr = "/ip4/0.0.0.0/udp/1234/quic".parse().unwrap();
    let keypair = libp2p_core::identity::Keypair::generate_ed25519();
    let config = QuicConfig::new(&keypair).unwrap();
    let mut incoming = config.listen_on(addr).unwrap();
    // Process all initial `NewAddress` events and make sure they
    // do not contain wildcard address or port.
    futures::executor::block_on(async move {
        while let Some(event) = incoming.next().await.map(|e| e.unwrap()) {
            println!("{:?}", event);
            match event {
                ListenerEvent::NewAddress(a) => {
                    let mut iter = a.iter();
                    match iter.next().expect("ip address") {
                        Protocol::Ip4(ip) => assert!(!ip.is_unspecified()),
                        Protocol::Ip6(ip) => assert!(!ip.is_unspecified()),
                        other => panic!("Unexpected protocol: {}", other),
                    }
                    if let Protocol::Udp(port) = iter.next().expect("port") {
                        assert_ne!(0, port)
                    } else {
                        panic!("No UDP port in address: {}", a)
                    }
                    assert_eq!(iter.next(), Some(Protocol::Quic));
                    assert_eq!(iter.next(), None);
                }
                ListenerEvent::Upgrade { .. } => panic!(),
                ListenerEvent::AddressExpired { .. } => panic!(),
                ListenerEvent::Error { .. } => panic!(),
            }
            break;
        }
    });
}

#[async_std::test]
async fn replace_port_0_in_returned_multiaddr_ipv4() {
    env_logger::try_init().ok();
    let keypair = libp2p_core::identity::Keypair::generate_ed25519();
    let addr = "/ip4/127.0.0.1/udp/0/quic".parse::<Multiaddr>().unwrap();
    assert!(addr.to_string().ends_with("udp/0/quic"));

    let config = QuicConfig::new(&keypair).unwrap();

    let new_addr = config
        .listen_on(addr)
        .unwrap()
        .next()
        .await
        .expect("some event")
        .expect("no error")
        .into_new_address()
        .expect("listen address");

    if new_addr.to_string().contains("udp/0") {
        panic!("failed to expand address ― got {}", new_addr);
    }
}

#[async_std::test]
async fn replace_port_0_in_returned_multiaddr_ipv6() {
    env_logger::try_init().ok();
    let keypair = libp2p_core::identity::Keypair::generate_ed25519();
    let addr: Multiaddr = "/ip6/::1/udp/0/quic".parse().unwrap();
    assert!(addr.to_string().ends_with("udp/0/quic"));

    let config = QuicConfig::new(&keypair).unwrap();

    let new_addr = config
        .listen_on(addr)
        .unwrap()
        .next()
        .await
        .expect("some event")
        .expect("no error")
        .into_new_address()
        .expect("listen address");

    if new_addr.to_string().contains("udp/0") {
        panic!("failed to expand address - got {}", new_addr);
    }
}

#[test]
#[should_panic]
fn larger_addr_denied() {
    env_logger::try_init().ok();
    let keypair = libp2p_core::identity::Keypair::generate_ed25519();
    let addr = "/ip4/127.0.0.1/tcp/12345/tcp/12345"
        .parse::<Multiaddr>()
        .unwrap();
    let config = QuicConfig::new(&keypair).unwrap();
    config.listen_on(addr).unwrap();
}

#[derive(Debug)]
struct QuicStream {
    id: Option<quinn_proto::StreamId>,
    muxer: Arc<QuicMuxer>,
    shutdown: bool,
}

impl QuicStream {
    async fn outbound(muxer: Arc<QuicMuxer>) -> Result<Self, Error> {
        let mut sub = muxer.open_outbound();
        let id = poll_fn(|cx| muxer.poll_outbound(cx, &mut sub)).await?;
        Ok(QuicStream {
            id: Some(id),
            muxer,
            shutdown: false,
        })
    }

    async fn inbound(muxer: Arc<QuicMuxer>) -> Result<Self, Error> {
        loop {
            let event = poll_fn(|cx| muxer.poll_event(cx)).await?;
            log::debug!("{:?}", event);
            if let StreamMuxerEvent::InboundSubstream(id) = event {
                return Ok(QuicStream {
                    id: Some(id),
                    muxer,
                    shutdown: false,
                });
            }
        }
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        assert!(!self.shutdown, "written after close");
        let Self { muxer, id, .. } = self.get_mut();
        muxer
            .write_substream(cx, id.as_mut().unwrap(), buf)
            .map_err(From::from)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown = true;
        let Self { muxer, id, .. } = self.get_mut();
        log::debug!("trying to close {:?}", id);
        ready!(muxer.shutdown_substream(cx, id.as_mut().unwrap()))?;
        log::debug!("closed {:?}", id);
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let Self { id, muxer, .. } = self.get_mut();
        muxer
            .read_substream(cx, id.as_mut().unwrap(), buf)
            .map_err(From::from)
    }
}

impl Drop for QuicStream {
    fn drop(&mut self) {
        match self.id.take() {
            None => {}
            Some(id) => self.muxer.destroy_substream(id),
        }
    }
}

#[async_std::test]
async fn communicating_between_dialer_and_listener() {
    env_logger::try_init().ok();
    let (ready_tx, ready_rx) = futures::channel::oneshot::channel();
    let mut ready_tx = Some(ready_tx);
    let keypair = libp2p_core::identity::Keypair::generate_ed25519();
    let keypair2 = keypair.clone();
    let addr: Multiaddr = "/ip4/127.0.0.1/udp/0/quic".parse().expect("bad address?");
    let config = QuicConfig::new(&keypair2).unwrap();
    let mut listener = config.listen_on(addr).unwrap();
    log::trace!("running tests");
    let handle = async_std::task::spawn(async move {
        let key = loop {
            log::trace!("awaiting connection");
            match listener.next().await.unwrap().unwrap() {
                ListenerEvent::NewAddress(listen_addr) => {
                    if let Some(channel) = ready_tx.take() {
                        channel.send(listen_addr).unwrap();
                    }
                }
                ListenerEvent::Upgrade { upgrade, .. } => {
                    log::debug!("in: connection upgrade");
                    let (id, muxer) = upgrade.await.expect("upgrade failed");
                    let muxer = Arc::new(muxer);
                    let muxer2 = muxer.clone();
                    log::debug!("in: muxer");
                    let mut stream = QuicStream::inbound(muxer.clone())
                        .await
                        .expect("no incoming stream");
                    log::debug!("in: accept {}", id);
                    async_std::task::spawn(poll_fn(move |cx| muxer2.poll_event(cx)));

                    log::debug!("in: read");
                    let mut buf = [0u8; 3];
                    stream.read_exact(&mut buf).await.unwrap();
                    assert_eq!(buf, [4, 5, 6]);

                    log::debug!("in: write");
                    stream.write_all(&[0x1, 0x2, 0x3]).await.unwrap();

                    log::debug!("in: close write half");
                    stream.close().await.unwrap();

                    log::debug!("in: read");
                    assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
                    log::debug!("in: eof");
                    drop(stream);

                    log::debug!("in: close");
                    poll_fn(|cx| muxer.close(cx))
                        .await
                        .expect("closed successfully");
                    log::debug!("in: closed");

                    break id;
                }
                _ => unreachable!(),
            }
        };
        drop(listener);
        key
    });

    let second_handle = async_std::task::spawn(async move {
        let addr = ready_rx.await.unwrap();
        let config = QuicConfig::new(&keypair).unwrap();
        // Obtain a future socket through dialing
        let (id, muxer) = config.dial(addr.clone()).unwrap().await.unwrap();
        let muxer = Arc::new(muxer);
        log::debug!("out: open {}", id);
        let muxer2 = muxer.clone();
        async_std::task::spawn(poll_fn(move |cx| muxer2.poll_event(cx)));
        let mut stream = QuicStream::outbound(muxer.clone()).await.expect("failed");
        log::debug!("out: opened");

        /*let result = stream.read(&mut [][..]).await;
        let result = result.expect_err("reading from an unwritten stream cannot succeed");
        assert_eq!(result.kind(), std::io::ErrorKind::NotConnected);
        assert!(result.source().is_none());
        let wrapped = result.get_ref().unwrap().downcast_ref().unwrap();
        match wrapped {
            libp2p_quic::Error::CannotReadFromUnwrittenStream => {}
            e => panic!("Wrong error from reading unwritten stream: {}", e),
        }*/

        log::debug!("out: write");
        stream.write_all(&[4u8, 5, 6]).await.unwrap();

        log::debug!("out: close write half");
        stream.close().await.unwrap();

        log::debug!("out: read");
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [1, 2, 3]);

        log::debug!("out: read");
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
        log::debug!("out: eof");
        drop(stream);

        log::debug!("out: close");
        poll_fn(|cx| muxer.close(cx))
            .await
            .expect("closed successfully");
        log::debug!("out: closed");

        id
    });
    assert_eq!(handle.await, second_handle.await,);
}
