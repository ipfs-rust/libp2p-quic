#[cfg(any(
    all(feature = "noise", feature = "tls"),
    all(not(feature = "noise"), not(feature = "tls"))
))]
fn main() {}

#[cfg(any(
    all(feature = "noise", not(feature = "tls")),
    all(not(feature = "noise"), feature = "tls")
))]
#[async_std::main]
async fn main() -> anyhow::Result<()> {
    use anyhow::Result;
    use async_trait::async_trait;
    use futures::future::FutureExt;
    use futures::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
    use futures::stream::StreamExt;
    use libp2p::core::upgrade;
    use libp2p::request_response::{
        ProtocolName, ProtocolSupport, RequestResponse, RequestResponseCodec,
        RequestResponseConfig, RequestResponseEvent, RequestResponseMessage,
    };
    use libp2p::swarm::{Swarm, SwarmBuilder, SwarmEvent};
    use libp2p_quic::{Keypair, QuicConfig, ToLibp2p};
    use rand::RngCore;
    use std::time::Instant;
    use std::{io, iter};

    #[cfg(feature = "noise")]
    type Crypto = libp2p_quic::NoiseCrypto;
    #[cfg(feature = "tls")]
    type Crypto = libp2p_quic::TlsCrypto;

    async fn create_swarm() -> Result<Swarm<RequestResponse<PingCodec>>> {
        let keypair = Keypair::generate(&mut rand_core::OsRng {});
        let peer_id = keypair.to_peer_id();
        let transport = QuicConfig::<Crypto>::new(keypair)
            .listen_on("/ip4/127.0.0.1/udp/0/quic".parse()?)
            .await?
            .boxed();

        let protocols = iter::once((PingProtocol(), ProtocolSupport::Full));
        let cfg = RequestResponseConfig::default();
        let behaviour = RequestResponse::new(PingCodec(), protocols, cfg);
        tracing::info!("{}", peer_id);
        let swarm = SwarmBuilder::new(transport, behaviour, peer_id)
            .executor(Box::new(|fut| {
                async_global_executor::spawn(fut).detach();
            }))
            .build();
        Ok(swarm)
    }

    #[derive(Debug, Clone)]
    struct PingProtocol();

    #[derive(Clone)]
    struct PingCodec();

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Ping(Vec<u8>);

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Pong(Vec<u8>);

    impl ProtocolName for PingProtocol {
        fn protocol_name(&self) -> &[u8] {
            "/ping/1".as_bytes()
        }
    }

    #[async_trait]
    impl RequestResponseCodec for PingCodec {
        type Protocol = PingProtocol;
        type Request = Ping;
        type Response = Pong;

        async fn read_request<T>(
            &mut self,
            _: &PingProtocol,
            io: &mut T,
        ) -> io::Result<Self::Request>
        where
            T: AsyncRead + Unpin + Send,
        {
            let req = upgrade::read_length_prefixed(io, 4096 * 10)
                .map(|res| match res {
                    Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
                    Ok(vec) if vec.is_empty() => Err(io::ErrorKind::UnexpectedEof.into()),
                    Ok(vec) => Ok(Ping(vec)),
                })
                .await?;
            Ok(req)
        }

        async fn read_response<T>(
            &mut self,
            _: &PingProtocol,
            io: &mut T,
        ) -> io::Result<Self::Response>
        where
            T: AsyncRead + Unpin + Send,
        {
            let res = upgrade::read_length_prefixed(io, 4096 * 10)
                .map(|res| match res {
                    Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
                    Ok(vec) if vec.is_empty() => Err(io::ErrorKind::UnexpectedEof.into()),
                    Ok(vec) => Ok(Pong(vec)),
                })
                .await?;
            Ok(res)
        }

        async fn write_request<T>(
            &mut self,
            _: &PingProtocol,
            io: &mut T,
            Ping(data): Ping,
        ) -> io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
        {
            upgrade::write_length_prefixed(io, data).await?;
            io.close().await?;
            Ok(())
        }

        async fn write_response<T>(
            &mut self,
            _: &PingProtocol,
            io: &mut T,
            Pong(data): Pong,
        ) -> io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
        {
            upgrade::write_length_prefixed(io, data).await?;
            io.close().await?;
            Ok(())
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();
    log_panics::init();
    let mut rng = rand::thread_rng();

    let mut a = create_swarm().await?;
    let mut b = create_swarm().await?;

    Swarm::listen_on(&mut a, "/ip4/127.0.0.1/udp/0/quic".parse()?)?;

    let addr = match a.next().await {
        Some(SwarmEvent::NewListenAddr { address, .. }) => address,
        e => panic!("{:?}", e),
    };

    let mut data = vec![0; 4096 * 10];
    rng.fill_bytes(&mut data);

    b.behaviour_mut()
        .add_address(&Swarm::local_peer_id(&a), addr);

    let now = Instant::now();

    for _ in 0..1024 {
        b.behaviour_mut()
            .send_request(&Swarm::local_peer_id(&a), Ping(data.clone()));
    }

    let mut res = 0;
    while res < 1024 {
        futures::select! {
            event = a.next().fuse() => {
                if let Some(SwarmEvent::Behaviour(RequestResponseEvent::Message {
                    message: RequestResponseMessage::Request {
                        request: Ping(ping),
                        channel,
                        ..
                    },
                    ..
                })) = event {
                    a.behaviour_mut().send_response(channel, Pong(ping)).unwrap();
                }
            },
            event = b.next().fuse() => {
                if let Some(SwarmEvent::Behaviour(RequestResponseEvent::Message {
                    message: RequestResponseMessage::Response {
                        response: Pong(pong),
                        ..
                    },
                    ..
                })) = event  {
                    assert_eq!(data, pong);
                    res += 1;
                }
            }
        }
    }

    let time = now.elapsed();
    println!("{}ms", time.as_millis());

    Ok(())
}
