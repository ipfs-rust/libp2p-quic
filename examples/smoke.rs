use anyhow::Result;
use async_trait::async_trait;
use futures::future::FutureExt;
use futures::io::{AsyncRead, AsyncWrite};
use libp2p::core::upgrade::{read_one, write_one};
use libp2p::request_response::{
    ProtocolName, ProtocolSupport, RequestResponse, RequestResponseCodec, RequestResponseConfig,
    RequestResponseEvent, RequestResponseMessage,
};
use libp2p::swarm::{Swarm, SwarmBuilder, SwarmEvent};
use libp2p::Multiaddr;
use libp2p_quic::{Keypair, QuicConfig, ToLibp2p};
use rand::RngCore;
use std::{io, iter};

async fn create_swarm() -> Result<Swarm<RequestResponse<PingCodec>>> {
    let keypair = Keypair::generate();
    let peer_id = keypair.to_peer_id();
    let transport = QuicConfig::new(keypair)
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

#[async_std::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();
    log_panics::init();
    let mut rng = rand::thread_rng();

    let mut a = create_swarm().await?;
    let mut b = create_swarm().await?;

    Swarm::listen_on(&mut a, Multiaddr::empty())?;

    let addr = match a.next_event().await {
        SwarmEvent::NewListenAddr(addr) => addr,
        e => panic!("{:?}", e),
    };

    let mut data = vec![0; 4096 * 10];
    rng.fill_bytes(&mut data);

    b.behaviour_mut()
        .add_address(&Swarm::local_peer_id(&a), addr);

    for _ in 0..1024 {
        b.behaviour_mut()
            .send_request(&Swarm::local_peer_id(&a), Ping(data.clone()));
    }

    let mut res = 0;
    while res < 1024 {
        futures::select! {
            event = a.next_event().fuse() => match event {
                SwarmEvent::Behaviour(RequestResponseEvent::Message {
                    message: RequestResponseMessage::Request {
                        request: Ping(ping),
                        channel,
                        ..
                    },
                    ..
                }) => {
                    a.behaviour_mut().send_response(channel, Pong(ping)).unwrap();
                }
                _ => {}
            },
            event = b.next_event().fuse() => match event {
                SwarmEvent::Behaviour(RequestResponseEvent::Message {
                    message: RequestResponseMessage::Response {
                        response: Pong(pong),
                        ..
                    },
                    ..
                }) => {
                    assert_eq!(data, pong);
                    res += 1;
                }
                _ => {}
            }
        }
    }

    Ok(())
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

    async fn read_request<T>(&mut self, _: &PingProtocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_one(io, 4096 * 10)
            .map(|res| match res {
                Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
                Ok(vec) if vec.is_empty() => Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(vec) => Ok(Ping(vec)),
            })
            .await
    }

    async fn read_response<T>(&mut self, _: &PingProtocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_one(io, 4096 * 10)
            .map(|res| match res {
                Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
                Ok(vec) if vec.is_empty() => Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(vec) => Ok(Pong(vec)),
            })
            .await
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
        write_one(io, data).await
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
        write_one(io, data).await
    }
}
