use anyhow::Result;
use libp2p::core::identity::Keypair;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::ping::{Ping, PingConfig};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{Multiaddr, Transport};
use libp2p_quic::QuicConfig;
use std::time::Duration;

async fn create_swarm() -> Result<Swarm<Ping>> {
    let keypair = Keypair::generate_ed25519();
    let transport = QuicConfig::new(&keypair)
        .listen_on("/ip4/127.0.0.1/udp/0/quic".parse()?)
        .await?
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
        .boxed();
    let behaviour = Ping::new(PingConfig::new().with_interval(Duration::from_millis(10)));
    let peer_id = keypair.public().into_peer_id();
    Ok(Swarm::new(transport, behaviour, peer_id))
}

#[async_std::test]
async fn communicating_between_dialer_and_listener_swarm() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();
    log_panics::init();

    let mut a = create_swarm().await?;
    let mut b = create_swarm().await?;

    tracing::info!("created swarms");

    Swarm::listen_on(&mut a, Multiaddr::empty())?;

    let addr = match a.next_event().await {
        SwarmEvent::NewListenAddr(addr) => addr,
        e => panic!("{:?}", e),
    };

    Swarm::dial_addr(&mut b, addr)?;

    match a.next_event().await {
        SwarmEvent::IncomingConnection { .. } => {}
        e => panic!("{:?}", e),
    };

    match b.next_event().await {
        SwarmEvent::ConnectionEstablished { .. } => {}
        e => panic!("{:?}", e),
    };

    match a.next_event().await {
        SwarmEvent::ConnectionEstablished { .. } => {}
        e => panic!("{:?}", e),
    };

    Ok(())
}
