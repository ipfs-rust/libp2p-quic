use futures::channel::mpsc;
use futures::prelude::*;
use quinn_proto::{ConnectionEvent, EndpointEvent, Transmit};
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct ConnectionChannel {
    tx: mpsc::UnboundedSender<ConnectionEvent>,
    rx: mpsc::UnboundedReceiver<EndpointEvent>,
    transmissions: mpsc::UnboundedReceiver<Transmit>,
}

pub struct EndpointChannel {
    tx: mpsc::UnboundedSender<EndpointEvent>,
    rx: mpsc::UnboundedReceiver<ConnectionEvent>,
    transmissions: mpsc::UnboundedSender<Transmit>,
}

impl EndpointChannel {
    pub fn poll_channel_events(&mut self, cx: &mut Context) -> Poll<ConnectionEvent> {
        match Pin::new(&mut self.rx).poll_next(cx) {
            Poll::Ready(Some(event)) => Poll::Ready(event),
            Poll::Ready(None) => panic!("endpoint has crashed"),
            Poll::Pending => Poll::Pending,
        }
    }

    pub fn send_endpoint_event(&mut self, event: EndpointEvent) {
        self.tx.unbounded_send(event).expect("endpoint has crashed")
    }

    pub fn send_transmit(&mut self, transmit: Transmit) {
        self.transmissions
            .unbounded_send(transmit)
            .expect("endpoint has crashed")
    }
}
