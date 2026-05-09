use std::{net::{Ipv4Addr, TcpListener, TcpStream}, os::unix::net::SocketAddr};
use anyhow::Result;

pub struct NetworkDriver {
    stream: TcpStream
}

impl NetworkDriver {
    pub fn client_init(destination: &str) -> Result<Self> {
        let stream = TcpStream::connect(destination)?;
        Ok(Self {
            stream,
        })
    }
}