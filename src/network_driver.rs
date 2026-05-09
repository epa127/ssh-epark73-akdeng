use std::net::TcpStream;
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