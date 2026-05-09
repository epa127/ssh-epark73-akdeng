use std::{net::{Ipv4Addr, SocketAddr, SocketAddrV4}, str::FromStr};

use clap::Parser;
use anyhow::Result;

fn main() {
  let args = ClientCli::parse();
}

#[derive(Parser)]
#[command(about = "probably client shell (pssh)", long_about = None)]
struct ClientCli {
  #[arg(value_parser = ClientCli::validate_destination )]
  /// For now, a destination Ipv4 Address
  pub destination: Ipv4Addr,

  #[arg(short = 'p', long, value_name = "port number", default_value = "22")]
  /// Port number
  pub port: u16,

  #[arg(short = 'l', long = "master",  value_name = "login name")]
  /// Login name for authentication
  pub username: Option<String>
}

impl ClientCli {
  fn validate_destination(destination: &str) -> Result<Ipv4Addr> {
    // Only validates that it is a valid IpV4 address for now
    // Ideally, later, we can use DNS
    Ok(Ipv4Addr::from_str(destination)?)
  }

  pub fn dest_socket(&self) -> Result<SocketAddr> {
    Ok(SocketAddr::V4(SocketAddrV4::new(self.destination, self.port)))
  }
}