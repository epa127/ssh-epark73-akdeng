use std::{
  net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
  str::FromStr,
};

use anyhow::Result;
use clap::Parser;

use ssh_epark73_akdeng::pkg::client::Client;

fn main() -> Result<()> {
  let args = ClientCli::parse();

  let addr = args.dest_socket()?;
  let stream = TcpStream::connect(addr)?;

  let mut reader = stream.try_clone()?;
  let mut writer = stream;

  let mut client = Client::new();

  client.start(&mut writer)?;
  client.receive_proto_version(&mut reader, &mut writer)?;
  client.receive_server_kexinit(&mut reader, &mut writer)?;
  client.receive_kex_reply(&mut reader, &mut writer)?;
  client.receive_newkeys(&mut reader)?;

  Ok(())
}

#[derive(Parser)]
#[command(about = "probably client shell (pssh)", long_about = None)]
struct ClientCli {
  #[arg(value_parser = ClientCli::validate_destination)]
  /// For now, a destination IPv4 address
  pub destination: Ipv4Addr,

  #[arg(short = 'p', long, value_name = "port number", default_value = "8000")]
  /// Port number
  pub port: u16,

  #[arg(short = 'l', long = "master", value_name = "login name")]
  /// Login name for authentication
  pub username: Option<String>,
}

impl ClientCli {
  fn validate_destination(destination: &str) -> Result<Ipv4Addr> {
      Ok(Ipv4Addr::from_str(destination)?)
  }

  pub fn dest_socket(&self) -> Result<SocketAddr> {
      Ok(SocketAddr::V4(SocketAddrV4::new(self.destination, self.port)))
  }
}