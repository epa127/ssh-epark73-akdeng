use std::{net::TcpListener, path::Path};

use clap::Parser;
use anyhow::{Error, Result};

fn main() {
  let args = ServerCli::parse();

  let listener = TcpListener::bind(format!("127.0.0.1:{}", args.port)).unwrap();
  for stream in listener.incoming() {
      match stream {
          Ok(stream) => {
              start_connection(stream);
          }
          Err(e) => { eprintln!("BAD") }
      }
  }

}

#[derive(Parser)]
#[command(about = "server side probably secure shell (psshd)", long_about = None)]
struct ServerCli {
  #[arg(short = 'p', long, value_name = "port number", default_value = "22")]
  /// Port number
  pub port: u16,

  #[arg(
    short = 'f', long = "master",  value_name = "config file", 
    default_value = "/etc/ssh/sshd_config", value_parser = ServerCli::validate_path)]
  /// Filepath to ssh host config
  pub config_path: String,

  #[arg(
    short = 'k', long,  value_name = "host key file", 
    default_value = "/etc/ssh/ssh_host_rsa_key", value_parser = ServerCli::validate_path)]
  /// Filepath to ssh host key
  pub host_key_path: String
}

impl ServerCli {
  fn validate_path(config: &str) -> Result<()> {
    if Path::new(config).exists() {
      Ok(())
    } else {
      Err(Error::msg(format!("File does not exist at path {}", config)))
    }
  }
}
