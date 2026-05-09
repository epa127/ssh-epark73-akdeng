use std::{net::TcpListener, path::Path};

use anyhow::{Error, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::{TryRngCore, rngs::OsRng};

use ssh_epark73_akdeng::{
    crypto::{Ed25519Signer, ServerKeyAlg},
    pkg::server::Server,
};

fn main() -> Result<()> {
    let args = ServerCli::parse();

    let listener = TcpListener::bind(format!("127.0.0.1:{}", args.port))?;
    println!("listening on 127.0.0.1:{}", args.port);

    for stream in listener.incoming() {
      match stream {
          Ok(stream) => {
              if let Err(e) = handle_connection(stream) {
                  eprintln!("connection failed: {}", e);
              }
          }
          Err(e) => {
              eprintln!("accept failed: {}", e);
          }
      }
    }

    Ok(())
}

fn handle_connection(stream: std::net::TcpStream) -> Result<()> {
  let mut reader = stream.try_clone()?;
  let mut writer = stream;

  let host_key = make_temporary_host_key()?;
  let mut server = Server::new(host_key);

  server.receive_proto_version(&mut reader, &mut writer)?;
  server.receive_client_kexinit(&mut reader, &mut writer)?;
  server.receive_kexdh_init(&mut reader, &mut writer)?;
  server.receive_newkeys(&mut reader)?;

  println!("SSH transport established");

  Ok(())
}

fn make_temporary_host_key() -> Result<ServerKeyAlg> {
  let mut secret = [0u8; 32];

  let mut rng = OsRng;
  rng.try_fill_bytes(&mut secret)?;

  let signing_key = SigningKey::from_bytes(&secret);
  let public_key = signing_key.verifying_key().to_bytes();

  Ok(ServerKeyAlg::Ed25519(Ed25519Signer {
      signing_key,
      public_key,
  }))
}

#[derive(Parser)]
#[command(about = "server side probably secure shell (psshd)", long_about = None)]
struct ServerCli {
    #[arg(short = 'p', long, value_name = "port number", default_value = "8000")]
    /// Port number
    pub port: u16,

    // #[arg(
    //     short = 'f',
    //     long = "master",
    //     value_name = "config file",
    //     default_value = "/etc/ssh/sshd_config",
    //     value_parser = ServerCli::validate_path
    // )]
    // /// Filepath to ssh host config
    // pub config_path: String,

    // #[arg(
    //     short = 'k',
    //     long,
    //     value_name = "host key file",
    //     default_value = "/etc/ssh/ssh_host_rsa_key",
    //     value_parser = ServerCli::validate_path
    // )]
    // /// Filepath to ssh host key
    // pub host_key_path: String,
}

impl ServerCli {
    fn validate_path(path: &str) -> Result<String> {
        if Path::new(path).exists() {
            Ok(path.to_string())
        } else {
            Err(Error::msg(format!("File does not exist at path {}", path)))
        }
    }
}