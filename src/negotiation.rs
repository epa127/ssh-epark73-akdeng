use std::{fmt::Display, str::FromStr};

use anyhow::Error;
use sha2::{Sha256, Sha512};

use crate::kex::dh::DiffieHellman;

pub enum ServerHostKeyAlgorithm {
    Ed25519,
    // RsaSha256,
    // RsaSha512,
}

impl Display for ServerHostKeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerHostKeyAlgorithm::Ed25519 => write!(f, "ssh-ed25519"),
        }
    }
}


impl FromStr for ServerHostKeyAlgorithm {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "ssh-ed25519" => Ok(ServerHostKeyAlgorithm::Ed25519),
            _ => Err(Error::msg(format!("Server Host Key Algorithm Not Found: {}", s)))
        }
    }
}

enum KexAlgorithm {
    DiffieHellmanSha256(DiffieHellman<Sha256>),
    DiffieHellmanSha512(DiffieHellman<Sha512>)
}

impl Display for KexAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KexAlgorithm::DiffieHellmanSha256(_) => {
                write!(f, "diffie-hellman-group14-sha256")
            }
            KexAlgorithm::DiffieHellmanSha512(diffie_hellman) => {
                write!(f, "diffie-hellman-group{}-sha512", diffie_hellman.group.id)
            }
        }
    }
}


impl FromStr for KexAlgorithm {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "diffie-hellman-group14-sha256" => Ok(KexAlgorithm::DiffieHellmanSha256(DiffieHellman::new(14)?)),
            "diffie-hellman-group15-sha512" => Ok(KexAlgorithm::DiffieHellmanSha512(DiffieHellman::new(15)?)),
            "diffie-hellman-group16-sha512" => Ok(KexAlgorithm::DiffieHellmanSha512(DiffieHellman::new(16)?)),
            "diffie-hellman-group17-sha512" => Ok(KexAlgorithm::DiffieHellmanSha512(DiffieHellman::new(17)?)),
            "diffie-hellman-group18-sha512" => Ok(KexAlgorithm::DiffieHellmanSha512(DiffieHellman::new(18)?)),
            _ => Err(Error::msg(format!("Kex Algorithm Not Found: {}", s)))
        }
    }
}

enum EncryptionAlgorithms{
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr
}

impl Display for EncryptionAlgorithms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionAlgorithms::Aes128Ctr => write!(f, "aes128-ctr"),
            EncryptionAlgorithms::Aes192Ctr => write!(f, "aes192-ctr"),
            EncryptionAlgorithms::Aes256Ctr => write!(f, "aes256-ctr"),
        }
    }
}


impl FromStr for EncryptionAlgorithms {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "aes128-ctr" => Ok(EncryptionAlgorithms::Aes128Ctr),
            "aes192-ctr" => Ok(EncryptionAlgorithms::Aes192Ctr),
            "aes256-ctr" => Ok(EncryptionAlgorithms::Aes256Ctr),
            _ => Err(Error::msg(format!("Encryption Algorithm Not Found: {}", s)))
        }
    }
}

enum MacAlgorithm {
    HmacSha256,
    HmacSha512
}

impl Display for MacAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MacAlgorithm::HmacSha256 => {
                write!(f, "hmac-sha2-256")
            }
            MacAlgorithm::HmacSha512 => {
                write!(f, "hmac-sha2-512")
            }
        }
    }
}


impl FromStr for MacAlgorithm {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "hmac-sha2-256" => Ok(MacAlgorithm::HmacSha256),
            "hmac-sha2-512" => Ok(MacAlgorithm::HmacSha512),
            _ => Err(Error::msg(format!("Mac Algorithm Not Found: {}", s)))
        }
    }
}

enum CompressionAlgorithm {
    None
}

impl Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressionAlgorithm::None => {
                write!(f, "none")
            }
        }
    }
}


impl FromStr for CompressionAlgorithm {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "none" => Ok(CompressionAlgorithm::None),
            _ => Err(Error::msg(format!("Compression Algorithm Not Found: {}", s)))
        }
    }
}