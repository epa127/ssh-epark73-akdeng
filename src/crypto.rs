use std::{cmp::max, fmt::Display, marker::PhantomData, str::FromStr};
use crate::{check_and_inc, data_primitives::SshUint32, kex::dh::{DhGroup, DiffieHellman}};

use aes::{Aes128, Aes192, Aes256, cipher::{Array, BlockCipherEncrypt, BlockSizeUser, KeyInit, KeyIvInit, KeySizeUser, StreamCipher, consts::{U16, U326}}};
use anyhow::{Error, Result};
use hmac::{Hmac, Mac, SimpleHmac, digest::{HashMarker, OutputSizeUser, core_api::{self, CoreProxy}}};
use sha2::{Digest, Sha256, Sha512};
use rand::{TryRngCore, prelude::*, rngs::OsRng, seq};

pub trait KexImplementor {

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

enum BinaryPacketEncoder {
    Naked,
    Traditional{ cipher: Box<Cipher>, mac: KeyedMac },
    // AeadGcm()
    // Aes256Gcm
}

impl BinaryPacketEncoder {
    fn get_padding_increment(&self) -> usize {
        max( 8, match self {
            BinaryPacketEncoder::Naked => 8,
            BinaryPacketEncoder::Traditional { cipher, .. } => cipher.block_size(),
        })
    }

    pub fn build(&mut self, payload: &[u8], seq_num: u32) -> Result<Vec<u8>> {
        let payload_len = payload.len();
        let pad_inc = self.get_padding_increment();

        let rem = (5 + payload_len) % pad_inc;
        let buf = (pad_inc - rem) % pad_inc;

        let start = if buf >= 4 {
            buf
        } else {
            buf + pad_inc
        };

        let mut pad_lengths = Vec::new();
        let mut pad_len = start;

        while pad_len <= 255 {
            pad_lengths.push(pad_len);
            pad_len += pad_inc;
        }

        let padding_length = pad_lengths.choose(&mut rand::rng()).ok_or(Error::msg("No possible pad lengths."))?;
        
        let mut padding = vec![0u8; *padding_length];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut padding)?;

        let packet_length: u32 = 1 + payload_len as u32 + *padding_length as u32;

        self.protect(packet_length, *padding_length as u8, payload, &padding, seq_num)
    }

    fn protect(&mut self, packet_length: u32, padding_length: u8, payload: &[u8], padding: &[u8], seq_num: u32) -> Result<Vec<u8>> {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&SshUint32::new(packet_length).to_be_bytes());
        data.push(padding_length);
        data.extend_from_slice(payload);
        data.extend_from_slice(padding);
        
        match self {
            BinaryPacketEncoder::Naked => {
                Ok(data)
            },
            BinaryPacketEncoder::Traditional { cipher, mac } => {
                let mut mac_data: Vec<u8> = Vec::new();
                mac_data.extend_from_slice(&SshUint32::new(seq_num).to_be_bytes());
                mac_data.extend_from_slice(&data);
                let data_mac = mac.generate_mac(&mac_data)?;
                let mut enc_data = cipher.encrypt(&data)?;
                enc_data.extend_from_slice(&data_mac);
                Ok(enc_data)
            },
        }
    }
}

enum BinaryPacketDecoder {
    Naked,
    Traditional{ cipher: Box<Cipher>, mac: KeyedMac },
    // AeadGcm()
    // Aes256Gcm
}

impl BinaryPacketDecoder {
    fn get_padding_increment(&self) -> usize {
        max( 8, match self {
            BinaryPacketDecoder::Naked => 8,
            BinaryPacketDecoder::Traditional { cipher, .. } => cipher.block_size(),
        })
    }

    fn get_payload(packet: &[u8]) -> Result<Vec<u8>> {
        if packet.is_empty() {
            return Err(Error::msg("Empty packet!"));
        }
    
        let mut i: usize = 0;
    
        let packet_length = SshUint32::from_be_bytes(&packet[i..])?.int;
        check_and_inc(packet, &mut i, &4)?;
    
        let padding_length = packet[i];
        check_and_inc(packet, &mut i, &1)?;
    
        if padding_length < 4 {
            return Err(Error::msg("Invalid packet: padding length less than 4"));
        }
    
        let payload_length = packet_length
            .checked_sub(padding_length as u32)
            .and_then(|n| n.checked_sub(1))
            .ok_or_else(|| Error::msg("Invalid packet lengths"))? as usize;
    
        let payload_start = i;
        check_and_inc(packet, &mut i, &payload_length)?;
        let payload_end = i;
    
        check_and_inc(packet, &mut i, &(padding_length as usize))?;
    
        if packet.len() != i {
            return Err(Error::msg("Invalid read: expected no more bytes"));
        }
    
        Ok(packet[payload_start..payload_end].to_vec())
    }

    pub fn decode(&mut self, packet: &[u8], seq_num: u32) -> Result<Vec<u8>> {
        match self {
            BinaryPacketDecoder::Naked => {
                Self::get_payload(packet)
            },
            BinaryPacketDecoder::Traditional { cipher, mac } => {
                let packet_len = packet.len();
                let mac_len = mac.mac_len();
            
                if packet_len < mac_len {
                    return Err(Error::msg("Packet too short for MAC"));
                }
            
                let data_mac = &packet[(packet_len - mac_len)..];
                let enc_data = &packet[..(packet_len - mac_len)];
            
                let data = cipher.decrypt(enc_data)?;
            
                let mut mac_data: Vec<u8> = Vec::new();
                mac_data.extend_from_slice(&SshUint32::new(seq_num).to_be_bytes());
                mac_data.extend_from_slice(&data);
            
                mac.verify_mac(&mac_data, data_mac)?;
            
                Self::get_payload(&data)
            }
        }
    }
}

#[allow(clippy::enum_variant_names)]
enum Cipher {
    Aes128Ctr(SshAesCtr<Aes128>),
    Aes192Ctr(SshAesCtr<Aes192>),
    Aes256Ctr(SshAesCtr<Aes256>)
}

impl Cipher {
    fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        match self {
            Cipher::Aes128Ctr(ssh_aes_ctr) => ssh_aes_ctr.encrypt(input),
            Cipher::Aes192Ctr(ssh_aes_ctr) => ssh_aes_ctr.encrypt(input),
            Cipher::Aes256Ctr(ssh_aes_ctr) => ssh_aes_ctr.encrypt(input),
        }
    }
    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        match self {
            Cipher::Aes128Ctr(ssh_aes_ctr) => ssh_aes_ctr.decrypt(input),
            Cipher::Aes192Ctr(ssh_aes_ctr) => ssh_aes_ctr.decrypt(input),
            Cipher::Aes256Ctr(ssh_aes_ctr) => ssh_aes_ctr.decrypt(input),
        }
    }
    fn block_size(&self) -> usize {
        match self {
            Cipher::Aes128Ctr(ssh_aes_ctr) => ssh_aes_ctr.block_size(),
            Cipher::Aes192Ctr(ssh_aes_ctr) => ssh_aes_ctr.block_size(),
            Cipher::Aes256Ctr(ssh_aes_ctr) => ssh_aes_ctr.block_size(),
        }
    }
}

struct SshAesCtr<C>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit,
{
    cipher: aes::cipher::StreamCipherCoreWrapper<ctr::CtrCore<C, ctr::flavors::Ctr128BE>>,
}

impl<C> SshAesCtr<C>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit,
{
    fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        let cipher = ctr::Ctr128BE::<C>::new_from_slices(key, iv)?;
        Ok(Self {cipher})
    }

    fn block_size(&self) -> usize {
        C::block_size()
    }

    fn apply(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut output = input.to_vec();
        self.cipher.apply_keystream(&mut output);
        Ok(output)
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.apply(plaintext)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.apply(ciphertext)
    }
}

enum MacAlgorithm {
    HmacSha256,
    HmacSha512
}

enum KeyedMac {
    HmacSha256(SshHmac<Sha256>),
    HmacSha512(SshHmac<Sha512>)
}

impl KeyedMac {
    pub fn generate_mac(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            KeyedMac::HmacSha256(ssh_hmac) => ssh_hmac.generate_mac(msg),
            KeyedMac::HmacSha512(ssh_hmac) => ssh_hmac.generate_mac(msg),
        }
    }

    pub fn verify_mac(&self, msg: &[u8], received_mac: &[u8]) -> Result<()> {
        match self {
            KeyedMac::HmacSha256(ssh_hmac) => ssh_hmac.verify_mac(msg, received_mac),
            KeyedMac::HmacSha512(ssh_hmac) => ssh_hmac.verify_mac(msg, received_mac),
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            KeyedMac::HmacSha256(ssh_hmac) => ssh_hmac.key_len(),
            KeyedMac::HmacSha512(ssh_hmac) => ssh_hmac.key_len(),
        }
    }

    pub fn mac_len(&self) -> usize {
        match self {
            KeyedMac::HmacSha256(ssh_hmac) => ssh_hmac.mac_len(),
            KeyedMac::HmacSha512(ssh_hmac) => ssh_hmac.mac_len(),
        }
    }

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

struct SshHmac<D> 
    where D: Digest + core_api::BlockSizeUser, 
{
    _hash: PhantomData<D>,
    key: Vec<u8>
}

impl<D> SshHmac<D> 
    where D: Digest + core_api::BlockSizeUser 
{
    pub fn new(key: &[u8]) -> Self {
        SshHmac { _hash: PhantomData, key: key.to_vec() }
    }

    pub fn key_len(&self) -> usize {
        <D as OutputSizeUser>::output_size()
    }

    pub fn mac_len(&self) -> usize {
        <D as OutputSizeUser>::output_size()
    }

    pub fn generate_mac(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let mut mac = SimpleHmac::<D>::new_from_slice(&self.key)?;
        mac.update(msg);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub fn verify_mac(&self, msg: &[u8], received_mac: &[u8]) -> Result<()> {
        let mut mac = SimpleHmac::<D>::new_from_slice(&self.key)?;
        mac.update(msg);
        mac.verify_slice(received_mac)?;
        Ok(())
    }
}