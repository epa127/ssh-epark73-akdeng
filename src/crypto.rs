use std::{cmp::max, io::Read, marker::PhantomData};
use crate::{SSH_ED25519, check_and_inc, data_primitives::SshUint32, messages::{Ed25519PublicKeyBlob, Ed25519SignatureBlob}};

use aes::{Aes128, Aes192, Aes256, cipher::{BlockCipherEncrypt, BlockSizeUser, KeyInit, KeyIvInit, StreamCipher, consts::U16}};
use anyhow::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Mac, SimpleHmac, digest::{OutputSizeUser, core_api}};
use sha2::{Digest, Sha256, Sha512};
use rand::{TryRngCore, prelude::*, rngs::OsRng};

pub enum BinaryPacketEncoder {
    Naked,
    Traditional{ cipher: Box<Cipher>, mac: KeyedMac },
    // AeadGcm()
    // Aes256Gcm
}

impl BinaryPacketEncoder {
    pub fn naked() -> Self { Self::Naked }

    pub fn traditional(cipher: Cipher, mac: KeyedMac) -> Self {
        Self::Traditional { cipher: Box::new(cipher), mac }
    }

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
pub enum ServerKeyAlg {
    Ed25519(Ed25519Signer<SigningKey>),
}

impl ServerKeyAlg {
    pub fn name(&self) -> &'static str {
        match self {
            ServerKeyAlg::Ed25519(_) => SSH_ED25519,
        }
    }

    pub fn public_key_blob(&self) -> Result<Vec<u8>> {
        match self {
            ServerKeyAlg::Ed25519(signer) => signer.public_key_blob(),
        }
    }

    pub fn sign_exchange_hash(&self, hash: &[u8]) -> Result<Vec<u8>> {
        match self {
            ServerKeyAlg::Ed25519(signer) => signer.sign_exchange_hash_blob(hash),
        }
    }
}

pub enum ClientKeyAlg {
    Ed25519(Ed25519Verifier<VerifyingKey>),
}

impl ClientKeyAlg {
    pub fn name(&self) -> &'static str {
        match self {
            ClientKeyAlg::Ed25519(_) => SSH_ED25519,
        }
    }

    pub fn from_public_key_blob(blob: &[u8]) -> Result<Self> {
        let public_key_blob = Ed25519PublicKeyBlob::from_be_bytes(blob)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key_blob.public_key)
            .map_err(|e| Error::msg(e.to_string()))?;

        Ok(Self::Ed25519(Ed25519Verifier { verifying_key }))
    }

    pub fn verify_exchange_hash_signature(&self,exchange_hash: &[u8],signature_blob: &[u8]) -> Result<()> {
        match self {
            ClientKeyAlg::Ed25519(verifier) => {
                verifier.verify_exchange_hash_signature_blob(exchange_hash, signature_blob)
            }
        }
    }
}

pub struct Ed25519Signer<S>
where
    S: Signer<Signature>,
{
    pub signing_key: S,
    pub public_key: [u8; 32],
}

impl<S> Ed25519Signer<S>
where
    S: Signer<Signature>,
{
    pub fn public_key_blob(&self) -> Result<Vec<u8>> {
        Ed25519PublicKeyBlob::new(self.public_key).to_be_bytes()
    }

    pub fn sign_exchange_hash_raw(&self, hash: &[u8]) -> Signature {
        self.signing_key.sign(hash)
    }

    pub fn sign_exchange_hash_blob(&self, hash: &[u8]) -> Result<Vec<u8>> {
        let signature = self.sign_exchange_hash_raw(hash);
        Ed25519SignatureBlob::new(signature).to_be_bytes()
    }
}

pub struct Ed25519Verifier<V>
where
    V: Verifier<Signature>,
{
    pub verifying_key: V,
}

impl<V> Ed25519Verifier<V>
where
    V: Verifier<Signature>,
{
    pub fn verify_signature(&self, msg: &[u8], signature: &Signature) -> Result<()> {
        self.verifying_key.verify(msg, signature).map_err(|e| Error::msg(e.to_string()))
    }

    pub fn verify_exchange_hash_signature_blob(&self,exchange_hash: &[u8],signature_blob: &[u8]) -> Result<()> {
        let signature_blob = Ed25519SignatureBlob::from_be_bytes(signature_blob)?;

        self.verify_signature(exchange_hash, &signature_blob.signature)
            .map_err(|e| Error::msg(e.to_string()))?;

        Ok(())
    }
}
pub enum BinaryPacketDecoder {
    Naked,
    Traditional{ cipher: Box<Cipher>, mac: KeyedMac },
    // AeadGcm()
    // Aes256Gcm
}

impl BinaryPacketDecoder {
    pub fn naked() -> Self { Self::Naked }

    pub fn traditional(cipher: Cipher, mac: KeyedMac) -> Self {
        Self::Traditional { cipher: Box::new(cipher), mac }
    }

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

    pub fn decode_from<R: Read>(&mut self, reader: &mut R, seq_num: u32) -> Result<Vec<u8>> {
        match self {
            BinaryPacketDecoder::Naked => {
                let mut buf = vec![0u8; 4];
                reader.read_exact(&mut buf)?;
                let packet_length = SshUint32::from_be_bytes(&buf)?.int;

                if packet_length < 5 {
                    return Err(Error::msg("Invalid packet length"));
                }
                
                if packet_length > 35000 {
                    return Err(Error::msg("Packet too large"));
                }

                let mut payload_buf = vec![0u8; packet_length as usize];
                reader.read_exact(&mut payload_buf)?;

                buf.extend_from_slice(&payload_buf);
                Self::get_payload(&buf)
            },
            BinaryPacketDecoder::Traditional { cipher, mac } => {
                let first_len = cipher.block_size();
                let mac_len = mac.mac_len();
            
                let mut first_enc = vec![0u8; first_len];
                reader.read_exact(&mut first_enc)?;
            
                let mut packet = cipher.decrypt(&first_enc)?;
            
                let packet_length = SshUint32::from_be_bytes(&packet[..4])?.int as usize;
            
                if packet_length < 5 {
                    return Err(Error::msg("Invalid packet length"));
                }
            
                if packet_length > 35000 {
                    return Err(Error::msg("Packet too large"));
                }
            
                let total_packet_len = 4 + packet_length;
            
                if total_packet_len < first_len {
                    return Err(Error::msg("Invalid packet length"));
                }
            
                let remaining_enc_len = total_packet_len - first_len;
            
                let mut rest = vec![0u8; remaining_enc_len + mac_len];
                reader.read_exact(&mut rest)?;
            
                let remaining_enc = &rest[..remaining_enc_len];
                let data_mac = &rest[remaining_enc_len..];
            
                let remaining_plain = cipher.decrypt(remaining_enc)?;
                packet.extend_from_slice(&remaining_plain);
            
                let mut mac_data = Vec::with_capacity(4 + packet.len());
                mac_data.extend_from_slice(&SshUint32::new(seq_num).to_be_bytes());
                mac_data.extend_from_slice(&packet);
            
                mac.verify_mac(&mac_data, data_mac)?;
            
                Self::get_payload(&packet)
            }
        }
    }
}

#[allow(clippy::enum_variant_names)]
pub enum Cipher {
    Aes128Ctr(SshAesCtr<Aes128>),
    Aes192Ctr(SshAesCtr<Aes192>),
    Aes256Ctr(SshAesCtr<Aes256>)
}

impl Cipher {
    pub fn aes128_ctr(key: &[u8], iv: &[u8]) -> Result<Self> {
        Ok(Self::Aes128Ctr(SshAesCtr::<Aes128>::new(key, iv)?))
    }

    pub fn aes192_ctr(key: &[u8], iv: &[u8]) -> Result<Self> {
        Ok(Self::Aes192Ctr(SshAesCtr::<Aes192>::new(key, iv)?))
    }

    pub fn aes256_ctr(key: &[u8], iv: &[u8]) -> Result<Self> {
        Ok(Self::Aes256Ctr(SshAesCtr::<Aes256>::new(key, iv)?))
    }

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

pub struct SshAesCtr<C>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit,
    ctr::Ctr128BE<C>: KeyIvInit + StreamCipher,
{
    cipher: ctr::Ctr128BE<C>,
}

impl<C> SshAesCtr<C>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit,
    ctr::Ctr128BE<C>: KeyIvInit + StreamCipher,
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

pub enum KeyedMac {
    HmacSha256(SshHmac<Sha256>),
    HmacSha512(SshHmac<Sha512>)
}

impl KeyedMac {
    pub fn hmac_sha256(key: &[u8]) -> Self {
        Self::HmacSha256(SshHmac::<Sha256>::new(key))
    }

    pub fn hmac_sha512(key: &[u8]) -> Self {
        Self::HmacSha512(SshHmac::<Sha512>::new(key))
    }

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

pub struct SshHmac<D> 
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