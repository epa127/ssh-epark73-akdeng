pub mod client;
pub mod server;

use std::{io::Read, str::FromStr};

use anyhow::{Error, Result};
use num_bigint::BigUint;
use sha2::{Digest, Sha256, Sha512};

use crate::{
    crypto::{BinaryPacketDecoder, BinaryPacketEncoder, Cipher, KeyedMac},
    data_primitives::{SshMpint, SshString},
    messages::KexInit,
    negotiation::{CompressionAlgorithm, EncryptionAlgorithms, KexAlgorithm, MacAlgorithm, ServerHostKeyAlgorithm},
};

pub enum Role {
    Client,
    Server,
}

pub fn read_identification_string<R: Read>(reader: &mut R) -> Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];

    loop {
        let n = reader.read(&mut byte)?;

        if n == 0 {
            return Err(Error::msg("Connection closed before SSH identification string"));
        }

        buf.push(byte[0]);

        if byte[0] == b'\n' {
            break;
        }

        if buf.len() > 255 {
            return Err(Error::msg("SSH identification string too long"));
        }
    }

    let line = std::str::from_utf8(&buf)?;

    let line = line
        .strip_suffix("\r\n")
        .or_else(|| line.strip_suffix('\n'))
        .ok_or_else(|| Error::msg("SSH identification string missing line ending"))?;

    if !line.starts_with("SSH-2.0-") {
        return Err(Error::msg(format!("Unsupported SSH identification string: {}", line)));
    }

    Ok(line.to_string())
}

pub struct ClientDhState {
    pub secret: BigUint,
    pub public_value: BigUint,
}

impl ClientDhState {
    pub fn new(negotiated: &NegotiatedTransport) -> Result<Self> {
        negotiated.make_client_dh_state()
    }

    pub fn compute_shared_secret(&self, negotiated: &NegotiatedTransport, server_public_value: BigUint) -> Result<BigUint> {
        negotiated.compute_dh_shared_secret(server_public_value, self.secret.clone())
    }
}

pub struct ServerDhState {
    pub secret: BigUint,
    pub public_value: BigUint,
}

impl ServerDhState {
    pub fn new(negotiated: &NegotiatedTransport) -> Result<Self> {
        negotiated.make_server_dh_state()
    }

    pub fn compute_shared_secret(&self, negotiated: &NegotiatedTransport, client_public_value: BigUint) -> Result<BigUint> {
        negotiated.compute_dh_shared_secret(client_public_value, self.secret.clone())
    }
}

pub struct NegotiatedTransport {
    pub kex: KexAlgorithm,
    pub host_key: ServerHostKeyAlgorithm,
    pub enc_c2s: EncryptionAlgorithms,
    pub enc_s2c: EncryptionAlgorithms,
    pub mac_c2s: MacAlgorithm,
    pub mac_s2c: MacAlgorithm,
    pub comp_c2s: CompressionAlgorithm,
    pub comp_s2c: CompressionAlgorithm,
}

impl NegotiatedTransport {
    pub fn client_negotiate(client: &KexInit, server: &KexInit) -> Result<Self> {
        let kex = KexAlgorithm::from_str(select_first_match(client.kex_algorithms(), server.kex_algorithms(), "kex")?)?;
        let host_key = ServerHostKeyAlgorithm::from_str(select_first_match(
            client.server_host_key_algorithms(),
            server.server_host_key_algorithms(),
            "server host key",
        )?)?;
        let enc_c2s = EncryptionAlgorithms::from_str(select_first_match(client.enc_c2s(), server.enc_c2s(), "encryption c2s")?)?;
        let enc_s2c = EncryptionAlgorithms::from_str(select_first_match(client.enc_s2c(), server.enc_s2c(), "encryption s2c")?)?;
        let mac_c2s = MacAlgorithm::from_str(select_first_match(client.mac_c2s(), server.mac_c2s(), "mac c2s")?)?;
        let mac_s2c = MacAlgorithm::from_str(select_first_match(client.mac_s2c(), server.mac_s2c(), "mac s2c")?)?;
        let comp_c2s = CompressionAlgorithm::from_str(select_first_match(client.comp_c2s(), server.comp_c2s(), "compression c2s")?)?;
        let comp_s2c = CompressionAlgorithm::from_str(select_first_match(client.comp_s2c(), server.comp_s2c(), "compression s2c")?)?;

        Ok(Self { kex, host_key, enc_c2s, enc_s2c, mac_c2s, mac_s2c, comp_c2s, comp_s2c })
    }

    pub fn server_negotiate(client: &KexInit, server: &KexInit) -> Result<Self> {
        Self::client_negotiate(client, server)
    }

    pub fn make_client_dh_state(&self) -> Result<ClientDhState> {
        let (secret, public_value) = self.kex.generate_keypair()?;
        Ok(ClientDhState { secret, public_value })
    }

    pub fn make_server_dh_state(&self) -> Result<ServerDhState> {
        let (secret, public_value) = self.kex.generate_keypair()?;
        Ok(ServerDhState { secret, public_value })
    }

    pub fn compute_dh_shared_secret(&self, peer_public: BigUint, secret: BigUint) -> Result<BigUint> {
        Ok(self.kex.compute_shared_key(peer_public, secret))
    }

    pub fn kex_hash(
        &self,
        client_id: &SshString,
        server_id: &SshString,
        client_init: &SshString,
        server_init: &SshString,
        host_key: &SshString,
        client_kex: &SshMpint,
        server_kex: &SshMpint,
        shared_secret: &SshMpint,
    ) -> Result<Vec<u8>> {
        self.kex.exchange_hash(client_id, server_id, client_init, server_init, host_key, client_kex, server_kex, shared_secret)
    }

    pub fn derive_keys(
        &self,
        shared_secret: &BigUint,
        exchange_hash: &[u8],
        session_id: &[u8],
        _role: Role,
    ) -> Result<PendingKeys> {
        let iv_c2s = self.derive_key_letter(shared_secret, exchange_hash, session_id, b'A', self.enc_c2s.iv_len())?;
        let iv_s2c = self.derive_key_letter(shared_secret, exchange_hash, session_id, b'B', self.enc_s2c.iv_len())?;
        let key_c2s = self.derive_key_letter(shared_secret, exchange_hash, session_id, b'C', self.enc_c2s.key_len())?;
        let key_s2c = self.derive_key_letter(shared_secret, exchange_hash, session_id, b'D', self.enc_s2c.key_len())?;
        let mac_c2s = self.derive_key_letter(shared_secret, exchange_hash, session_id, b'E', self.mac_c2s.key_len())?;
        let mac_s2c = self.derive_key_letter(shared_secret, exchange_hash, session_id, b'F', self.mac_s2c.key_len())?;

        let c2s_encoder = BinaryPacketEncoder::traditional(
            make_cipher(&self.enc_c2s, &key_c2s, &iv_c2s)?,
            make_mac(&self.mac_c2s, &mac_c2s),
        );
        let c2s_decoder = BinaryPacketDecoder::traditional(
            make_cipher(&self.enc_c2s, &key_c2s, &iv_c2s)?,
            make_mac(&self.mac_c2s, &mac_c2s),
        );
        let s2c_encoder = BinaryPacketEncoder::traditional(
            make_cipher(&self.enc_s2c, &key_s2c, &iv_s2c)?,
            make_mac(&self.mac_s2c, &mac_s2c),
        );
        let s2c_decoder = BinaryPacketDecoder::traditional(
            make_cipher(&self.enc_s2c, &key_s2c, &iv_s2c)?,
            make_mac(&self.mac_s2c, &mac_s2c),
        );

        Ok(PendingKeys { c2s_encoder, c2s_decoder, s2c_encoder, s2c_decoder })
    }

    fn derive_key_letter(&self, shared_secret: &BigUint, exchange_hash: &[u8], session_id: &[u8], letter: u8, len: usize) -> Result<Vec<u8>> {
        match self.kex.hash_len() {
            32 => derive_key_with_hash::<Sha256>(shared_secret, exchange_hash, session_id, letter, len),
            64 => derive_key_with_hash::<Sha512>(shared_secret, exchange_hash, session_id, letter, len),
            n => Err(Error::msg(format!("Unsupported KEX hash length: {}", n))),
        }
    }
}

pub struct PendingKeys {
    pub c2s_encoder: BinaryPacketEncoder,
    pub c2s_decoder: BinaryPacketDecoder,
    pub s2c_encoder: BinaryPacketEncoder,
    pub s2c_decoder: BinaryPacketDecoder,
}

impl PendingKeys {
    pub fn into_client_pair(self) -> (BinaryPacketEncoder, BinaryPacketDecoder) {
        (self.c2s_encoder, self.s2c_decoder)
    }

    pub fn into_server_pair(self) -> (BinaryPacketEncoder, BinaryPacketDecoder) {
        (self.s2c_encoder, self.c2s_decoder)
    }
}

fn select_first_match<'a>(client: &'a [String], server: &[String], what: &str) -> Result<&'a str> {
    for candidate in client {
        if server.iter().any(|s| s == candidate) {
            return Ok(candidate.as_str());
        }
    }

    Err(Error::msg(format!("No mutually supported {} algorithm", what)))
}

fn make_cipher(algorithm: &EncryptionAlgorithms, key: &[u8], iv: &[u8]) -> Result<Cipher> {
    match algorithm {
        EncryptionAlgorithms::Aes128Ctr => Cipher::aes128_ctr(&key[..16], &iv[..16]),
        EncryptionAlgorithms::Aes192Ctr => Cipher::aes192_ctr(&key[..24], &iv[..16]),
        EncryptionAlgorithms::Aes256Ctr => Cipher::aes256_ctr(&key[..32], &iv[..16]),
    }
}

fn make_mac(algorithm: &MacAlgorithm, key: &[u8]) -> KeyedMac {
    match algorithm {
        MacAlgorithm::HmacSha256 => KeyedMac::hmac_sha256(&key[..32]),
        MacAlgorithm::HmacSha512 => KeyedMac::hmac_sha512(&key[..64]),
    }
}

fn derive_key_with_hash<D: Digest>(shared_secret: &BigUint, exchange_hash: &[u8], session_id: &[u8], letter: u8, len: usize) -> Result<Vec<u8>> {
    let k = SshMpint::new(shared_secret.clone()).to_be_bytes()?;
    let mut out = Vec::new();

    let mut h = D::new();
    h.update(&k);
    h.update(exchange_hash);
    h.update(&[letter]);
    h.update(session_id);
    let block = h.finalize();
    out.extend_from_slice(block.as_slice());

    while out.len() < len {
        let mut h = D::new();
        h.update(&k);
        h.update(exchange_hash);
        h.update(&out);
        let block = h.finalize();
        out.extend_from_slice(block.as_slice());
    }

    out.truncate(len);
    Ok(out)
}