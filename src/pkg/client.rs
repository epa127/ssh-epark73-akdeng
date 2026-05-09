use std::io::{Read, Write};

use anyhow::{Error, Result};

use crate::{
    PROTOVERSION, SOFTWAREVERSION,
    crypto::{BinaryPacketDecoder, BinaryPacketEncoder, ClientKeyAlg},
    data_primitives::{SshMpint, SshString},
    kex::{KexDhInit, KexDhReply},
    messages::{KexInit, Msg, NewKeys},
};

use super::{read_identification_string, ClientDhState, NegotiatedTransport, Role};

pub enum Client {
    WaitingForProtoVersion(ClientWaitingForProtoVersion),
    WaitingForServerKexInit(ClientWaitingForServerKexInit),
    WaitingForKexReply(ClientWaitingForKexReply),
    WaitingForNewKeys(ClientWaitingForNewKeys),
    Ready(ClientReady),
    Failed,
}

pub(crate) struct ClientWaitingForProtoVersion { client_id: String }

pub(crate) struct ClientWaitingForServerKexInit {
    client_id: String,
    server_id: String,
    encoder: BinaryPacketEncoder,
    decoder: BinaryPacketDecoder,
    send_seq: u32,
    recv_seq: u32,
    client_kexinit: KexInit,
    client_kexinit_payload: Vec<u8>,
}

pub(crate) struct ClientWaitingForKexReply {
    client_id: String,
    server_id: String,
    encoder: BinaryPacketEncoder,
    decoder: BinaryPacketDecoder,
    send_seq: u32,
    recv_seq: u32,
    client_kexinit: KexInit,
    server_kexinit: KexInit,
    client_kexinit_payload: Vec<u8>,
    server_kexinit_payload: Vec<u8>,
    dh: ClientDhState,
    negotiated: NegotiatedTransport,
}

pub(crate) struct ClientWaitingForNewKeys {
    decoder: BinaryPacketDecoder,
    send_seq: u32,
    recv_seq: u32,
    pending_encoder: BinaryPacketEncoder,
    pending_decoder: BinaryPacketDecoder,
    session_id: Vec<u8>,
}

pub(crate) struct ClientReady {
    encoder: BinaryPacketEncoder,
    decoder: BinaryPacketDecoder,
    send_seq: u32,
    recv_seq: u32,
    session_id: Vec<u8>,
}

impl Client {
    pub fn new() -> Self {
        Self::WaitingForProtoVersion(ClientWaitingForProtoVersion {
            client_id: format!("SSH-{}-{}", PROTOVERSION, SOFTWAREVERSION),
        })
    }

    pub fn start<W: Write>(&mut self, writer: &mut W) -> Result<()> {
        match self {
            Client::WaitingForProtoVersion(state) => state.start(writer),
            _ => Err(Error::msg("Client is not waiting to send protocol version")),
        }
    }

    pub fn receive_proto_version<R: Read, W: Write>(&mut self, reader: &mut R, writer: &mut W) -> Result<()> {
        let state = std::mem::replace(self, Client::Failed);
        match state {
            Client::WaitingForProtoVersion(state) => {
                *self = Client::WaitingForServerKexInit(state.receive_proto_version(reader, writer)?);
                Ok(())
            }
            other => { *self = other; Err(Error::msg("Client is not waiting for protocol version")) }
        }
    }

    pub fn receive_server_kexinit<R: Read, W: Write>(&mut self, reader: &mut R, writer: &mut W) -> Result<()> {
        let state = std::mem::replace(self, Client::Failed);
        match state {
            Client::WaitingForServerKexInit(state) => {
                *self = Client::WaitingForKexReply(state.receive_server_kexinit(reader, writer)?);
                Ok(())
            }
            other => { *self = other; Err(Error::msg("Client is not waiting for server KEXINIT")) }
        }
    }

    pub fn receive_kex_reply<R: Read, W: Write>(&mut self, reader: &mut R, writer: &mut W) -> Result<()> {
        let state = std::mem::replace(self, Client::Failed);
        match state {
            Client::WaitingForKexReply(state) => {
                *self = Client::WaitingForNewKeys(state.receive_kex_reply(reader, writer)?);
                Ok(())
            }
            other => { *self = other; Err(Error::msg("Client is not waiting for KEXDH_REPLY")) }
        }
    }

    pub fn receive_newkeys<R: Read>(&mut self, reader: &mut R) -> Result<()> {
        let state = std::mem::replace(self, Client::Failed);
        match state {
            Client::WaitingForNewKeys(state) => {
                *self = Client::Ready(state.receive_newkeys(reader)?);
                Ok(())
            }
            other => { *self = other; Err(Error::msg("Client is not waiting for NEWKEYS")) }
        }
    }

    pub fn send_packet<W: Write>(&mut self, writer: &mut W, payload: &[u8]) -> Result<()> {
        match self {
            Client::Ready(state) => state.send_packet(writer, payload),
            _ => Err(Error::msg("Client transport is not ready")),
        }
    }

    pub fn read_packet<R: Read>(&mut self, reader: &mut R) -> Result<Vec<u8>> {
        match self {
            Client::Ready(state) => state.read_packet(reader),
            _ => Err(Error::msg("Client transport is not ready")),
        }
    }
}

impl ClientWaitingForProtoVersion {
    fn start<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(self.client_id.as_bytes())?;
        writer.write_all(b"\r\n")?;
        writer.flush()?;
        Ok(())
    }

    fn receive_proto_version<R: Read, W: Write>(self, reader: &mut R, writer: &mut W) -> Result<ClientWaitingForServerKexInit> {
        let server_id = read_identification_string(reader)?;
        let mut encoder = BinaryPacketEncoder::naked();
        let decoder = BinaryPacketDecoder::naked();
        let client_kexinit = KexInit::default_client()?;
        let client_kexinit_payload = client_kexinit.serialize()?;
        let packet = encoder.build(&client_kexinit_payload, 0)?;
        writer.write_all(&packet)?;
        writer.flush()?;
        Ok(ClientWaitingForServerKexInit { client_id: self.client_id, server_id, encoder, decoder, send_seq: 1, recv_seq: 0, client_kexinit, client_kexinit_payload })
    }
}

impl ClientWaitingForServerKexInit {
    fn receive_server_kexinit<R: Read, W: Write>(mut self, reader: &mut R, writer: &mut W) -> Result<ClientWaitingForKexReply> {
        let server_kexinit_payload = self.decoder.decode_from(reader, self.recv_seq)?;
        let server_kexinit = KexInit::deserialize(&server_kexinit_payload)?;
        let negotiated = NegotiatedTransport::client_negotiate(&self.client_kexinit, &server_kexinit)?;
        let dh = ClientDhState::new(&negotiated)?;
        let kexdh_init = KexDhInit { e: SshMpint::new(dh.public_value.clone()) };
        let kexdh_init_payload = kexdh_init.serialize()?;
        let packet = self.encoder.build(&kexdh_init_payload, self.send_seq)?;
        writer.write_all(&packet)?;
        writer.flush()?;
        Ok(ClientWaitingForKexReply {
            client_id: self.client_id, server_id: self.server_id, encoder: self.encoder, decoder: self.decoder,
            send_seq: self.send_seq.wrapping_add(1), recv_seq: self.recv_seq.wrapping_add(1),
            client_kexinit: self.client_kexinit, server_kexinit, client_kexinit_payload: self.client_kexinit_payload,
            server_kexinit_payload, dh, negotiated,
        })
    }
}

impl ClientWaitingForKexReply {
    fn receive_kex_reply<R: Read, W: Write>(mut self, reader: &mut R, writer: &mut W) -> Result<ClientWaitingForNewKeys> {
        let reply_payload = self.decoder.decode_from(reader, self.recv_seq)?;
        let reply = KexDhReply::deserialize(&reply_payload)?;

        let server_public_value = reply.f.int.clone();

        let shared_secret = self
            .dh
            .compute_shared_secret(&self.negotiated, server_public_value.clone())?;

        let host_key_blob = reply.k_s;
        let signature_blob = reply.signature;

        let exchange_hash = self.negotiated.kex_hash(
            &SshString::new(self.client_id.as_bytes())?,
            &SshString::new(self.server_id.as_bytes())?,
            &SshString::new(&self.client_kexinit_payload)?,
            &SshString::new(&self.server_kexinit_payload)?,
            &host_key_blob,
            &SshMpint::new(self.dh.public_value.clone()),
            &SshMpint::new(server_public_value),
            &SshMpint::new(shared_secret.clone()),
        )?;

        let verifier = ClientKeyAlg::from_public_key_blob(&host_key_blob.bytes)?;
        verifier.verify_exchange_hash_signature(&exchange_hash, &signature_blob.bytes)?;
        let session_id = exchange_hash.clone();
        let pending_keys = self.negotiated.derive_keys(&shared_secret, &exchange_hash, &session_id, Role::Client)?;
        let (pending_encoder, pending_decoder) = pending_keys.into_client_pair();
        let newkeys_payload = NewKeys {}.serialize()?;
        let packet = self.encoder.build(&newkeys_payload, self.send_seq)?;
        writer.write_all(&packet)?;
        writer.flush()?;
        Ok(ClientWaitingForNewKeys { decoder: self.decoder, send_seq: self.send_seq.wrapping_add(1), recv_seq: self.recv_seq.wrapping_add(1), pending_encoder, pending_decoder, session_id })
    }
}

impl ClientWaitingForNewKeys {
    fn receive_newkeys<R: Read>(mut self, reader: &mut R) -> Result<ClientReady> {
        let payload = self.decoder.decode_from(reader, self.recv_seq)?;
        NewKeys::deserialize(&payload)?;
        Ok(ClientReady { encoder: self.pending_encoder, decoder: self.pending_decoder, send_seq: self.send_seq, recv_seq: self.recv_seq.wrapping_add(1), session_id: self.session_id })
    }
}

impl ClientReady {
    fn send_packet<W: Write>(&mut self, writer: &mut W, payload: &[u8]) -> Result<()> {
        let packet = self.encoder.build(payload, self.send_seq)?;
        writer.write_all(&packet)?;
        writer.flush()?;
        self.send_seq = self.send_seq.wrapping_add(1);
        Ok(())
    }

    fn read_packet<R: Read>(&mut self, reader: &mut R) -> Result<Vec<u8>> {
        let payload = self.decoder.decode_from(reader, self.recv_seq)?;
        self.recv_seq = self.recv_seq.wrapping_add(1);
        Ok(payload)
    }
}
