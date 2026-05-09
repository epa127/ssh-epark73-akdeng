use std::io::{Read, Write};

use anyhow::{Error, Result};

use crate::{
    PROTOVERSION,
    SOFTWAREVERSION,
    crypto::{BinaryPacketDecoder, BinaryPacketEncoder, ServerKeyAlg},
    data_primitives::{SshMpint, SshString},
    kex::{KexDhInit, KexDhReply},
    messages::{KexInit, Msg, NewKeys},
};

use super::{
    read_identification_string,
    NegotiatedTransport,
    Role,
    ServerDhState,
};

pub enum Server {
    WaitingForProtoVersion(ServerWaitingForProtoVersion),
    WaitingForClientKexInit(ServerWaitingForClientKexInit),
    WaitingForKexDhInit(ServerWaitingForKexDhInit),
    WaitingForNewKeys(ServerWaitingForNewKeys),
    Ready(ServerReady),
    Failed,
}

pub(crate) struct ServerWaitingForProtoVersion {
    server_id: String,
    host_key: ServerKeyAlg,
}

pub(crate) struct ServerWaitingForClientKexInit {
    client_id: String,
    server_id: String,
    host_key: ServerKeyAlg,

    encoder: BinaryPacketEncoder,
    decoder: BinaryPacketDecoder,
    send_seq: u32,
    recv_seq: u32,
}

pub(crate) struct ServerWaitingForKexDhInit {
    client_id: String,
    server_id: String,
    host_key: ServerKeyAlg,

    encoder: BinaryPacketEncoder,
    decoder: BinaryPacketDecoder,
    send_seq: u32,
    recv_seq: u32,

    client_kexinit: KexInit,
    server_kexinit: KexInit,
    client_kexinit_payload: Vec<u8>,
    server_kexinit_payload: Vec<u8>,

    negotiated: NegotiatedTransport,
}

pub(crate) struct ServerWaitingForNewKeys {
    encoder: BinaryPacketEncoder,
    decoder: BinaryPacketDecoder,
    send_seq: u32,
    recv_seq: u32,

    pending_encoder: BinaryPacketEncoder,
    pending_decoder: BinaryPacketDecoder,

    session_id: Vec<u8>,
}

pub(crate) struct ServerReady {
    encoder: BinaryPacketEncoder,
    decoder: BinaryPacketDecoder,
    send_seq: u32,
    recv_seq: u32,
    session_id: Vec<u8>,
}

impl Server {
    pub fn new(host_key: ServerKeyAlg) -> Self {
        Self::WaitingForProtoVersion(ServerWaitingForProtoVersion {
            server_id: format!("SSH-{}-{}", PROTOVERSION, SOFTWAREVERSION),
            host_key,
        })
    }

    pub fn receive_proto_version<R: Read, W: Write>(&mut self, reader: &mut R, writer: &mut W) -> Result<()> {
        let state = std::mem::replace(self, Server::Failed);

        match state {
            Server::WaitingForProtoVersion(state) => {
                *self = Server::WaitingForClientKexInit(state.receive_proto_version(reader, writer)?);
                Ok(())
            }
            other => {
                *self = other;
                Err(Error::msg("Server is not waiting for protocol version"))
            }
        }
    }

    pub fn receive_client_kexinit<R: Read, W: Write>(&mut self, reader: &mut R, writer: &mut W) -> Result<()> {
        let state = std::mem::replace(self, Server::Failed);

        match state {
            Server::WaitingForClientKexInit(state) => {
                *self = Server::WaitingForKexDhInit(state.receive_client_kexinit(reader, writer)?);
                Ok(())
            }
            other => {
                *self = other;
                Err(Error::msg("Server is not waiting for client KEXINIT"))
            }
        }
    }

    pub fn receive_kexdh_init<R: Read, W: Write>(&mut self, reader: &mut R, writer: &mut W) -> Result<()> {
        let state = std::mem::replace(self, Server::Failed);

        match state {
            Server::WaitingForKexDhInit(state) => {
                *self = Server::WaitingForNewKeys(state.receive_kexdh_init(reader, writer)?);
                Ok(())
            }
            other => {
                *self = other;
                Err(Error::msg("Server is not waiting for KEXDH_INIT"))
            }
        }
    }

    pub fn receive_newkeys<R: Read>(&mut self, reader: &mut R) -> Result<()> {
        let state = std::mem::replace(self, Server::Failed);

        match state {
            Server::WaitingForNewKeys(state) => {
                *self = Server::Ready(state.receive_newkeys(reader)?);
                Ok(())
            }
            other => {
                *self = other;
                Err(Error::msg("Server is not waiting for NEWKEYS"))
            }
        }
    }

    pub fn send_packet<W: Write>(&mut self, writer: &mut W, payload: &[u8]) -> Result<()> {
        match self {
            Server::Ready(state) => state.send_packet(writer, payload),
            _ => Err(Error::msg("Server transport is not ready")),
        }
    }

    pub fn read_packet<R: Read>(&mut self, reader: &mut R) -> Result<Vec<u8>> {
        match self {
            Server::Ready(state) => state.read_packet(reader),
            _ => Err(Error::msg("Server transport is not ready")),
        }
    }
}

impl ServerWaitingForProtoVersion {
    fn receive_proto_version<R: Read, W: Write>(
        self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<ServerWaitingForClientKexInit> {
        let client_id = read_identification_string(reader)?;

        writer.write_all(self.server_id.as_bytes())?;
        writer.write_all(b"\r\n")?;
        writer.flush()?;

        Ok(ServerWaitingForClientKexInit {
            client_id,
            server_id: self.server_id,
            host_key: self.host_key,
            encoder: BinaryPacketEncoder::naked(),
            decoder: BinaryPacketDecoder::naked(),
            send_seq: 0,
            recv_seq: 0,
        })
    }
}

impl ServerWaitingForClientKexInit {
    fn receive_client_kexinit<R: Read, W: Write>(
        mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<ServerWaitingForKexDhInit> {
        let client_kexinit_payload = self.decoder.decode_from(reader, self.recv_seq)?;
        let client_kexinit = KexInit::deserialize(&client_kexinit_payload)?;

        let server_kexinit = KexInit::default_server()?;
        let server_kexinit_payload = server_kexinit.serialize()?;

        let packet = self.encoder.build(&server_kexinit_payload, self.send_seq)?;
        writer.write_all(&packet)?;
        writer.flush()?;

        let negotiated = NegotiatedTransport::server_negotiate(
            &client_kexinit,
            &server_kexinit,
        )?;

        Ok(ServerWaitingForKexDhInit {
            client_id: self.client_id,
            server_id: self.server_id,
            host_key: self.host_key,
            encoder: self.encoder,
            decoder: self.decoder,
            send_seq: self.send_seq.wrapping_add(1),
            recv_seq: self.recv_seq.wrapping_add(1),
            client_kexinit,
            server_kexinit,
            client_kexinit_payload,
            server_kexinit_payload,
            negotiated,
        })
    }
}

impl ServerWaitingForKexDhInit {
    fn receive_kexdh_init<R: Read, W: Write>(
        mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<ServerWaitingForNewKeys> {
        let init_payload = self.decoder.decode_from(reader, self.recv_seq)?;
        let init = KexDhInit::deserialize(&init_payload)?;

        let server_dh = ServerDhState::new(&self.negotiated)?;

        let client_public_value = init.e;
        let shared_secret = server_dh.compute_shared_secret(
            &self.negotiated,
            client_public_value.to_biguint(),
        )?;

        let host_key_blob = self.host_key.public_key_blob()?;

        let exchange_hash = self.negotiated.kex_hash(
            &SshString::new(self.client_id.as_bytes())?,
            &SshString::new(self.server_id.as_bytes())?,
            &SshString::new(&self.client_kexinit_payload)?,
            &SshString::new(&self.server_kexinit_payload)?,
            &SshString::new(&host_key_blob)?,
            &SshMpint::new(client_public_value.to_biguint()),
            &SshMpint::new(server_dh.public_value.clone()),
            &SshMpint::new(shared_secret.clone()),
        )?;

        let signature_blob = self.host_key.sign_exchange_hash(&exchange_hash)?;

        let reply = KexDhReply {
            k_s: SshString::new(&host_key_blob)?,
            f: SshMpint::new(server_dh.public_value.clone()),
            signature: SshString::new(&signature_blob)?,
        };

        let reply_payload = reply.serialize()?;
        let packet = self.encoder.build(&reply_payload, self.send_seq)?;
        writer.write_all(&packet)?;

        let newkeys_payload = NewKeys {}.serialize()?;
        let packet = self.encoder.build(&newkeys_payload, self.send_seq.wrapping_add(1))?;
        writer.write_all(&packet)?;
        writer.flush()?;
 
        let session_id = exchange_hash.clone();

        let pending_keys = self.negotiated.derive_keys(
            &shared_secret,
            &exchange_hash,
            &session_id,
            Role::Server,
        )?;

        let (pending_encoder, pending_decoder) = pending_keys.into_server_pair();

        Ok(ServerWaitingForNewKeys {
            encoder: self.encoder,
            decoder: self.decoder,
            send_seq: self.send_seq.wrapping_add(2),
            recv_seq: self.recv_seq.wrapping_add(1),
            pending_encoder,
            pending_decoder,
            session_id,
        })
    }
}

impl ServerWaitingForNewKeys {
    fn receive_newkeys<R: Read>(mut self, reader: &mut R) -> Result<ServerReady> {
        let payload = self.decoder.decode_from(reader, self.recv_seq)?;
        NewKeys::deserialize(&payload)?;

        Ok(ServerReady {
            encoder: self.pending_encoder,
            decoder: self.pending_decoder,
            send_seq: self.send_seq,
            recv_seq: self.recv_seq.wrapping_add(1),
            session_id: self.session_id,
        })
    }
}

impl ServerReady {
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