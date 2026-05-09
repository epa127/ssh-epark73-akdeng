use std::{hash::Hash, str::FromStr};

use anyhow::{Error, Result};

use rand::{TryRngCore, rng, rngs::{OsRng, ThreadRng}};

use crate::{DISCONNECT, KEXINIT, NEWKEYS, SSH_DISCONNECT_AUTH_CANCELLED_BY_USER, SSH_DISCONNECT_BY_APPLICATION, SSH_DISCONNECT_COMPRESSION_ERROR, SSH_DISCONNECT_CONNECTION_LOST, SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT, SSH_DISCONNECT_ILLEGAL_USER_NAME, SSH_DISCONNECT_MAC_ERROR, SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, SSH_DISCONNECT_PROTOCOL_ERROR, SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, SSH_DISCONNECT_RESERVED, SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, SSH_DISCONNECT_TOO_MANY_CONNECTIONS, check_and_inc, data_primitives::{SshBool, SshNameList, SshString, SshUint32}};

pub trait Msg: Sized {
    fn get_msg_number() -> u8;
    fn serialize(&self) -> Result<Vec<u8>>;
    fn deserialize(vec: &[u8]) -> Result<Self>;
}

pub struct KexInit {
    cookie: [u8; 16],
    kex: SshNameList,
    sh_key: SshNameList,
    enc_c2s: SshNameList,
    enc_s2c: SshNameList,
    mac_c2s: SshNameList,
    mac_s2c: SshNameList,
    comp_c2s: SshNameList,
    comp_s2c: SshNameList,
    lang_c2s: SshNameList,
    lang_s2c: SshNameList,
    kex_follow: SshBool,
}

impl KexInit {
    fn bake_cookie() -> Result<[u8; 16]> {
        let mut cookie = [0u8; 16];

        let mut rng = OsRng;
        rng.try_fill_bytes(&mut cookie)?;
        Ok(cookie)
    }
}

impl Msg for KexInit {
    fn get_msg_number() -> u8 {
        KEXINIT
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut data: Vec<u8> = Vec::new();
        data.push(Self::get_msg_number());
        
        data.extend_from_slice(&self.cookie);
        data.extend_from_slice(&self.kex.to_bytes()?);
        data.extend_from_slice(&self.sh_key.to_bytes()?);
        data.extend_from_slice(&self.enc_c2s.to_bytes()?);
        data.extend_from_slice(&self.enc_s2c.to_bytes()?);
        data.extend_from_slice(&self.mac_c2s.to_bytes()?);
        data.extend_from_slice(&self.mac_s2c.to_bytes()?);
        data.extend_from_slice(&self.comp_c2s.to_bytes()?);
        data.extend_from_slice(&self.comp_s2c.to_bytes()?);
        data.extend_from_slice(&self.lang_c2s.to_bytes()?);
        data.extend_from_slice(&self.lang_s2c.to_bytes()?);
        data.extend_from_slice(&self.kex_follow.to_bytes());

        let zero = SshUint32::new(0);
        data.extend_from_slice(&zero.to_be_bytes());

        Ok(data)
    }

    fn deserialize(vec: &[u8]) -> Result<Self> {
        if vec.is_empty() {
            return Err(Error::msg("Empty buffer!".to_string()));
        }

        let mut i: usize = 0;
        if vec[i] != Self::get_msg_number() {
            return Err(Error::msg(format!("Unexpected message: expected {}, received {}", Self::get_msg_number(), vec[i])));
        }
        check_and_inc(vec, &mut i, &17)?;

        let cookie: [u8; 16] = vec[1..17].try_into()?;
        
        let (kex, inc) = SshNameList::from_be_bytes(&vec[i..])?;
        check_and_inc(vec, &mut i, &inc)?;

        let (sh_key, inc) = SshNameList::from_be_bytes(&vec[i..])?;
        check_and_inc(vec, &mut i, &inc)?;

        let (enc_c2s, inc) = SshNameList::from_be_bytes(&vec[i..])?;
        check_and_inc(vec, &mut i, &inc)?;

        let (enc_s2c, inc) = SshNameList::from_be_bytes(&vec[i..])?;
        check_and_inc(vec, &mut i, &inc)?;

        let (mac_c2s, inc) = SshNameList::from_be_bytes(&vec[i..])?;
        check_and_inc(vec, &mut i, &inc)?;

        let (mac_s2c, inc) = SshNameList::from_be_bytes(&vec[i..])?;
        check_and_inc(vec, &mut i, &inc)?;

        let (comp_c2s, inc) = SshNameList::from_be_bytes(&vec[i..])?;
        check_and_inc(vec, &mut i, &inc)?;

        let (comp_s2c, inc) = SshNameList::from_be_bytes(&vec[i..])?;
        check_and_inc(vec, &mut i, &inc)?;

        let (lang_c2s, inc) = SshNameList::from_be_bytes(&vec[i..])?;
        check_and_inc(vec, &mut i, &inc)?;

        let (lang_s2c, inc) = SshNameList::from_be_bytes(&vec[i..])?;
        check_and_inc(vec, &mut i, &inc)?;

        let kex_follow = SshBool::from_bytes(&[vec[i]])?;
        check_and_inc(vec, &mut i, &1)?;

        let zero = SshUint32::from_be_bytes(&vec[i..])?;
        i += 4;

        if zero.int != 0 {
            return Err(Error::msg(format!("Invalid read: expected zero value, received {}", zero.int)));
        }

        if vec.len() != i {
            return Err(Error::msg("Invalid read: expected no more bytes".to_string()));
        }

        Ok(KexInit { kex, cookie, sh_key, enc_c2s, enc_s2c, mac_c2s, mac_s2c, comp_c2s, comp_s2c, lang_c2s, lang_s2c, kex_follow })
    }
}

pub struct NewKeys {}

impl Msg for NewKeys {
    fn get_msg_number() -> u8 {
        NEWKEYS
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(vec![Self::get_msg_number(); 1])
    }

    fn deserialize(vec: &[u8]) -> Result<Self> {
        if vec.is_empty() {
            return Err(Error::msg(format!("Empty buffer!")));
        }

        let mut i: usize = 0;
        if vec[i] != Self::get_msg_number() {
            return Err(Error::msg(format!("Unexpected message: expected {}, received {}", Self::get_msg_number(), vec[i])));
        }
        check_and_inc(vec, &mut i, &1)?;

        if vec.len() != i {
            return Err(Error::msg("Invalid read: expected no more bytes".to_string()));
        }

        Ok(Self {  })
    }
}

pub struct Disconnect {
    reason_code: DisconnectReasonCodes,
    description: String,
    language_tag: String
}

impl Msg for Disconnect {
    fn get_msg_number() -> u8 {
        DISCONNECT
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut data: Vec<u8> = Vec::new();
        data.push(Self::get_msg_number());
        data.extend_from_slice(&SshUint32::new(self.reason_code.to_code()).to_be_bytes());
        data.extend_from_slice(&SshString::from_str(self.description.as_str())?.to_be_bytes());
        data.extend_from_slice(&SshString::from_str(self.language_tag.as_str())?.to_be_bytes());

        Ok(data)
    }

    fn deserialize(vec: &[u8]) -> Result<Self> {
        if vec.is_empty() {
            return Err(Error::msg("Empty buffer!".to_string()));
        }

        let mut i: usize = 0;
        if vec[i] != Self::get_msg_number() {
            return Err(Error::msg(format!("Unexpected message: expected {}, received {}", Self::get_msg_number(), vec[i])));
        }
        check_and_inc(vec, &mut i, &1)?;

        let reason_code_bytes = SshUint32::from_be_bytes(&vec[i..])?;
        let reason_code = DisconnectReasonCodes::from_code(reason_code_bytes.int)?;
        check_and_inc(vec, &mut i, &4)?;

        let (description_bytes, inc) = SshString::from_be_bytes(&vec[i..])?;
        let description = String::from_utf8(description_bytes.bytes)?;
        check_and_inc(vec, &mut i, &inc)?;

        let (language_tag_bytes, inc) = SshString::from_be_bytes(&vec[i..])?;
        let language_tag = String::from_utf8(language_tag_bytes.bytes)?;
        check_and_inc(vec, &mut i, &inc)?;

        if vec.len() != i {
            return Err(Error::msg("Invalid read: expected no more bytes".to_string()));
        }

        Ok(Self { reason_code, description, language_tag } )
    }
}

pub enum DisconnectReasonCodes {
    HostNotAllowedToConnect,
    ProtocolError,
    Reserved,
    MacError,
    CompressionError,
    ServiceNotAvailable,
    ProtocolVersionNotSupported,
    ConnectionLost,
    ByApplication,
    TooManyConnections,
    AuthCancelledByUser,
    NoMoreAuthMethodsAvailable,
    IllegalUserName
}

impl DisconnectReasonCodes {
    fn to_code(&self) -> u32 {
        match self {
            DisconnectReasonCodes::HostNotAllowedToConnect => SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT,
            DisconnectReasonCodes::ProtocolError => SSH_DISCONNECT_PROTOCOL_ERROR,
            DisconnectReasonCodes::Reserved => SSH_DISCONNECT_RESERVED,
            DisconnectReasonCodes::MacError => SSH_DISCONNECT_MAC_ERROR,
            DisconnectReasonCodes::CompressionError => SSH_DISCONNECT_COMPRESSION_ERROR,
            DisconnectReasonCodes::ServiceNotAvailable => SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
            DisconnectReasonCodes::ProtocolVersionNotSupported => SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
            DisconnectReasonCodes::ConnectionLost => SSH_DISCONNECT_CONNECTION_LOST,
            DisconnectReasonCodes::ByApplication => SSH_DISCONNECT_BY_APPLICATION,
            DisconnectReasonCodes::TooManyConnections => SSH_DISCONNECT_TOO_MANY_CONNECTIONS,
            DisconnectReasonCodes::AuthCancelledByUser => SSH_DISCONNECT_AUTH_CANCELLED_BY_USER,
            DisconnectReasonCodes::NoMoreAuthMethodsAvailable => SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
            DisconnectReasonCodes::IllegalUserName => SSH_DISCONNECT_ILLEGAL_USER_NAME,
        }
    }
    fn from_code(code: u32) -> Result<Self> {
        Ok(match code {
            SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT => DisconnectReasonCodes::HostNotAllowedToConnect,
            SSH_DISCONNECT_PROTOCOL_ERROR => DisconnectReasonCodes::ProtocolError,
            SSH_DISCONNECT_RESERVED => DisconnectReasonCodes::Reserved,
            SSH_DISCONNECT_MAC_ERROR => DisconnectReasonCodes::MacError,
            SSH_DISCONNECT_COMPRESSION_ERROR => DisconnectReasonCodes::CompressionError,
            SSH_DISCONNECT_SERVICE_NOT_AVAILABLE => DisconnectReasonCodes::ServiceNotAvailable,
            SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED => DisconnectReasonCodes::ProtocolVersionNotSupported,
            SSH_DISCONNECT_CONNECTION_LOST => DisconnectReasonCodes::ConnectionLost,
            SSH_DISCONNECT_BY_APPLICATION => DisconnectReasonCodes::ByApplication,
            SSH_DISCONNECT_TOO_MANY_CONNECTIONS => DisconnectReasonCodes::TooManyConnections,
            SSH_DISCONNECT_AUTH_CANCELLED_BY_USER => DisconnectReasonCodes::AuthCancelledByUser,
            SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE => DisconnectReasonCodes::NoMoreAuthMethodsAvailable,
            SSH_DISCONNECT_ILLEGAL_USER_NAME => DisconnectReasonCodes::IllegalUserName,
            _ => return Err(Error::msg("Invalid disconnect reason code")),
        })
    }
}

struct BinaryPacket {
    packet_length: u32,
    padding_length: u8,
    payload: Vec<u8>,
    padding: Vec<u8>,
    mac_or_tag: Option<Vec<u8>>,
    seq_num: u32
}

struct BinaryPacketBuilder {
    
}

impl BinaryPacketBuilder {
    fn new() -> Self {
        todo!()
    }
    fn build(self) -> BinaryPacket {
        todo!()
    }
}
