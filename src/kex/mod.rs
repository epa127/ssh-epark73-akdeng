use crate::{KEX_ECDH_INIT, KEX_ECDH_REPLY, check_and_inc, messages::Msg};
use crate::data_primitives::SshString;
use crate::data_primitives::SshMpint;
use anyhow::{Error, Result};
pub mod dh;

pub struct KexDhInit {
    pub(crate) e: SshMpint
}

impl Msg for KexDhInit {
    fn get_msg_number() -> u8 {
        KEX_ECDH_INIT
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut data: Vec<u8> = Vec::new();
        data.push(Self::get_msg_number());
        data.extend_from_slice(&self.e.to_be_bytes()?);

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

        let (e, inc) = SshMpint::from_be_bytes(&vec[i..])?;
        check_and_inc(vec, &mut i, &inc)?;

        if vec.len() != i {
            return Err(Error::msg("Invalid read: expected no more bytes".to_string()));
        }

        Ok(KexDhInit { e })
    }
}

pub struct KexDhReply {
    pub(crate) k_s: SshString,
    pub(crate) f: SshMpint,
    pub(crate) signature: SshString
}

impl Msg for KexDhReply {
    fn get_msg_number() -> u8 {
        KEX_ECDH_REPLY
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut data: Vec<u8> = Vec::new();
        data.push(Self::get_msg_number());
        data.extend_from_slice(&self.k_s.to_be_bytes());
        data.extend_from_slice(&self.f.to_be_bytes()?);
        data.extend_from_slice(&self.signature.to_be_bytes());

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

        let (k_s, inc) = SshString::from_be_bytes(&vec[i..])?;
        check_and_inc(vec, &mut i, &inc)?;

        let (f, inc) = SshMpint::from_be_bytes(&vec[i..])?;
        check_and_inc(vec, &mut i, &inc)?;

        let (signature, inc) = SshString::from_be_bytes(&vec[i..])?;
        check_and_inc(vec, &mut i, &inc)?;

        if vec.len() != i {
            return Err(Error::msg("Invalid read: expected no more bytes".to_string()));
        }

        Ok(Self { k_s, f, signature })
    }
}