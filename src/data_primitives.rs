use std::str::{FromStr, from_utf8};

use anyhow::{Result,Error};
use num_bigint::{BigInt, BigUint};

pub(crate) struct SshBool {
    pub bool: bool
}

impl SshBool {
    pub fn new(bool: bool) -> Self {
        Self { bool }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::msg("Buffer is too small (< 1)".to_string()));
        }

        Ok(Self { bool: bytes[0] != 0 })
    }

    pub fn to_bytes(&self) -> [u8; 1] {
        if self.bool { [1u8] } else { [0u8] }
    }
}

pub(crate) struct SshUint32 {
    pub int: u32
}

impl SshUint32 {
    pub fn new(int: u32) -> Self {
        Self { int }
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(Error::msg("Buffer is too small (< 4)".to_string()));
        }

        Ok(Self { int: u32::from_be_bytes(bytes[0..4].try_into()?) })
    }

    pub fn to_be_bytes(&self) -> [u8; 4] {
        self.int.to_be_bytes()
    }
}

pub(crate)struct SshUint64 {
    pub int: u64
}

impl SshUint64 {
    pub fn new(int: u64) -> Self {
        Self { int }
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(Error::msg("Buffer is too small (< 8)".to_string()));
        }

        Ok(Self { int: u64::from_be_bytes(bytes[0..4].try_into()?) })
    }

    pub fn to_be_bytes(&self) -> [u8; 8] {
        self.int.to_be_bytes()
    }
}

// Only compatible with nonnegative values
pub(crate)struct SshMpint {
    int: BigUint
}

impl SshMpint {
    pub fn new(int: BigUint) -> Self {
        Self { int }
    }
    
    pub fn to_be_bytes(&self) -> Result<Vec<u8>> {
        if self.int == BigUint::ZERO {
            return Ok(vec![0u8; 4]);
        }
        
        let mut int_bytes = self.int.to_bytes_be();

        if int_bytes[0] & 0x80 != 0 {
            int_bytes.insert(0, 0u8);
        }

        let mut mpint = u32::to_be_bytes(int_bytes.len().try_into()?).to_vec();
        mpint.extend_from_slice(&int_bytes);
        
        Ok(mpint)
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < 4 {
            return Err(Error::msg("Buffer is too small (< 4)".to_string()));
        }

        // Number of bytes following length
        let len = u32::from_be_bytes(bytes[0..4].try_into()?) as usize;

        if len == 0 {
            return Ok(((Self::new(BigUint::ZERO)), 4));
        }
        
        if bytes.len() < (len + 4) {
            return Err(Error::msg(format!("Buffer is too short ({} bytes, expected at least {} bytes)", bytes.len(), len + 4)));
        }

        if bytes[4] & 0x80 != 0 {
            return Err(Error::msg(format!("Expected positive value, received MSB of {:X?}", bytes[4])));
        }
        
        Ok((Self::new(BigUint::from_bytes_be(&bytes[4..4 + len])), 4 + len))
    }
}

pub(crate) struct SshString {
    pub(crate) bytes: Vec<u8>
}

impl SshString {
    pub fn new(str: &[u8]) -> Result<Self> {
        if str.len() > u32::MAX as usize {
            return Err(Error::msg(format!("String too large: Length cannot be represented with 32 bits (str length of {})", str.len())));
        }
        Ok(SshString { 
            bytes: str.to_vec() 
        })
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < 4 {
            return Err(Error::msg("Buffer is too small (< 4)".to_string()));
        }

        // Number of bytes following length
        let len = u32::from_be_bytes(bytes[0..4].try_into()?) as usize;

        if len == 0 {
            return Ok((Self::new(&[])?, 4));
        }
        
        if bytes.len() < (len + 4) {
            return Err(Error::msg(format!("Buffer is too short ({} bytes, expected at least {} bytes)", bytes.len(), len + 4)));
        }


        Ok((SshString::new(&bytes[4..4+len])?, 4 + len))
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&(self.bytes.len() as u32).to_be_bytes());
        data.extend_from_slice(&self.bytes);
        data
    }

    pub fn payload_len(&self) -> u32 {
        self.bytes.len() as u32
    }

    pub fn encoded_len(&self) -> u32 {
        self.bytes.len() as u32 + 4
    }
}

impl FromStr for SshString {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        Self::new(s.as_bytes())
    }
}
pub(crate) struct SshNameList {
    pub name_list: Vec<String>
}

impl SshNameList {
    pub fn new() -> Self {
        SshNameList { name_list: Vec::new() }
    }

    fn validate_list(vec: &Vec<String>) -> Result<()> {
        if vec.len() > u32::MAX as usize {
            return Err(Error::msg(format!("Vec too large: Length cannot be represented with 32 bits (vec length of {})", vec.len())));
        }
        for str in vec {
            if str.contains(',') || str.contains('\0') {
                return Err(Error::msg(format!("Invalid name in name list: values may not contain commas (element: {})", str)));
            }
        }
        Ok(())
    }

    pub fn from_vec(vec: Vec<String>) -> Result<Self> {
        SshNameList::validate_list(&vec)?;

        Ok(SshNameList {
            name_list: vec
        })
    }

    // Reads the name-list at the front of a given buffer, returns an SshNameList object with number of bytes read.
    pub fn from_be_bytes(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < 4 {
            return Err(Error::msg("Buffer is too small (< 4)".to_string()));
        }

        // Number of bytes following length
        let len = u32::from_be_bytes(bytes[0..4].try_into()?) as usize;

        if len == 0 {
            return Ok((Self::new(), 4));
        }
        
        if bytes.len() < (len + 4) {
            return Err(Error::msg(format!("Buffer is too short ({} bytes, expected at least {} bytes)", bytes.len(), len + 4)));
        }
        
        let name_str = std::str::from_utf8(&bytes[4..4 + len])?;

        let mut name_list: Vec<String> = Vec::new();
        for name in name_str.split(",") {
            if name.is_empty() {
                return Err(Error::msg("Invalid formatting of name-list: received empty name".to_string()));
            }
            name_list.push(name.to_string());
        }
        
        Ok((SshNameList { name_list }, len + 4))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        SshNameList::validate_list(&self.name_list)?;

        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&(self.name_list.len() as u32).to_be_bytes());

        for (i, str) in self.name_list.iter().enumerate() {
            bytes.extend_from_slice(str.as_bytes());
            if i < self.name_list.len() - 1 {
                bytes.extend_from_slice(b",");
            }
        }
        Ok(bytes)
    }
}