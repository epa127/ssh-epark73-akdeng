use anyhow::{Error, Result};

use crate::{PROTOVERSION, SOFTWAREVERSION};

pub struct ProtoVersion {
    pub protoversion: String,
    pub softwareversion: String,
    pub comments: Option<String>,
}

impl ProtoVersion {
    pub fn new(protoversion: &str, softwareversion: &str, comments: Option<&str>) -> Result<Self> {
        Self::validate(protoversion, softwareversion, comments)?;

        Ok(Self {
            protoversion: protoversion.to_string(),
            softwareversion: softwareversion.to_string(),
            comments: comments.map(|s| s.to_string()),
        })
    }

    pub fn default() -> Result<Self> {
        Self::new(PROTOVERSION, SOFTWAREVERSION, None)
    }

    pub fn validate(protoversion: &str, softwareversion: &str, comments: Option<&str>) -> Result<()> {
        if protoversion != "2.0" {
            return Err(Error::msg(format!("Unsupported SSH protocol version: {}", protoversion)));
        }

        if softwareversion.is_empty() {
            return Err(Error::msg("Software version cannot be empty"));
        }

        if softwareversion.contains(' ') {
            return Err(Error::msg("Software version cannot contain spaces"));
        }

        if softwareversion.contains('\r') || softwareversion.contains('\n') {
            return Err(Error::msg("Software version cannot contain CR or LF"));
        }

        if let Some(comments) = comments
            && (comments.contains('\r') || comments.contains('\n')) {
                return Err(Error::msg("Comments cannot contain CR or LF"));
            }

        Ok(())
    }

    pub fn identification_string(&self) -> String {
        match &self.comments {
            Some(comments) => {
                format!("SSH-{}-{} {}", self.protoversion, self.softwareversion, comments)
            }
            None => {
                format!("SSH-{}-{}", self.protoversion, self.softwareversion)
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = self.identification_string().into_bytes();
        data.extend_from_slice(b"\r\n");
        data
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::msg("Empty protocol version buffer"));
        }

        let line = std::str::from_utf8(bytes)?;

        let line = line
            .strip_suffix("\r\n")
            .or_else(|| line.strip_suffix('\n'))
            .unwrap_or(line);

        if !line.starts_with("SSH-") {
            return Err(Error::msg("Invalid SSH identification string: missing SSH- prefix"));
        }

        let rest = &line[4..];

        let first_dash = rest
            .find('-')
            .ok_or_else(|| Error::msg("Invalid SSH identification string: missing version separator"))?;

        let protoversion = &rest[..first_dash];
        let rest = &rest[first_dash + 1..];

        let (softwareversion, comments) = match rest.find(' ') {
            Some(space_idx) => {
                let softwareversion = &rest[..space_idx];
                let comments = &rest[space_idx + 1..];

                if comments.is_empty() {
                    (softwareversion, None)
                } else {
                    (softwareversion, Some(comments))
                }
            }
            None => {
                (rest, None)
            }
        };

        Self::new(protoversion, softwareversion, comments)
    }

    pub fn exchange_hash_bytes(&self) -> Vec<u8> {
        self.identification_string().into_bytes()
    }
}