use anyhow::{Result,Error};

pub mod kex;
pub mod messages;
pub mod crypto;
pub mod data_primitives;

pub const PROTOVERSION: &str = "2.0";
pub const SOFTWAREVERSION: &str = "mssh_1.0";

pub fn check_and_inc(vec: &[u8], i: &mut usize, inc: &usize) -> Result<()> {
    if vec.len() < i.clone() + inc.clone() {
        return Err(Error::msg(format!("Invalid read: Not enough bytes")));
    }

    *i += *inc;
    Ok(())
}

// From russh
pub const DISCONNECT: u8 = 1;
#[allow(dead_code)]
pub const IGNORE: u8 = 2;
#[allow(dead_code)]
pub const UNIMPLEMENTED: u8 = 3;
#[allow(dead_code)]
pub const DEBUG: u8 = 4;

pub const SERVICE_REQUEST: u8 = 5;
pub const SERVICE_ACCEPT: u8 = 6;
pub const EXT_INFO: u8 = 7;
pub const KEXINIT: u8 = 20;
pub const NEWKEYS: u8 = 21;

// http://tools.ietf.org/html/rfc5656#section-7.1
pub const KEX_ECDH_INIT: u8 = 30;
pub const KEX_ECDH_REPLY: u8 = 31;

pub const KEX_DH_GEX_REQUEST: u8 = 34;
pub const KEX_DH_GEX_GROUP: u8 = 31;
pub const KEX_DH_GEX_INIT: u8 = 32;
pub const KEX_DH_GEX_REPLY: u8 = 33;

// PQ/T Hybrid Key Exchange with ML-KEM
// https://datatracker.ietf.org/doc/draft-ietf-sshm-mlkem-hybrid-kex/
pub const KEX_HYBRID_INIT: u8 = 30;
#[allow(dead_code)]
pub const KEX_HYBRID_REPLY: u8 = 31;

// https://tools.ietf.org/html/rfc4250#section-4.1.2
pub const USERAUTH_REQUEST: u8 = 50;
pub const USERAUTH_FAILURE: u8 = 51;
pub const USERAUTH_SUCCESS: u8 = 52;
pub const USERAUTH_BANNER: u8 = 53;

pub const USERAUTH_INFO_RESPONSE: u8 = 61;

// some numbers have same meaning
pub const USERAUTH_INFO_REQUEST_OR_USERAUTH_PK_OK: u8 = 60;

// https://tools.ietf.org/html/rfc4254#section-9
pub const GLOBAL_REQUEST: u8 = 80;
pub const REQUEST_SUCCESS: u8 = 81;
pub const REQUEST_FAILURE: u8 = 82;

pub const CHANNEL_OPEN: u8 = 90;
pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const CHANNEL_OPEN_FAILURE: u8 = 92;
pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const CHANNEL_DATA: u8 = 94;
pub const CHANNEL_EXTENDED_DATA: u8 = 95;
pub const CHANNEL_EOF: u8 = 96;
pub const CHANNEL_CLOSE: u8 = 97;
pub const CHANNEL_REQUEST: u8 = 98;
pub const CHANNEL_SUCCESS: u8 = 99;
pub const CHANNEL_FAILURE: u8 = 100;

#[allow(dead_code)]
pub const SSH_OPEN_CONNECT_FAILED: u8 = 2;
pub const SSH_OPEN_UNKNOWN_CHANNEL_TYPE: u8 = 3;
#[allow(dead_code)]
pub const SSH_OPEN_RESOURCE_SHORTAGE: u8 = 4;

pub const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT   : u32 =  1;
pub const SSH_DISCONNECT_PROTOCOL_ERROR                : u32 =  2;
pub const SSH_DISCONNECT_KEY_EXCHANGE_FAILED           : u32 =  3;
pub const SSH_DISCONNECT_RESERVED                      : u32 =  4;
pub const SSH_DISCONNECT_MAC_ERROR                     : u32 =  5;
pub const SSH_DISCONNECT_COMPRESSION_ERROR             : u32 =  6;
pub const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE         : u32 =  7;
pub const SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED: u32 =  8;
pub const SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE       : u32 =  9;
pub const SSH_DISCONNECT_CONNECTION_LOST               : u32 = 10;
pub const SSH_DISCONNECT_BY_APPLICATION                : u32 = 11;
pub const SSH_DISCONNECT_TOO_MANY_CONNECTIONS          : u32 = 12;
pub const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER        : u32 = 13;
pub const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: u32 = 14;
pub const SSH_DISCONNECT_ILLEGAL_USER_NAME             : u32 = 15;