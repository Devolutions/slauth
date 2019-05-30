#![allow(dead_code)]

pub const MAX_RESPONSE_LEN_SHORT: usize = 256;
pub const MAX_RESPONSE_LEN_EXTENDED: usize = 65536;

// From :Common U2F raw message format header - Review Draft
// 2014-10-08

// ASN1 constants

pub const ASN1_SEQ_TYPE: u8 = 0x30;
pub const ASN1_DEFINITE_SHORT_MASK: u8 = 0x80;
pub const ASN1_DEFINITE_LONG_FOLLOWING_MASK: u8 = 0x7f;
pub const ASN1_MAX_FOLLOWING_LEN_BYTES: usize = 126;

// General constants

pub const U2F_EC_KEY_SIZE: usize = 32; // EC key size in bytes
pub const U2F_EC_POINT_SIZE: usize = ((U2F_EC_KEY_SIZE * 2) + 1); // Size of EC point
pub const U2F_MAX_KH_SIZE: usize = 128; // Max size of key handle
pub const U2F_MAX_ATT_CERT_SIZE: usize = 2048; // Max size of attestation certificate
pub const U2F_MAX_EC_SIG_SIZE: usize = 72; // Max size of DER coded EC signature
pub const U2F_CTR_SIZE: usize = 4; // Size of counter field
pub const U2F_APPID_SIZE: usize = 32; // Size of application id
pub const U2F_CHAL_SIZE: usize = 32; // Size of challenge

#[inline]
pub const fn enc_size(x: u16) -> u16 {(x + 7) & 0xfff8}

// EC (uncompressed) point

pub const U2F_POINT_UNCOMPRESSED: u8 = 0x04; // Uncompressed point format

pub struct U2fEcPoint {
    point_format: u8,
    x: [u8; U2F_EC_KEY_SIZE],
    y: [u8; U2F_EC_KEY_SIZE],
}

// U2F native commands

pub const U2F_REGISTER: u8 = 0x01; // Registration command
pub const U2F_AUTHENTICATE: u8 = 0x02; // Authenticate/sign command
pub const U2F_VERSION: u8 = 0x03; // Read version string command

pub const U2F_VENDOR_FIRST: u8 = 0x40; // First vendor defined command
pub const U2F_VENDOR_LAST: u8 = 0xbf; // Last vendor defined command

// U2F_CMD_REGISTER command defines

pub const U2F_REGISTER_ID: u8 = 0x05; // Version 2 registration identifier
pub const U2F_REGISTER_HASH_ID: u8 = 0x00; // Version 2 hash identintifier

pub struct U2fRegusterReq {
    chal: [u8; U2F_CHAL_SIZE], // Challenge
    app_id: [u8; U2F_APPID_SIZE], // Application id
}

pub struct U2fRegusterRsp {
    register_id: u8, // Registration identifier (U2F_REGISTER_ID_V2)
    pubkey: U2fEcPoint, // Generated public key
    key_handle_len: u8, // Length of key handle
    key_handle_cert_sig: [u8;
        U2F_MAX_KH_SIZE +               // Key handle
        U2F_MAX_ATT_CERT_SIZE +         // Attestation certificate
        U2F_MAX_EC_SIG_SIZE],           // Registration signature
}

// U2F_CMD_AUTHENTICATE command defines

// Authentication control byte

pub const U2F_AUTH_DONT_ENFORCE: u8 = 0x08;
pub const U2F_AUTH_ENFORCE: u8 = 0x03; // Enforce user presence and sign
pub const U2F_AUTH_CHECK_ONLY: u8 = 0x07; // Check only
pub const U2F_AUTH_FLAG_TUP: u8 = 0x01; // Test of user presence set

pub struct U2fAuthenticateReq {
    chal: [u8; U2F_CHAL_SIZE], // Challenge
    app_id: [u8; U2F_APPID_SIZE], // Application id
    key_handle_len: u8, // Length of key handle
    key_handle: [u8; U2F_MAX_KH_SIZE], // Key handle
}

pub struct U2fAuthenticateRsp {
    flags: u8,
    ctr: [u8; U2F_CTR_SIZE],
    sig: [u8; U2F_MAX_EC_SIG_SIZE],
}

// Command status responses

pub const U2F_SW_NO_ERROR: u16 = 0x9000; // SW_NO_ERROR
pub const U2F_SW_WRONG_DATA: u16 = 0x6A80; // SW_WRONG_DATA
pub const U2F_SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985; // SW_CONDITIONS_NOT_SATISFIED
pub const U2F_SW_COMMAND_NOT_ALLOWED: u16 = 0x6986; // SW_COMMAND_NOT_ALLOWED
pub const U2F_SW_INS_NOT_SUPPORTED: u16 = 0x6D00; // SW_INS_NOT_SUPPORTED
