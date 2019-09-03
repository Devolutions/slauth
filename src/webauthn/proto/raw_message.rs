use crate::webauthn::error::Error;
use serde_derive::*;
use serde_cbor::Value;
use std::io::{Cursor, Read};
use byteorder::{ReadBytesExt, BigEndian};
use bytes::Buf;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RawAttestationObject {
    auth_data: serde_cbor::Value,
    fmt: String,
    att_stmt: serde_cbor::Value,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AttestationObject {
    pub auth_data: AuthenticatorData,
    fmt: String,
    att_stmt: serde_cbor::Value,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorData {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    attested_credential_data: AttestedCredentialData,
    extensions: serde_cbor::Value
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AttestedCredentialData {
    aaguid: [u8; 16],
    credential_id: Vec<u8>,
    credential_public_key: serde_cbor::Value,
}

pub trait Message {
    fn from_base64(string: &String) -> Result<Self, Error> where Self: Sized;
}

impl Message for AttestationObject {
    fn from_base64(string: &String) -> Result<Self, Error> where Self: Sized {
        let raw_values = base64::decode(string)?;
        let value = serde_cbor::from_slice::<RawAttestationObject>(raw_values.as_slice()).map_err(|e| Error::CborError(e))?;

        let auth_data = match value.auth_data {
            Value::Bytes(vec) => Ok(vec),
            _ => Err(Error::Other("Cannot proceed without auth data".to_string()))
        }?;

        let mut cursor = Cursor::new(auth_data);

        let mut rp_id_hash = [0u8; 32];
        cursor.read_exact(&mut rp_id_hash)?;

        let flags = cursor.read_u8()?;

        let sign_count = cursor.read_u32::<BigEndian>()?;

        let mut aaguid = [0u8; 16];
        cursor.read_exact(&mut aaguid)?;

        let length = cursor.read_u16::<BigEndian>()?;

        let mut credential_id = vec![0u8; length as usize];
        cursor.read_exact(&mut credential_id[..])?;

        let mut remaining = vec![0u8; cursor.remaining()];
        cursor.read_exact(&mut remaining[..])?;

        let _final_value = dbg!(serde_cbor::from_slice::<serde_cbor::Value>(remaining.as_slice()).map_err(|e| Error::CborError(e)))?;

        Ok(AttestationObject{
            auth_data: AuthenticatorData {
                rp_id_hash,
                flags,
                sign_count,
                attested_credential_data: AttestedCredentialData {
                    aaguid,
                    credential_id,
                    credential_public_key: Value::Null
                },
                extensions: Value::Null
            },
            fmt: value.fmt,
            att_stmt: value.att_stmt
        })
    }
}