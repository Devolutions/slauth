use crate::webauthn::error::Error;
use serde_derive::*;
use serde_cbor::Value;
use std::io::{Cursor, Read};
use byteorder::{ReadBytesExt, BigEndian};
use bytes::Buf;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RawAttestationObject {
    auth_data: serde_cbor::Value,
    fmt: String,
    att_stmt: AttestationStatement,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AttestationObject {
    pub auth_data: AuthenticatorData,
    pub raw_auth_data: Vec<u8>,
    pub fmt: String,
    pub att_stmt: AttestationStatement,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AttestationStatement {
    pub alg: i64,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<serde_cbor::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecdaa_key_id: Option<serde_cbor::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub attested_credential_data: AttestedCredentialData,
    pub extensions: serde_cbor::Value
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AttestedCredentialData {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    pub credential_public_key: CredentialPublicKey,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CredentialPublicKey {
    pub key_type: i64,
    pub alg: i64,
    pub curve: i64,
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl CredentialPublicKey {
    pub fn from_value(value: serde_cbor::Value) -> Result<Self, Error> {
        let map = match value {
            Value::Map(m) => m,
            _ => { BTreeMap::new() },
        };

        let key_type = map.get(&Value::Integer(1)).map(|val| {
            match val {
                Value::Integer(i) => *i as i64,
                _ => 0i64,
            }
        }).ok_or(Error::Other("Key type missing".to_string()))?;

        let alg = map.get(&Value::Integer(3)).map(|val| {
            match val {
                Value::Integer(i) => *i as i64,
                _ => 0i64,
            }
        }).ok_or(Error::Other("algorithm missing".to_string()))?;

        let curve = map.get(&Value::Integer(-1)).map(|val| {
            match val {
                Value::Integer(i) => *i as i64,
                _ => 0i64,
            }
        }).ok_or(Error::Other("curve missing".to_string()))?;

        let x = map.get(&Value::Integer(-2)).map(|val| {
            match val {
                Value::Bytes(i) => {
                    let mut array = [0u8; 32];
                    array.copy_from_slice(&i[0..32]);
                    array
                },
                _ => [0u8; 32],
            }
        }).ok_or(Error::Other("x coord missing".to_string()))?;

        let y = map.get(&Value::Integer(-3)).map(|val| {
            match val {
                Value::Bytes(i) => {
                    let mut array = [0u8; 32];
                    array.copy_from_slice(&i[0..32]);
                    array
                },
                _ => [0u8; 32],
            }
        }).ok_or(Error::Other("x coord missing".to_string()))?;

        Ok(CredentialPublicKey {
            key_type,
            alg,
            curve,
            x,
            y,
        })
    }
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

        let remaining_value = serde_cbor::from_slice::<serde_cbor::Value>(remaining.as_slice()).map_err(|e| Error::CborError(e))?;

        let credential_public_key = CredentialPublicKey::from_value(remaining_value)?;

        let raw_auth_data = cursor.into_inner();

        Ok(AttestationObject {
            auth_data: AuthenticatorData {
                rp_id_hash,
                flags,
                sign_count,
                attested_credential_data: AttestedCredentialData {
                    aaguid,
                    credential_id,
                    credential_public_key,
                },
                extensions: Value::Null
            },
            raw_auth_data,
            fmt: value.fmt,
            att_stmt: value.att_stmt
        })
    }
}