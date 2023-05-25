use crate::webauthn::{
    error::Error,
    proto::{
        constants::{
            ECDSA_Y_PREFIX_NEGATIVE, ECDSA_Y_PREFIX_POSITIVE, ECDSA_Y_PREFIX_UNCOMPRESSED, WEBAUTHN_FORMAT_ANDROID_KEY,
            WEBAUTHN_FORMAT_ANDROID_SAFETYNET, WEBAUTHN_FORMAT_FIDO_U2F, WEBAUTHN_FORMAT_NONE, WEBAUTHN_FORMAT_PACKED, WEBAUTHN_FORMAT_TPM,
            WEBAUTH_PUBLIC_KEY_TYPE_EC2, WEBAUTH_PUBLIC_KEY_TYPE_RSA,
        },
        tpm::TPM,
    },
};
use byteorder::{BigEndian, ReadBytesExt};
use bytes::Buf;
use serde_cbor::Value;
use serde_derive::*;
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    str::FromStr,
};

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
    pub raw_auth_data: Vec<u8>,
    pub fmt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub att_stmt: Option<AttestationStatement>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Packed {
    pub alg: i64,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<serde_cbor::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecdaa_key_id: Option<serde_cbor::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FidoU2F {
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<serde_cbor::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AndroidKey {
    pub alg: i64,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<serde_cbor::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AndroidSafetynet {
    pub ver: String,
    #[serde(with = "serde_bytes")]
    pub response: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged, rename_all = "camelCase")]
pub enum AttestationStatement {
    Packed(Packed),
    TPM(TPM),
    FidoU2F(FidoU2F),
    AndroidKey(AndroidKey),
    AndroidSafetynet(AndroidSafetynet),
    None,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub attested_credential_data: Option<AttestedCredentialData>,
    pub extensions: serde_cbor::Value,
}

impl AuthenticatorData {
    pub fn from_vec(data: Vec<u8>) -> Result<(Self, Vec<u8>), Error> {
        let mut cursor = Cursor::new(data);

        let mut rp_id_hash = [0u8; 32];
        cursor.read_exact(&mut rp_id_hash)?;

        let flags = cursor.read_u8()?;

        let sign_count = cursor.read_u32::<BigEndian>()?;

        let attested_credential_data = if cursor.remaining() > 16 {
            let mut aaguid = [0u8; 16];
            cursor.read_exact(&mut aaguid)?;

            let length = cursor.read_u16::<BigEndian>()?;

            let mut credential_id = vec![0u8; length as usize];
            cursor.read_exact(&mut credential_id[..])?;

            let mut remaining = vec![0u8; cursor.remaining()];
            cursor.read_exact(&mut remaining[..])?;

            let remaining_value = serde_cbor::from_slice::<serde_cbor::Value>(remaining.as_slice()).map_err(Error::CborError)?;

            let credential_public_key = CredentialPublicKey::from_value(remaining_value)?;

            Some(AttestedCredentialData {
                aaguid,
                credential_id,
                credential_public_key,
            })
        } else {
            None
        };

        Ok((
            AuthenticatorData {
                rp_id_hash,
                flags,
                sign_count,
                attested_credential_data,
                extensions: Value::Null,
            },
            cursor.into_inner(),
        ))
    }
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
    pub key_info: CoseKeyInfo,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Rsa {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EC2 {
    pub curve: i64,
    pub coords: Coordinates,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum CoseKeyInfo {
    EC2(EC2),
    RSA(Rsa),
}

impl CredentialPublicKey {
    pub fn from_value(value: serde_cbor::Value) -> Result<Self, Error> {
        let map = match value {
            Value::Map(m) => m,
            _ => BTreeMap::new(),
        };

        let key_type = map
            .get(&Value::Integer(1))
            .map(|val| match val {
                Value::Integer(i) => *i as i64,
                _ => 0i64,
            })
            .ok_or_else(|| Error::Other("Key type missing".to_string()))?;

        let alg = map
            .get(&Value::Integer(3))
            .map(|val| match val {
                Value::Integer(i) => *i as i64,
                _ => 0i64,
            })
            .ok_or_else(|| Error::Other("algorithm missing".to_string()))?;

        return match (key_type, CoseAlgorithmIdentifier::from(alg)) {
            (WEBAUTH_PUBLIC_KEY_TYPE_EC2, CoseAlgorithmIdentifier::EC2) => {
                let curve = map
                    .get(&Value::Integer(-1))
                    .map(|val| match val {
                        Value::Integer(i) => *i as i64,
                        _ => 0i64,
                    })
                    .ok_or_else(|| Error::Other("curve missing".to_string()))?;

                let x = map
                    .get(&Value::Integer(-2))
                    .and_then(|val| match val {
                        Value::Bytes(i) => {
                            let mut array = [0u8; 32];
                            array.copy_from_slice(&i[0..32]);
                            Some(array)
                        }
                        _ => None,
                    })
                    .ok_or_else(|| Error::Other("x coordinate missing".to_string()))?;

                let coords = map
                    .get(&Value::Integer(-3))
                    .and_then(|val| match val {
                        Value::Bytes(i) => {
                            let mut array = [0u8; 32];
                            array.copy_from_slice(&i[0..32]);
                            Some(Coordinates::Uncompressed { x, y: array })
                        }

                        Value::Bool(b) => Some(Coordinates::Compressed {
                            x,
                            y: if *b { ECDSA_Y_PREFIX_NEGATIVE } else { ECDSA_Y_PREFIX_POSITIVE },
                        }),
                        _ => None,
                    })
                    .ok_or_else(|| Error::Other("y coordinate missing".to_string()))?;

                Ok(CredentialPublicKey {
                    key_type,
                    alg,
                    key_info: CoseKeyInfo::EC2(EC2 { curve, coords }),
                })
            }
            (WEBAUTH_PUBLIC_KEY_TYPE_RSA, CoseAlgorithmIdentifier::RSA) => {
                let n = map
                    .get(&Value::Integer(-1))
                    .and_then(|val| match val {
                        Value::Bytes(i) => {
                            let mut n = Vec::with_capacity(256);
                            n.extend_from_slice(i);
                            Some(n)
                        }
                        _ => None,
                    })
                    .ok_or_else(|| Error::Other("Invalid modulus for RSA key type".to_owned()))?;

                let e = map
                    .get(&Value::Integer(-2))
                    .and_then(|val| match val {
                        Value::Bytes(i) => {
                            let mut e = Vec::with_capacity(3);
                            e.extend_from_slice(i);
                            Some(e)
                        }
                        _ => None,
                    })
                    .ok_or_else(|| Error::Other("Invalid exponent for RSA key type".to_owned()))?;

                if n.len() != 256 || e.len() != 3 {
                    return Err(Error::Other("Invalid RSA".to_owned()));
                }

                Ok(CredentialPublicKey {
                    key_type,
                    alg,
                    key_info: CoseKeyInfo::RSA(Rsa { n, e }),
                })
            }
            _ => Err(Error::Other("Cose key type not supported".to_owned())),
        };
    }
}

pub trait Message {
    fn from_base64(string: &str) -> Result<Self, Error>
    where
        Self: Sized;
    fn from_bytes(raw_values: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
}

impl Message for AttestationObject {
    fn from_base64(string: &str) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let raw_values = base64::decode(string)?;
        Self::from_bytes(raw_values.as_slice())
    }

    fn from_bytes(raw_values: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let value = serde_cbor::from_slice::<RawAttestationObject>(raw_values).map_err(Error::CborError)?;

        let data = match value.auth_data {
            Value::Bytes(vec) => Ok(vec),
            _ => Err(Error::Other("Cannot proceed without auth data".to_string())),
        }?;

        let att_stmt = match value.fmt.as_str() {
            WEBAUTHN_FORMAT_PACKED => serde_cbor::value::from_value::<Packed>(value.att_stmt)
                .ok()
                .map(AttestationStatement::Packed),

            WEBAUTHN_FORMAT_FIDO_U2F => serde_cbor::value::from_value::<FidoU2F>(value.att_stmt)
                .ok()
                .map(AttestationStatement::FidoU2F),

            WEBAUTHN_FORMAT_TPM => serde_cbor::value::from_value::<TPM>(value.att_stmt)
                .ok()
                .map(AttestationStatement::TPM),

            WEBAUTHN_FORMAT_ANDROID_KEY => serde_cbor::value::from_value::<AndroidKey>(value.att_stmt)
                .ok()
                .map(AttestationStatement::AndroidKey),

            WEBAUTHN_FORMAT_ANDROID_SAFETYNET => serde_cbor::value::from_value::<AndroidSafetynet>(value.att_stmt)
                .ok()
                .map(AttestationStatement::AndroidSafetynet),

            WEBAUTHN_FORMAT_NONE => Some(AttestationStatement::None),

            _ => None,
        };

        let (auth_data, raw_auth_data) = AuthenticatorData::from_vec(data)?;

        Ok(AttestationObject {
            auth_data,
            raw_auth_data,
            fmt: value.fmt,
            att_stmt,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Coordinates {
    Compressed { x: [u8; 32], y: u8 },
    Uncompressed { x: [u8; 32], y: [u8; 32] },
    None,
}

impl Coordinates {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut key = Vec::new();
        match self {
            Coordinates::Compressed { x, y } => {
                key.push(*y);
                key.append(&mut x.to_vec());
            }

            Coordinates::Uncompressed { x, y } => {
                key.push(ECDSA_Y_PREFIX_UNCOMPRESSED);
                key.append(&mut x.to_vec());
                key.append(&mut y.to_vec());
            }

            _ => {}
        }

        key
    }
}

impl ToString for Coordinates {
    fn to_string(&self) -> String {
        let mut key = Vec::new();
        match self {
            Coordinates::Compressed { x, y } => {
                key.push(*y);
                key.append(&mut x.to_vec());
            }

            Coordinates::Uncompressed { x, y } => {
                key.push(ECDSA_Y_PREFIX_UNCOMPRESSED);
                key.append(&mut x.to_vec());
                key.append(&mut y.to_vec());
            }

            _ => {}
        }

        base64::encode_config(&key, base64::URL_SAFE_NO_PAD)
    }
}

impl FromStr for Coordinates {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key = base64::decode_config(s, base64::URL_SAFE_NO_PAD).map_err(Error::Base64Error)?;

        match key[0] {
            ECDSA_Y_PREFIX_UNCOMPRESSED => {
                if key.len() == 65 {
                    let mut x = [0u8; 32];
                    let mut y = [0u8; 32];

                    x.copy_from_slice(&key[1..33]);
                    y.copy_from_slice(&key[33..65]);

                    Ok(Coordinates::Uncompressed { x, y })
                } else {
                    Err(Error::Other("Key is wrong length".to_string()))
                }
            }

            ECDSA_Y_PREFIX_POSITIVE => {
                if key.len() == 33 {
                    let mut x = [0u8; 32];
                    x.copy_from_slice(&key[1..32]);

                    Ok(Coordinates::Compressed {
                        x,
                        y: ECDSA_Y_PREFIX_POSITIVE,
                    })
                } else {
                    Err(Error::Other("Key is wrong length".to_string()))
                }
            }

            ECDSA_Y_PREFIX_NEGATIVE => {
                if key.len() == 33 {
                    let mut x = [0u8; 32];
                    x.copy_from_slice(&key[1..32]);

                    Ok(Coordinates::Compressed {
                        x,
                        y: ECDSA_Y_PREFIX_NEGATIVE,
                    })
                } else {
                    Err(Error::Other("Key is wrong length".to_string()))
                }
            }

            _ => Err(Error::Other("Key prefix missing".to_string())),
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum CoseAlgorithmIdentifier {
    EC2 = -7,
    RSA = -257,
    RS1 = -65535,
    NotSupported,
}

impl From<i64> for CoseAlgorithmIdentifier {
    fn from(value: i64) -> Self {
        match value {
            -65535 => CoseAlgorithmIdentifier::RS1,
            -257 => CoseAlgorithmIdentifier::RSA,
            -7 => CoseAlgorithmIdentifier::EC2,
            _ => CoseAlgorithmIdentifier::NotSupported,
        }
    }
}

impl From<CoseAlgorithmIdentifier> for i64 {
    fn from(value: CoseAlgorithmIdentifier) -> Self {
        match value {
            CoseAlgorithmIdentifier::RS1 => -65535,
            CoseAlgorithmIdentifier::RSA => -257,
            CoseAlgorithmIdentifier::EC2 => -7,
            _ => -65536, //Unassigned
        }
    }
}
