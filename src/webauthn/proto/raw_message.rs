use crate::webauthn::{
    error::Error,
    proto::{
        constants::{
            ECDSA_Y_PREFIX_NEGATIVE, ECDSA_Y_PREFIX_POSITIVE, ECDSA_Y_PREFIX_UNCOMPRESSED, WEBAUTHN_FORMAT_ANDROID_KEY,
            WEBAUTHN_FORMAT_ANDROID_SAFETYNET, WEBAUTHN_FORMAT_FIDO_U2F, WEBAUTHN_FORMAT_NONE, WEBAUTHN_FORMAT_PACKED, WEBAUTHN_FORMAT_TPM,
            WEBAUTH_PUBLIC_KEY_TYPE_EC2, WEBAUTH_PUBLIC_KEY_TYPE_OKP, WEBAUTH_PUBLIC_KEY_TYPE_RSA,
        },
        tpm::TPM,
    },
};
use byteorder::{BigEndian, ReadBytesExt};
use bytes::Buf;
use serde_cbor::{to_vec, Value};
use serde_derive::*;
use std::{
    collections::BTreeMap,
    io::{Cursor, Read, Write},
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

impl AttestationStatement {
    pub fn to_cbor(self) -> Result<Value, Error> {
        match self {
            AttestationStatement::Packed(value) => serde_cbor::value::to_value(&value).map_err(Error::CborError),
            AttestationStatement::TPM(value) => serde_cbor::value::to_value(&value).map_err(Error::CborError),
            AttestationStatement::FidoU2F(value) => serde_cbor::value::to_value(&value).map_err(Error::CborError),
            AttestationStatement::AndroidKey(value) => serde_cbor::value::to_value(&value).map_err(Error::CborError),
            AttestationStatement::AndroidSafetynet(value) => serde_cbor::value::to_value(&value).map_err(Error::CborError),
            AttestationStatement::None => Ok(Value::Map(BTreeMap::new())),
        }
    }
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
        let has_attested_credential_data = flags & (1 << 6) > 0;
        let has_extensions = flags & (1 << 7) > 0;

        let sign_count = cursor.read_u32::<BigEndian>()?;

        let mut remaining_cbor = Value::Null;
        let attested_credential_data = if has_attested_credential_data {
            let mut aaguid = [0u8; 16];
            cursor.read_exact(&mut aaguid)?;

            let length = cursor.read_u16::<BigEndian>()?;

            let mut credential_id = vec![0u8; length as usize];
            cursor.read_exact(&mut credential_id[..])?;

            let mut remaining = vec![0u8; cursor.remaining()];
            cursor.read_exact(&mut remaining[..])?;
            let public_key_cbor = match serde_cbor::from_slice::<serde_cbor::Value>(remaining.as_slice()) {
                Ok(cred) => cred,
                Err(e) if has_extensions && e.is_syntax() => {
                    // serde_cbor will send a `ErrorImpl` with code: `ErrorCode::TrailingData` and offset: offset of
                    // first extra byte if we have Extensions blob afterward.
                    // Since `ErrorImpl` is not public, the best we can do is catch the syntax category and retry
                    // the slice before the first offset error.

                    // The offset is incorectly reported as of serde_cbor 0.11.2;
                    // If, for example, a buffer of 93 bytes contain a valid CBOR payload from [0..77] (77 bytes,
                    // bytes from 0 to 76 as the 77 bound is exclusive), the reported offset in the error will be 78.
                    let offset = (e.offset() - 1) as usize;

                    remaining_cbor = serde_cbor::from_slice::<serde_cbor::Value>(&remaining[offset..])?;
                    serde_cbor::from_slice::<serde_cbor::Value>(&remaining[..offset])?
                }
                Err(e) => return Err(Error::CborError(e).into()),
            };

            let credential_public_key = CredentialPublicKey::from_value(&public_key_cbor)?;

            Some(AttestedCredentialData {
                aaguid,
                credential_id,
                credential_public_key,
            })
        } else {
            if has_extensions {
                let mut remaining = vec![0u8; cursor.remaining()];
                cursor.read_exact(&mut remaining[..])?;
                remaining_cbor = serde_cbor::from_slice::<serde_cbor::Value>(remaining.as_slice()).map_err(Error::CborError)?;
            }

            None
        };

        let extensions = if has_extensions { remaining_cbor } else { Value::Null };

        Ok((
            AuthenticatorData {
                rp_id_hash,
                flags,
                sign_count,
                attested_credential_data,
                extensions,
            },
            cursor.into_inner(),
        ))
    }

    pub fn to_vec(self) -> Result<Vec<u8>, Error> {
        let mut vec = vec![];
        vec.write(&self.rp_id_hash)?;
        vec.push(self.flags);
        vec.write(&self.sign_count.to_be_bytes())?;

        if let Some(att_cred_data) = self.attested_credential_data {
            vec.write(&att_cred_data.aaguid)?;
            vec.write(&(att_cred_data.credential_id.len() as u16).to_be_bytes())?;
            vec.write(&att_cred_data.credential_id)?;
            vec.write(&att_cred_data.credential_public_key.to_bytes()?)?;
        }

        Ok(vec)
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
pub struct OKP {
    pub curve: i64,
    pub coords: Coordinates,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum CoseKeyInfo {
    OKP(OKP),
    EC2(EC2),
    RSA(Rsa),
}

impl CoseKeyInfo {
    pub fn key_type(&self) -> i64 {
        match self {
            CoseKeyInfo::OKP(_) => 1,
            CoseKeyInfo::EC2(_) => 2,
            CoseKeyInfo::RSA(_) => 3,
        }
    }
}

impl CredentialPublicKey {
    pub fn from_value(value: &serde_cbor::Value) -> Result<Self, Error> {
        let map = match value {
            Value::Map(m) => m,
            _ => return Err(Error::Other("Invalid Cbor for CredentialPublicKey".to_string())),
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

        match (key_type, CoseAlgorithmIdentifier::from(alg)) {
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
                            if i.len() < 32 {
                                return None;
                            }
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
                            if i.len() < 32 {
                                return None;
                            }
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
            (WEBAUTH_PUBLIC_KEY_TYPE_OKP, CoseAlgorithmIdentifier::Ed25519) => {
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
                            if i.len() < 32 {
                                return None;
                            }
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
                            if i.len() < 32 {
                                return None;
                            }
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
                    key_info: CoseKeyInfo::OKP(OKP { curve, coords }),
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
        }
    }

    pub fn to_bytes(self) -> Result<Vec<u8>, Error> {
        let mut map = BTreeMap::new();
        match self.key_info {
            CoseKeyInfo::EC2(value) => {
                map.insert(Value::Integer(1), Value::Integer(WEBAUTH_PUBLIC_KEY_TYPE_EC2 as i128));
                map.insert(Value::Integer(3), Value::Integer(CoseAlgorithmIdentifier::EC2 as i128));
                map.insert(Value::Integer(-1), Value::Integer(value.curve as i128));
                match value.coords {
                    Coordinates::Compressed { x, y } => {
                        map.insert(Value::Integer(-2), Value::Bytes(x.to_vec()));
                        map.insert(Value::Integer(-3), Value::Bool(y == ECDSA_Y_PREFIX_NEGATIVE));
                    }

                    Coordinates::Uncompressed { x, y } => {
                        map.insert(Value::Integer(-2), Value::Bytes(x.to_vec()));
                        map.insert(Value::Integer(-3), Value::Bytes(y.to_vec()));
                    }

                    Coordinates::None => {
                        return Err(Error::Other("Invalid coordinates".to_string()));
                    }
                }
            }

            CoseKeyInfo::OKP(value) => {
                map.insert(Value::Integer(1), Value::Integer(WEBAUTH_PUBLIC_KEY_TYPE_OKP as i128));
                map.insert(Value::Integer(3), Value::Integer(CoseAlgorithmIdentifier::Ed25519 as i128));
                map.insert(Value::Integer(-1), Value::Integer(value.curve as i128));
                match value.coords {
                    Coordinates::Compressed { x, y } => {
                        map.insert(Value::Integer(-2), Value::Bytes(x.to_vec()));
                        map.insert(Value::Integer(-3), Value::Bool(y == ECDSA_Y_PREFIX_NEGATIVE));
                    }

                    Coordinates::Uncompressed { x, y } => {
                        map.insert(Value::Integer(-2), Value::Bytes(x.to_vec()));
                        map.insert(Value::Integer(-3), Value::Bytes(y.to_vec()));
                    }

                    Coordinates::None => {
                        return Err(Error::Other("Invalid coordinates".to_string()));
                    }
                }
            }

            CoseKeyInfo::RSA(value) => {
                map.insert(Value::Integer(1), Value::Integer(WEBAUTH_PUBLIC_KEY_TYPE_RSA as i128));
                map.insert(Value::Integer(3), Value::Integer(CoseAlgorithmIdentifier::RSA as i128));
                map.insert(Value::Integer(-1), Value::Bytes(value.n));
                map.insert(Value::Integer(-2), Value::Bytes(value.e));
            }
        };
        to_vec(&map).map_err(Error::CborError)
    }
}

pub trait Message {
    fn from_base64(string: &str) -> Result<Self, Error>
    where
        Self: Sized;
    fn from_bytes(raw_values: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;

    fn to_bytes(self) -> Result<Vec<u8>, Error>
    where
        Self: Sized;

    fn to_base64(self) -> Result<String, Error>
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

    fn to_bytes(self) -> Result<Vec<u8>, Error>
    where
        Self: Sized,
    {
        let att_stmt = match self.att_stmt {
            Some(v) => v.to_cbor()?,
            None => Value::Null,
        };

        let mut att_obj = BTreeMap::new();
        att_obj.insert("authData".to_string(), Value::Bytes(self.auth_data.to_vec()?));
        att_obj.insert("fmt".to_string(), Value::Text(self.fmt));
        att_obj.insert("attStmt".to_string(), att_stmt);
        to_vec(&att_obj).map_err(Error::CborError)
    }

    fn to_base64(self) -> Result<String, Error>
    where
        Self: Sized,
    {
        Ok(base64::encode(Self::to_bytes(self)?))
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

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Copy)]
pub enum CoseAlgorithmIdentifier {
    Ed25519 = -8,
    EC2 = -7,
    RSA = -257,
    RS1 = -65535,
    NotSupported,
}

impl Default for CoseAlgorithmIdentifier {
    fn default() -> Self {
        CoseAlgorithmIdentifier::NotSupported
    }
}

impl From<i64> for CoseAlgorithmIdentifier {
    fn from(value: i64) -> Self {
        match value {
            -65535 => CoseAlgorithmIdentifier::RS1,
            -257 => CoseAlgorithmIdentifier::RSA,
            -7 => CoseAlgorithmIdentifier::EC2,
            -8 => CoseAlgorithmIdentifier::Ed25519,
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
            CoseAlgorithmIdentifier::Ed25519 => -8,
            _ => -65536, //Unassigned
        }
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum AttestationFlags {
    UserPresent = 1,
    //Reserved for future = 2
    UserVerified = 4,
    BackupEligible = 8,
    BackedUp = 16,
    //Reserved for future = 32
    AttestedCredentialDataIncluded = 64,
    ExtensionDataIncluded = 128,
}
