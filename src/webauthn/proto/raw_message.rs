use crate::webauthn::{
    error::Error,
    proto::constants::{
        ECDSA_Y_PREFIX_NEGATIVE, ECDSA_Y_PREFIX_POSITIVE, ECDSA_Y_PREFIX_UNCOMPRESSED, WEBAUTHN_FORMAT_ANDROID_KEY,
        WEBAUTHN_FORMAT_ANDROID_SAFETYNET, WEBAUTHN_FORMAT_FIDO_U2F, WEBAUTHN_FORMAT_NONE, WEBAUTHN_FORMAT_PACKED, WEBAUTHN_FORMAT_TPM,
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
use std::fmt::Formatter;
use std::marker::PhantomData;
use serde::de::Visitor;
use serde::Deserializer;

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
#[serde(rename_all = "camelCase")]
pub struct TPM {
    pub ver: serde_cbor::Value,
    pub alg: i64,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<X5C>,
    #[serde(deserialize_with = "deserialize_cert_info")]
    pub cert_info: CertInfo,
    #[serde(deserialize_with = "deserialize_public_area")]
    pub pub_area: PublicArea,
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ObjectAttributes {
    pub fixed_tpm: bool,
    pub st_clear: bool,
    pub fixed_parent: bool,
    pub sensitive_data_origin: bool,
    pub user_with_auth: bool,
    pub admin_with_policy: bool,
    pub no_da: bool,
    pub encryption_duplication: bool,
    pub restricted: bool,
    pub decrypt: bool,
    pub sign_or_encrypt: bool,
}

impl ObjectAttributes {
    pub fn from_u32(o: u32) -> ObjectAttributes {
        ObjectAttributes {
            fixed_tpm: (o & 1) != 0,
            st_clear: (o & 2) != 0,
            fixed_parent: (o & 8) != 0,
            sensitive_data_origin: (o & 16) != 0,
            user_with_auth: (o & 32) != 0,
            admin_with_policy: (o & 64) != 0,
            no_da: (o & 512) != 0,
            encryption_duplication: (o & 1024) != 0,
            restricted: (o & 32768) != 0,
            decrypt: (o & 65536) != 0,
            sign_or_encrypt: (o & 131072) != 0,
        }
    }
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TPM2BDigest {
    size: u16,
    #[serde(with = "serde_bytes")]
    buffer: Option<Vec<u8>>
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub enum AlgParameters {
    None,
    RSA(RsaAlgParameters),
    ECC(EccAlgParameters),
}

impl Default for AlgParameters {
    fn default() -> Self {
        AlgParameters::None
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RsaAlgParameters {
    pub symmetric: TpmAlgId,
    pub scheme: TpmAlgId,
    pub key_bits: u16,
    pub exponent: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EccAlgParameters {
    pub symmetrics: TpmAlgId,
    pub scheme: TpmAlgId,
    pub curve_id: TpmEccCurve,
    pub kdf: TpmAlgId,
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PublicArea {
    #[serde(alias = "type")]
    pub alg_type: u16,
    pub name_alg: u16,
    pub object_attributes: ObjectAttributes,
    pub auth_policy: TPM2BDigest,
    pub parameters: AlgParameters,
    pub unique: TPM2BDigest,
}

impl PublicArea {
    pub fn from_vec(buf: Vec<u8>) -> Result<PublicArea, Error> {
        let mut cursor = Cursor::new(buf);
        let alg_type = cursor.read_u16::<BigEndian>().unwrap();

        let name_alg = cursor.read_u16::<BigEndian>().unwrap();

        let o = cursor.read_u32::<BigEndian>().unwrap();
        let object_attributes = ObjectAttributes::from_u32(o);

        let auth_policy_length = cursor.read_u16::<BigEndian>().unwrap();
        let mut auth_policy = vec![0u8; auth_policy_length as usize];
        cursor.read_exact(&mut auth_policy).unwrap();

        let parameters = match TpmAlgId::from_u16(alg_type) {
            TpmAlgId::RSA => {
                AlgParameters::RSA(RsaAlgParameters{
                    symmetric: TpmAlgId::from_u16(cursor.read_u16::<BigEndian>()?),
                    scheme: TpmAlgId::from_u16(cursor.read_u16::<BigEndian>()?),
                    key_bits: cursor.read_u16::<BigEndian>()?,
                    exponent: cursor.read_u32::<BigEndian>()?,
                })
            }
            TpmAlgId::ECC => {
                AlgParameters::ECC(EccAlgParameters{
                    symmetrics: TpmAlgId::from_u16(cursor.read_u16::<BigEndian>()?),
                    scheme: TpmAlgId::from_u16(cursor.read_u16::<BigEndian>()?),
                    curve_id: TpmEccCurve::from_u16(cursor.read_u16::<BigEndian>()?),
                    kdf: TpmAlgId::from_u16(cursor.read_u16::<BigEndian>()?),
                })
            }
            _ => {
                AlgParameters::None
            }
        };

        let unique_length = cursor.read_u16::<BigEndian>().unwrap();
        let mut unique = vec![0u8; unique_length as usize];
        cursor.read_exact(&mut unique).unwrap();

        Ok(PublicArea {
            alg_type,
            name_alg,
            object_attributes,
            auth_policy: TPM2BDigest {
                size: auth_policy_length,
                buffer: Some(auth_policy)
            },
            parameters,
            unique: TPM2BDigest {
                size: unique_length,
                buffer: Some(unique)
            }
        })
    }
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    pub magic: u32,
    pub attestation_type: AttestationType,
    pub qualified_signer: Tpm2bName,
    pub extra_data: Tpm2bData,
    pub clock_info: TpmsClockInfo,
    pub firmware_version: u64,
    pub attested_name: (u16, Vec<u8>, Vec<u8>),
}

impl CertInfo {
    pub fn from_vec(buf: Vec<u8>) -> Result<CertInfo, Error> {
        let mut cursor = Cursor::new(buf);

        let magic = cursor.read_u32::<BigEndian>()?;

        let attestation_type = AttestationType::from_u16(cursor.read_u16::<BigEndian>()?);

        let qualifier_signer_length = cursor.read_u16::<BigEndian>()?;
        let mut qualifier_signer = vec![0u8; qualifier_signer_length as usize];
        cursor.read_exact(&mut qualifier_signer)?;

        let extra_data_length = cursor.read_u16::<BigEndian>()?;
        let mut extra_data = vec![0u8; extra_data_length as usize];
        cursor.read_exact(&mut extra_data)?;

        let clock = cursor.read_u64::<BigEndian>()?;
        let reset_count = cursor.read_u32::<BigEndian>()?;
        let restart_count = cursor.read_u32::<BigEndian>()?;
        let safe = cursor.read_u8()?;

        let firmware_version = cursor.read_u64::<BigEndian>()?;

        let attested_name_length = cursor.read_u16::<BigEndian>()?;
        let mut attested_name_buffer = vec![0u8; attested_name_length as usize];
        cursor.read_exact(&mut attested_name_buffer)?;

        let attested_qualified_name_length = cursor.read_u16::<BigEndian>()?;
        let mut attested_qualified_name = vec![0u8; attested_qualified_name_length as usize];
        cursor.read_exact(&mut attested_qualified_name)?;

        let mut cursor = Cursor::new(attested_name_buffer);
        let attested_name_alg = cursor.read_u16::<BigEndian>()?;
        let mut attested_name = vec![0u8; cursor.remaining()];
        cursor.read_exact(&mut attested_name[..])?;

        Ok(CertInfo{
            magic,
            attestation_type,
            qualified_signer: Tpm2bName {
                size: qualifier_signer_length,
                name: Some(qualifier_signer),
            },
            extra_data: Tpm2bData {
                size: extra_data_length,
                ca_cert: Some(extra_data),
            },
            clock_info: TpmsClockInfo {
                reset_count,
                clock,
                restart_count,
                safe: (safe & 1) != 0
            },
            firmware_version,
            attested_name: (attested_name_alg, attested_name, attested_qualified_name)
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct X5C {
    #[serde(with = "serde_bytes")]
    pub aik_cert: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub ca_cert: Option<Vec<u8>>
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Tpm2bData {
    pub size: u16,
    #[serde(with = "serde_bytes")]
    pub ca_cert: Option<Vec<u8>>
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TpmsClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Tpm2bName {
    pub size: u16,
    #[serde(with = "serde_bytes")]
    pub name: Option<Vec<u8>>
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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
#[repr(u16)]
pub enum AttestationType {
    None,
    TpmStAttestNv = 0x8014,
    TpmStAttestCommandAudit = 0x8015,
    TpmStAttestSessionAudit = 0x8016,
    TpmStAttestCertify = 0x8017,
    TpmStAttestQuote = 0x8018,
    TpmStAttestTime = 0x8019,
    TpmStAttestCreation = 0x801A,
}

impl Default for AttestationType {
    fn default() -> Self {
        AttestationType::None
    }
}

impl AttestationType {
    pub fn from_u16(att_type: u16) -> AttestationType {
        match att_type {
            0x8014 => AttestationType::TpmStAttestNv,
            0x8015 => AttestationType::TpmStAttestCommandAudit,
            0x8016 => AttestationType::TpmStAttestSessionAudit,
            0x8017 => AttestationType::TpmStAttestCertify,
            0x8018 => AttestationType::TpmStAttestQuote,
            0x8019 => AttestationType::TpmStAttestTime,
            0x801A => AttestationType::TpmStAttestCreation,
            _ => AttestationType::None
        }
    }
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
    pub curve: i64,
    pub coords: Coordinates,
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
            curve,
            coords,
        })
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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub enum TpmAlgId {
    Error = 0x0000,
    RSA = 0x0001,
    SHA1 = 0x0004,
    HMAC = 0x0005,
    AES = 0x0006,
    MGF1 = 0x0007,
    KEYEDHASH = 0x0008,
    XOR = 0x000A,
    SHA256 = 0x000B,
    SHA384 = 0x000C,
    SHA512 = 0x000D,
    NULL = 0x0010,
    SM3_256 = 0x0012,
    SM4 = 0x0013,
    RSASSA = 0x0014,
    RSAES = 0x0015,
    RSAPSS = 0x0016,
    OAEP = 0x0017,
    ECDSA = 0x0018,
    ECDH = 0x0019,
    ECDAA = 0x001A,
    SM2 = 0x001B,
    ECSCHNORR = 0x001C,
    ECMQV = 0x001D,
    Kdf1Sp800_56A = 0x0020,
    KDF2 = 0x0021,
    Kdf1Sp800_108 = 0x0022,
    ECC = 0x0023,
    SYMCIPHER = 0x0025,
    CAMELLIA = 0x0026,
    CTR = 0x0040,
    OFB = 0x0041,
    CBC = 0x0042,
    CFB = 0x0043,
    ECB = 0x0044,
}

impl TpmAlgId {
    pub fn from_u16(alg_id: u16) -> TpmAlgId {
        match alg_id {
            0x0000 => TpmAlgId::Error,
            0x0001 => TpmAlgId::RSA,
            0x0004 => TpmAlgId::SHA1,
            0x0005 => TpmAlgId::HMAC,
            0x0006 => TpmAlgId::AES,
            0x0007 => TpmAlgId::MGF1,
            0x0008 => TpmAlgId::KEYEDHASH,
            0x000A => TpmAlgId::XOR,
            0x000B => TpmAlgId::SHA256,
            0x000C => TpmAlgId::SHA384,
            0x000D => TpmAlgId::SHA512,
            0x0010 => TpmAlgId::NULL,
            0x0012 => TpmAlgId::SM3_256,
            0x0013 => TpmAlgId::SM4,
            0x0014 => TpmAlgId::RSASSA,
            0x0015 => TpmAlgId::RSAES,
            0x0016 => TpmAlgId::RSAPSS,
            0x0017 => TpmAlgId::OAEP,
            0x0018 => TpmAlgId::ECDSA,
            0x0019 => TpmAlgId::ECDH,
            0x001A => TpmAlgId::ECDAA,
            0x001B => TpmAlgId::SM2,
            0x001C => TpmAlgId::ECSCHNORR,
            0x001D => TpmAlgId::ECMQV,
            0x0020 => TpmAlgId::Kdf1Sp800_56A,
            0x0021 => TpmAlgId::KDF2,
            0x0022 => TpmAlgId::Kdf1Sp800_108,
            0x0023 => TpmAlgId::ECC,
            0x0025 => TpmAlgId::SYMCIPHER,
            0x0026 => TpmAlgId::CAMELLIA,
            0x0040 => TpmAlgId::CTR,
            0x0041 => TpmAlgId::OFB,
            0x0042 => TpmAlgId::CBC,
            0x0043 => TpmAlgId::CFB,
            0x0044 => TpmAlgId::ECB,
            _ => TpmAlgId::Error
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub enum TpmEccCurve {
    None = 0x0000,
    NISTP192 = 0x0001,
    NISTP224 = 0x0002,
    NISTP256 = 0x0003,
    NISTP384 = 0x0004,
    NISTP521 = 0x0005,
    BNP256 = 0x00010,
    BNP638 = 0x0011,
    SM2P256 = 0x0020,
    BPP256R1 = 0x0030,
    BPP384R1 = 0x0031,
    BPP512R1 = 0x0032,
    Curve25519 = 0x0040,
    Curve448 = 0x0041,
}

impl TpmEccCurve {
    pub fn from_u16(ecc: u16) -> TpmEccCurve {
        match ecc {
            0x0000 => TpmEccCurve::None,
            0x0001 => TpmEccCurve::NISTP192,
            0x0002 => TpmEccCurve::NISTP224,
            0x0003 => TpmEccCurve::NISTP256,
            0x0004 => TpmEccCurve::NISTP384,
            0x0005 => TpmEccCurve::NISTP521,
            0x00010 => TpmEccCurve::BNP256,
            0x0011 => TpmEccCurve::BNP638,
            0x0020 => TpmEccCurve::SM2P256,
            0x0030 => TpmEccCurve::BPP256R1,
            0x0031 => TpmEccCurve::BPP384R1,
            0x0032 => TpmEccCurve::BPP512R1,
            0x0040 => TpmEccCurve::Curve25519,
            0x0041 => TpmEccCurve::Curve448,
            _ => TpmEccCurve::None
        }
    }
}

pub fn deserialize_cert_info<'de, D>(deserializer: D) -> Result<CertInfo, D::Error>
    where
        D: Deserializer<'de>,
{
    struct CertInfoFromBuffer(PhantomData<fn() -> CertInfo>);

    impl<'de> Visitor<'de> for CertInfoFromBuffer {
        type Value = CertInfo;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("a valid CertInfo buffer")
        }

        fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E> where E: serde::de::Error {
            CertInfo::from_vec(v).map_err(|e| serde::de::Error::custom(e))
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> where E: serde::de::Error {
            self.visit_byte_buf(v.to_vec())
        }
    }

    deserializer.deserialize_any(CertInfoFromBuffer(PhantomData))
}

pub fn deserialize_public_area<'de, D>(deserializer: D) -> Result<PublicArea, D::Error>
    where
        D: Deserializer<'de>,
{
    struct PublicAreaFromBuffer(PhantomData<fn() -> PublicArea>);

    impl<'de> Visitor<'de> for PublicAreaFromBuffer {
        type Value = PublicArea;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("a valid PublicArea buffer")
        }

        fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E> where E: serde::de::Error {
            PublicArea::from_vec(v).map_err(|e| serde::de::Error::custom(e))
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> where E: serde::de::Error {
            self.visit_byte_buf(v.to_vec())
        }
    }

    deserializer.deserialize_any(PublicAreaFromBuffer(PhantomData))
}