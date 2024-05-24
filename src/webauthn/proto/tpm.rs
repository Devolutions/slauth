use crate::webauthn::{
    error::{Error, TpmError},
    proto::{
        constants::{
            ECDSA_CURVE_P256, ECDSA_CURVE_P384, ECDSA_CURVE_P521, TCG_AT_TPM_MANUFACTURER, TCG_AT_TPM_MODEL, TCG_AT_TPM_VERSION,
            TCG_KP_AIK_CERTIFICATE, TPM_GENERATED_VALUE,
        },
        raw_message::{Coordinates, CoseAlgorithmIdentifier, CoseKeyInfo, CredentialPublicKey},
    },
};
use byteorder::{BigEndian, ReadBytesExt};
use hmac::digest::FixedOutput;
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey};
use serde_cbor::Value;
use serde_derive::*;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::{
    collections::HashMap,
    io::{Cursor, Read},
};
use x509_parser::{
    nom::{
        bytes::complete::{tag, take},
        IResult, Parser,
    },
    prelude::{GeneralName, X509Certificate, X509CertificateParser, X509Version},
};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TPM {
    pub ver: serde_cbor::Value,
    pub alg: i64,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<serde_cbor::Value>,
    #[serde(with = "serde_bytes")]
    pub cert_info: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub pub_area: Vec<u8>,
}

impl TPM {
    pub fn verify_structure(&self) -> Result<CertInfo, Error> {
        if CoseAlgorithmIdentifier::from(self.alg) == CoseAlgorithmIdentifier::NotSupported {
            return Err(Error::TpmError(TpmError::AlgorithmNotSupported));
        }

        if !matches!(&self.ver, Value::Text(ver) if ver == "2.0") {
            return Err(Error::TpmError(TpmError::AttestationVersionNotSupported));
        }

        if self.x5c.is_none() {
            return Err(Error::TpmError(TpmError::CertificateMissing));
        }

        let cert_info = CertInfo::from_slice(self.cert_info.as_slice())?;

        if cert_info.magic != TPM_GENERATED_VALUE {
            return Err(Error::TpmError(TpmError::MagicInvalid));
        }

        Ok(cert_info)
    }

    pub fn verify_attest(&self, cert_info: &CertInfo, name_alg: TpmAlgId) -> Result<(), Error> {
        match cert_info.attestation_type {
            AttestationType::TpmStAttestCertify => {
                let (name, _) = &cert_info.attested_name;
                let hash_name = match name_alg {
                    TpmAlgId::SHA256 => {
                        let mut hash_name: Vec<u8> = vec![0, 11];
                        let mut hasher = Sha256::new();
                        hasher.update(self.pub_area.as_slice());
                        let mut pub_area_hash = hasher.finalize().to_vec();
                        hash_name.append(&mut pub_area_hash);
                        hash_name
                    }
                    _ => return Err(Error::TpmError(TpmError::PubAreaHashUnknown(name_alg.into()))),
                };

                if hash_name != *name {
                    return Err(Error::TpmError(TpmError::AttestedNamePubAreaMismatch));
                }
            }
            _ => return Err(Error::TpmError(TpmError::AttestationTypeInvalid)),
        }

        Ok(())
    }

    pub fn verify_extra_data(&self, auth_data: &[u8], client_data_hash: &[u8], extra_data: Option<Vec<u8>>) -> Result<(), Error> {
        let mut buf = Vec::with_capacity(auth_data.len() + client_data_hash.len());
        buf.extend_from_slice(auth_data);
        buf.extend_from_slice(client_data_hash);

        let att_to_be_signed = match self.alg.into() {
            CoseAlgorithmIdentifier::RS1 => {
                let mut hasher = Sha1::new();
                hasher.update(buf.as_slice());
                Ok(hasher.finalize_fixed().to_vec())
            }
            CoseAlgorithmIdentifier::RSA => {
                let mut hasher = Sha256::new();
                hasher.update(buf.as_slice());
                Ok(hasher.finalize().to_vec())
            }
            _ => Err(Error::TpmError(TpmError::AttToBeSignedHashAlgorithmInvalid(self.alg))),
        }?;

        if let Some(extra_data) = extra_data {
            if att_to_be_signed == extra_data {
                return Ok(());
            }
        }

        Err(Error::TpmError(TpmError::AttToBeSignedMismatch))
    }

    pub fn verify_signature(&self, cert: &[u8]) -> Result<(), Error> {
        let (scheme, hashed) = match self.alg.into() {
            CoseAlgorithmIdentifier::RS1 => (
                Pkcs1v15Sign::new::<Sha1>(),
                sha1::Sha1::digest(self.cert_info.as_slice()).as_slice().to_vec(),
            ),
            CoseAlgorithmIdentifier::RSA => (
                Pkcs1v15Sign::new::<Sha256>(),
                sha2::Sha256::digest(self.cert_info.as_slice()).as_slice().to_vec(),
            ),
            _ => return Err(Error::TpmError(TpmError::SignatureHashInvalid(self.alg))),
        };

        let public_key = RsaPublicKey::from_public_key_der(cert)
            .map_err(|e| Error::Other(format!("verify_signature - Invalid certificate: {:?}", e)))?;
        public_key
            .verify(scheme, hashed.as_slice(), self.sig.as_slice())
            .map_err(|_| Error::TpmError(TpmError::SignatureValidationFailed))
    }

    pub fn verify_public_key(&self, credential_pk: &CredentialPublicKey) -> Result<(), Error> {
        let pub_area = PublicArea::from_slice(self.pub_area.as_slice())?;

        match (credential_pk.alg.into(), pub_area.parameters, pub_area.unique) {
            (CoseAlgorithmIdentifier::RSA, AlgParameters::RSA(_), TpmuPublicId::Rsa(modulus)) => {
                if !matches!(&self.ver, Value::Text(ver) if ver == "2.0") {
                    return Err(Error::TpmError(TpmError::AttestationVersionNotSupported));
                }

                if !matches!(&credential_pk.key_info, CoseKeyInfo::RSA(rsa) if rsa.n == modulus) {
                    return Err(Error::TpmError(TpmError::PublicKeyParametersMismatch(credential_pk.alg)));
                }
            }
            (CoseAlgorithmIdentifier::ES256, AlgParameters::ECC(params), TpmuPublicId::Ecc(ecc_points)) => {
                if let CoseKeyInfo::EC2(ec2) = &credential_pk.key_info {
                    if !matches!(
                        (ec2.curve, params.curve_id),
                        (ECDSA_CURVE_P256, TpmEccCurve::NISTP256)
                            | (ECDSA_CURVE_P384, TpmEccCurve::NISTP384)
                            | (ECDSA_CURVE_P521, TpmEccCurve::NISTP521)
                    ) {
                        return Err(Error::TpmError(TpmError::PublicKeyParametersMismatch(credential_pk.alg)));
                    }

                    match ec2.coords {
                        Coordinates::Compressed { .. } => {
                            return Err(Error::TpmError(TpmError::PublicKeyCoordinatesMismatch));
                        }
                        Coordinates::Uncompressed { x, y } => {
                            if x.as_slice() != ecc_points.x.as_slice() || y.as_slice() != ecc_points.y.as_slice() {
                                return Err(Error::TpmError(TpmError::PublicKeyCoordinatesMismatch));
                            }
                        }
                        _ => return Err(Error::Other("Expected coordinates found nothing".to_owned())),
                    }
                }
            }
            _ => {
                return Err(Error::TpmError(TpmError::PubAreaMismatch));
            }
        }

        Ok(())
    }

    pub fn verify_cert(&self) -> Result<Vec<u8>, Error> {
        if let Some(serde_cbor::Value::Array(cert_arr)) = self.x5c.as_ref() {
            if let Some(serde_cbor::Value::Bytes(aik_cert)) = cert_arr.first() {
                let (_, x509) = X509CertificateParser::new()
                    .with_deep_parse_extensions(true)
                    .parse(aik_cert)
                    .map_err(|_| Error::TpmError(TpmError::CertificateParsing))?;

                if x509.version != X509Version::V3 {
                    return Err(Error::TpmError(TpmError::CertificateVersionInvalid));
                }

                if x509.subject.iter().next().is_some() {
                    return Err(Error::TpmError(TpmError::CertificateSubjectInvalid));
                }

                self.verify_subject_alternative_name(&x509)?;
                self.verify_extended_key_usage(&x509)?;
                self.verify_basic_constraints(&x509)?;
                return Ok(x509.public_key().raw.to_vec());
            }
        }

        Err(Error::TpmError(TpmError::CertificateMissing))
    }

    fn verify_subject_alternative_name(&self, x509: &X509Certificate) -> Result<(), Error> {
        if let Ok(Some(subject_alt_name)) = x509.subject_alternative_name() {
            if !subject_alt_name.critical {
                return Err(Error::TpmError(TpmError::CertificateExtensionNotCritical));
            }

            if subject_alt_name.value.general_names.iter().any(|general_name| {
                if let GeneralName::DirectoryName(x509_name) = general_name {
                    let mut alt_name_attributes = HashMap::new();

                    for attribute in x509_name.iter_attributes() {
                        match attribute.attr_type().as_bytes() {
                            TCG_AT_TPM_MANUFACTURER => {
                                if let Ok(manufacturer) = attribute.attr_value().as_str() {
                                    alt_name_attributes.insert(TCG_AT_TPM_MANUFACTURER, manufacturer.to_owned());
                                }
                            }
                            TCG_AT_TPM_MODEL => {
                                if let Ok(model) = attribute.attr_value().as_str() {
                                    alt_name_attributes.insert(TCG_AT_TPM_MODEL, model.to_owned());
                                }
                            }
                            TCG_AT_TPM_VERSION => {
                                if let Ok(version) = attribute.attr_value().as_str() {
                                    alt_name_attributes.insert(TCG_AT_TPM_VERSION, version.to_owned());
                                }
                            }
                            _ => {}
                        }
                    }

                    if alt_name_attributes.contains_key(TCG_AT_TPM_MANUFACTURER)
                        && alt_name_attributes.contains_key(TCG_AT_TPM_MODEL)
                        && alt_name_attributes.contains_key(TCG_AT_TPM_VERSION)
                    {
                        if let Some(manufacturer) = alt_name_attributes.get(TCG_AT_TPM_MANUFACTURER) {
                            if let Ok((_, vendor_bytes)) = parse_vendor_attribute(manufacturer.as_bytes()) {
                                return TpmVendor::try_from_bytes(vendor_bytes).is_ok();
                            }
                        }
                    }
                }
                false
            }) {
                return Ok(());
            }
        }

        Err(Error::TpmError(TpmError::CertificateExtensionRequirementNotMet(
            "Subject Alternative Name".to_owned(),
        )))
    }

    fn verify_extended_key_usage(&self, x509: &X509Certificate) -> Result<(), Error> {
        match x509.extended_key_usage() {
            Ok(Some(extended_key_usage)) if extended_key_usage.value.other.contains(TCG_KP_AIK_CERTIFICATE) => Ok(()),
            _ => Err(Error::TpmError(TpmError::CertificateRequirementNotMet(
                "Extended Key Usage".to_owned(),
            ))),
        }
    }

    fn verify_basic_constraints(&self, x509: &X509Certificate) -> Result<(), Error> {
        match x509.basic_constraints() {
            Ok(Some(basic_constraints)) if !basic_constraints.value.ca => Ok(()),
            _ => Err(Error::TpmError(TpmError::CertificateRequirementNotMet(
                "Basic Constraint".to_owned(),
            ))),
        }
    }
}

pub fn parse_vendor_attribute(b: &[u8]) -> IResult<&[u8], &[u8; 8]> {
    let (b, _) = tag("id:")(b)?;
    let (b, vendor_code) = take(8usize)(b)?;

    Ok((b, vendor_code.try_into().unwrap_or(&[0u8; 8])))
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
    buffer: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub enum AlgParameters {
    #[default]
    None,
    RSA(RsaAlgParameters),
    ECC(EccAlgParameters),
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
    pub unique: TpmuPublicId,
}

impl PublicArea {
    pub fn from_slice(buf: &[u8]) -> Result<PublicArea, Error> {
        let mut cursor = Cursor::new(buf);
        let alg_type = cursor.read_u16::<BigEndian>()?;

        let name_alg = cursor.read_u16::<BigEndian>()?;

        let o = cursor.read_u32::<BigEndian>()?;
        let object_attributes = ObjectAttributes::from_u32(o);

        let auth_policy_length = cursor.read_u16::<BigEndian>()?;
        let mut auth_policy = vec![0u8; auth_policy_length as usize];
        cursor.read_exact(&mut auth_policy)?;

        let (parameters, public_id) = match TpmAlgId::from_u16(alg_type) {
            TpmAlgId::RSA => {
                let parameters = AlgParameters::RSA(RsaAlgParameters {
                    symmetric: TpmAlgId::from_u16(cursor.read_u16::<BigEndian>()?),
                    scheme: TpmAlgId::from_u16(cursor.read_u16::<BigEndian>()?),
                    key_bits: cursor.read_u16::<BigEndian>()?,
                    exponent: cursor.read_u32::<BigEndian>()?,
                });

                let unique_length = cursor.read_u16::<BigEndian>()?;
                let mut unique = vec![0u8; unique_length as usize];
                cursor.read_exact(&mut unique)?;

                (parameters, TpmuPublicId::Rsa(unique))
            }
            TpmAlgId::ECC => {
                let parameters = AlgParameters::ECC(EccAlgParameters {
                    symmetrics: TpmAlgId::from_u16(cursor.read_u16::<BigEndian>()?),
                    scheme: TpmAlgId::from_u16(cursor.read_u16::<BigEndian>()?),
                    curve_id: TpmEccCurve::from_u16(cursor.read_u16::<BigEndian>()?),
                    kdf: TpmAlgId::from_u16(cursor.read_u16::<BigEndian>()?),
                });

                let x_length = cursor.read_u16::<BigEndian>()?;
                let mut x = vec![0u8; x_length as usize];
                cursor.read_exact(&mut x)?;

                let y_length = cursor.read_u16::<BigEndian>()?;
                let mut y = vec![0u8; y_length as usize];
                cursor.read_exact(&mut y)?;

                (parameters, TpmuPublicId::Ecc(EccPoint { x, y }))
            }
            _ => (AlgParameters::None, TpmuPublicId::None),
        };

        Ok(PublicArea {
            alg_type,
            name_alg,
            object_attributes,
            auth_policy: TPM2BDigest {
                size: auth_policy_length,
                buffer: Some(auth_policy),
            },
            parameters,
            unique: public_id,
        })
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub enum TpmuPublicId {
    #[default]
    None,
    Rsa(Vec<u8>),
    Ecc(EccPoint),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EccPoint {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
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
    pub alg: u16,
    pub attested_name: (Vec<u8>, Vec<u8>),
}

impl CertInfo {
    pub fn from_slice(buf: &[u8]) -> Result<CertInfo, Error> {
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

        let mut cursor = Cursor::new(attested_name_buffer.as_slice());
        let attested_name_alg = cursor.read_u16::<BigEndian>()?;

        Ok(CertInfo {
            magic,
            attestation_type,
            qualified_signer: Tpm2bName {
                size: qualifier_signer_length,
                name: Some(qualifier_signer),
            },
            extra_data: Tpm2bData {
                size: extra_data_length,
                data: Some(extra_data),
            },
            clock_info: TpmsClockInfo {
                reset_count,
                clock,
                restart_count,
                safe: (safe & 1) != 0,
            },
            firmware_version,
            alg: attested_name_alg,
            attested_name: (attested_name_buffer, attested_qualified_name),
        })
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Tpm2bData {
    pub size: u16,
    #[serde(with = "serde_bytes")]
    pub data: Option<Vec<u8>>,
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
    pub name: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, PartialEq, Default, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub enum AttestationType {
    #[default]
    None,
    TpmStAttestNv = 0x8014,
    TpmStAttestCommandAudit = 0x8015,
    TpmStAttestSessionAudit = 0x8016,
    TpmStAttestCertify = 0x8017,
    TpmStAttestQuote = 0x8018,
    TpmStAttestTime = 0x8019,
    TpmStAttestCreation = 0x801A,
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
            _ => AttestationType::None,
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
            _ => TpmAlgId::Error,
        }
    }
}

impl From<TpmAlgId> for u16 {
    fn from(alg_id: TpmAlgId) -> Self {
        match alg_id {
            TpmAlgId::Error => 0x0000,
            TpmAlgId::RSA => 0x0001,
            TpmAlgId::SHA1 => 0x0004,
            TpmAlgId::HMAC => 0x0005,
            TpmAlgId::AES => 0x0006,
            TpmAlgId::MGF1 => 0x0007,
            TpmAlgId::KEYEDHASH => 0x0008,
            TpmAlgId::XOR => 0x000A,
            TpmAlgId::SHA256 => 0x000B,
            TpmAlgId::SHA384 => 0x000C,
            TpmAlgId::SHA512 => 0x000D,
            TpmAlgId::NULL => 0x0010,
            TpmAlgId::SM3_256 => 0x0012,
            TpmAlgId::SM4 => 0x0013,
            TpmAlgId::RSASSA => 0x0014,
            TpmAlgId::RSAES => 0x0015,
            TpmAlgId::RSAPSS => 0x0016,
            TpmAlgId::OAEP => 0x0017,
            TpmAlgId::ECDSA => 0x0018,
            TpmAlgId::ECDH => 0x0019,
            TpmAlgId::ECDAA => 0x001A,
            TpmAlgId::SM2 => 0x001B,
            TpmAlgId::ECSCHNORR => 0x001C,
            TpmAlgId::ECMQV => 0x001D,
            TpmAlgId::Kdf1Sp800_56A => 0x0020,
            TpmAlgId::KDF2 => 0x0021,
            TpmAlgId::Kdf1Sp800_108 => 0x0022,
            TpmAlgId::ECC => 0x0023,
            TpmAlgId::SYMCIPHER => 0x0025,
            TpmAlgId::CAMELLIA => 0x0026,
            TpmAlgId::CTR => 0x0040,
            TpmAlgId::OFB => 0x0041,
            TpmAlgId::CBC => 0x0042,
            TpmAlgId::CFB => 0x0043,
            TpmAlgId::ECB => 0x0044,
        }
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
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
            _ => TpmEccCurve::None,
        }
    }
}

pub enum TpmVendor {
    AMD,
    Atmel,
    Broadcom,
    Cisco,
    FlysliceTechnologies,
    FuzhouRockchip,
    Google,
    HPE,
    Huawei,
    IBM,
    Infineon,
    Intel,
    Lenovo,
    Microsoft,
    NationalSemiconductor,
    Nationz,
    NuvotonTechnology,
    Qualcomm,
    Samsung,
    Sinosun,
    SMSC,
    StMicroelectronics,
    TexasInstruments,
    Winbond,
}

impl TpmVendor {
    pub fn try_from_bytes(b: &[u8; 8]) -> Result<Self, Error> {
        match b {
            b"414d4400" => Ok(TpmVendor::AMD),
            b"41544D4C" => Ok(TpmVendor::Atmel),
            b"4252434D" => Ok(TpmVendor::Broadcom),
            b"4353434F" => Ok(TpmVendor::Cisco),
            b"464C5953" => Ok(TpmVendor::FlysliceTechnologies),
            b"524F4343" => Ok(TpmVendor::FuzhouRockchip),
            b"474F4F47" => Ok(TpmVendor::Google),
            b"48504500" => Ok(TpmVendor::HPE),
            b"48495349" => Ok(TpmVendor::Huawei),
            b"49424D00" => Ok(TpmVendor::IBM),
            b"49465800" => Ok(TpmVendor::Infineon),
            b"494E5443" => Ok(TpmVendor::Intel),
            b"4C454E00" => Ok(TpmVendor::Lenovo),
            b"4D534654" => Ok(TpmVendor::Microsoft),
            b"4E534D20" => Ok(TpmVendor::NationalSemiconductor),
            b"4E545A00" => Ok(TpmVendor::Nationz),
            b"4E544300" => Ok(TpmVendor::NuvotonTechnology),
            b"51434F4D" => Ok(TpmVendor::Qualcomm),
            b"534D534E" => Ok(TpmVendor::Samsung),
            b"534E5300" => Ok(TpmVendor::Sinosun),
            b"534D5343" => Ok(TpmVendor::SMSC),
            b"53544D20" => Ok(TpmVendor::StMicroelectronics),
            b"54584E00" => Ok(TpmVendor::TexasInstruments),
            b"57454300" => Ok(TpmVendor::Winbond),
            _ => Err(Error::TpmError(TpmError::TpmVendorNotFound)),
        }
    }
}
