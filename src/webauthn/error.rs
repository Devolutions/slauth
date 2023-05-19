use base64::DecodeError;
use ring::error::Unspecified;
use serde_cbor::Error as CborError;
use serde_json::Error as JsonError;
use std::{
    error::Error as StdError,
    fmt::{Display, Formatter},
    io::Error as IoError,
};
use webpki::Error as WebPkiError;

#[derive(Debug)]
pub enum CredentialError {
    RequestType,
    Challenge,
    Origin,
    Rp,
    UserPresentFlag,
    UserVerifiedFlag,
    Extensions,
    KeyType,
    CertificateMissing,
    CertificateNotSupported,
    AttestationMissing,
    AttestationNotSupported,
    Other(String),
}

#[derive(Debug)]
pub enum TpmError {
    AlgorithmNotSupported,
    AttestationVersionNotSupported,
    AttestedNamePubAreaMismatch,
    AttToBeSignedHashAlgorithmInvalid(i64),
    AttToBeSignedMismatch,
    AttestationTypeInvalid,
    CertificateMissing,
    CertificateParsing,
    CertificateVersionInvalid,
    CertificateSubjectInvalid,
    CertificateExtensionNotCritical,
    CertificateExtensionRequirementNotMet(String),
    CertificateRequirementNotMet(String),
    MagicInvalid,
    PubAreaHashUnknown(u16),
    PubAreaMismatch,
    PublicKeyParametersMismatch(i64),
    PublicKeyCoordinatesMismatch,
    SignatureHashInvalid(i64),
    SignatureValidationFailed,
    TpmVendorNotFound,
}

#[derive(Debug)]
pub enum Error {
    IoError(IoError),
    Base64Error(DecodeError),
    CborError(CborError),
    JsonError(JsonError),
    WebPkiError(WebPkiError),
    RingError(Unspecified),
    Version,
    CredentialError(CredentialError),
    TpmError(TpmError),
    Other(String),
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Self {
        Error::Base64Error(e)
    }
}

impl From<CborError> for Error {
    fn from(e: CborError) -> Self {
        Error::CborError(e)
    }
}

impl From<JsonError> for Error {
    fn from(e: JsonError) -> Self {
        Error::JsonError(e)
    }
}

impl From<WebPkiError> for Error {
    fn from(e: WebPkiError) -> Self {
        Error::WebPkiError(e)
    }
}

impl From<Unspecified> for Error {
    fn from(e: Unspecified) -> Self {
        Error::RingError(e)
    }
}

impl StdError for Error {}

impl Display for CredentialError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        use CredentialError::*;
        match self {
            RequestType => write!(f, "Wrong request type"),
            Challenge => write!(f, "Challenges do not match"),
            Origin => write!(f, "Wrong origin"),
            Rp => write!(f, "Wrong rp ID"),
            UserPresentFlag => write!(f, "Missing user present flag"),
            UserVerifiedFlag => write!(f, "Missing user verified flag"),
            Extensions => write!(f, "Extensions should not be present"),
            KeyType => write!(f, "wrong key type"),
            CertificateMissing => write!(f, "Certificate is missing"),
            CertificateNotSupported => write!(f, "Ecdaaa certificate is not supported"),
            AttestationMissing => write!(f, "Missing attested credential data"),
            AttestationNotSupported => write!(f, "Attestation format is not supported"),
            Other(s) => write!(f, "{}", s),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        use Error::*;
        match self {
            IoError(io_e) => io_e.fmt(f),
            Version => write!(f, "Unsupported version"),
            CredentialError(ce) => ce.fmt(f),
            Other(s) => write!(f, "{}", s),
            Base64Error(e) => e.fmt(f),
            CborError(cb_e) => cb_e.fmt(f),
            JsonError(js_e) => js_e.fmt(f),
            WebPkiError(wp_e) => wp_e.fmt(f),
            RingError(r_e) => r_e.fmt(f),
            TpmError(tpm_e) => tpm_e.fmt(f),
        }
    }
}

impl Display for TpmError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        match self {
            TpmError::AlgorithmNotSupported => write!(f, "Algorithm not supported"),
            TpmError::AttestationVersionNotSupported => write!(f, "Attestation version not supported"),
            TpmError::AttestedNamePubAreaMismatch => write!(f, "Attested name does not match with hash of PubArea"),
            TpmError::AttToBeSignedHashAlgorithmInvalid(hash) => write!(f, "Invalid hash algorithm for AttToBeSigned: {}", hash),
            TpmError::AttToBeSignedMismatch => write!(f, "AttToBeSigned does not match with CertInfo.extra_data"),
            TpmError::AttestationTypeInvalid => write!(f, "Attestation type is invalid"),
            TpmError::CertificateMissing => write!(f, "Aik certificate is missing"),
            TpmError::CertificateParsing => write!(f, "Error parsing aik certificate"),
            TpmError::CertificateVersionInvalid => write!(f, "Certificate version is not supported. Expected v3"),
            TpmError::CertificateSubjectInvalid => write!(f, "Certificate subject is not empty"),
            TpmError::CertificateExtensionNotCritical => write!(f, "Certificate extension is not critical"),
            TpmError::CertificateExtensionRequirementNotMet(ext) => write!(f, "Requirements for {} certificate extension are not met", ext),
            TpmError::CertificateRequirementNotMet(field) => write!(f, "Requirements for {} certificate field are not met", field),
            TpmError::MagicInvalid => write!(f, "CertInfo.magic is different then TPM_GENERATED_VALUE"),
            TpmError::PubAreaHashUnknown(hash) => write!(f, "PubArea's Tpm Algorithm ID {} is not supported", hash),
            TpmError::PubAreaMismatch => write!(f, "PubArea public key information does not match with CredentialPublicKey"),
            TpmError::PublicKeyParametersMismatch(alg) => write!(
                f,
                "PubArea public key parameters does not match with CredentialPublicKey with algorithm {}",
                alg
            ),
            TpmError::PublicKeyCoordinatesMismatch => {
                write!(f, "PubArea public key coordinates does not match with EC2 CredentialPublicKey")
            }
            TpmError::SignatureHashInvalid(hash) => write!(f, "Signature hash not supported {}", hash),
            TpmError::SignatureValidationFailed => write!(f, "Signature validation failed"),
            TpmError::TpmVendorNotFound => write!(f, "TPM Vendor not found"),
        }
    }
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::IoError(e)
    }
}
