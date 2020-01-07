use std::fmt::{Display, Formatter};
use std::io::Error as IoError;
use std::error::Error as StdError;
use serde_cbor::Error as CborError;
use serde_json::Error as JsonError;
use base64::DecodeError;
use webpki::Error as WebPkiError;
use ring::error::Unspecified;

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
pub enum Error {
    IoError(IoError),
    Base64Error(DecodeError),
    CborError(CborError),
    JsonError(JsonError),
    WebPkiError(WebPkiError),
    RingError(Unspecified),
    Version,
    Registration(CredentialError),
    Sign(CredentialError),
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
            Other(s) => write!(f, "{}", s)
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        use Error::*;
        match self {
            IoError(io_e) => io_e.fmt(f),
            Version => write!(f, "Unsupported version"),
            Registration(ce) => ce.fmt(f),
            Sign(ce) => ce.fmt(f),
            Other(s) => write!(f, "{}", s),
            Base64Error(e) =>  e.fmt(f),
            CborError(cb_e) => cb_e.fmt(f),
            JsonError(js_e) => js_e.fmt(f),
            WebPkiError(wp_e) => wp_e.fmt(f),
            RingError(r_e) => r_e.fmt(f),
        }
    }
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::IoError(e)
    }
}
