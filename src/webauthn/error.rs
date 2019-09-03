use std::fmt::{Display, Formatter};
use std::io::Error as IoError;
use std::error::Error as StdError;
use serde_cbor::Error as CborError;
use serde_json::Error as JsonError;
use base64::DecodeError;

#[derive(Debug)]
pub enum Error {
    IoError(IoError),
    Base64Error(DecodeError),
    CborError(CborError),
    JsonError(JsonError),
    Version,
    Registration(String),
    Sign(String),
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

impl StdError for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        use Error::*;
        match self {
            IoError(io_e) => io_e.fmt(f),
            Version => write!(f, "Unsupported version"),
            Registration(s) => write!(f, "{}", s),
            Sign(s) => write!(f, "{}", s),
            Other(s) => write!(f, "{}", s),
            Base64Error(e) =>  e.fmt(f),
            CborError(cb_e) => cb_e.fmt(f),
            JsonError(cb_e) => cb_e.fmt(f),
        }
    }
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::IoError(e)
    }
}
