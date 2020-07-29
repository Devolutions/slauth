use ring::error::{KeyRejected, Unspecified};
#[cfg(feature = "u2f-server")]
use serde_json::error::Error as SJsonError;
use std::{
    error::Error as StdError,
    fmt::{Display, Formatter},
    io::Error as IoError,
};

#[derive(Debug)]
pub enum Error {
    IoError(IoError),
    U2FErrorCode(u16),
    UnexpectedApdu(String),
    AsnFormatError(String),
    MalformedApdu,
    Version,
    RingKeyRejected(KeyRejected),
    Registration(String),
    Sign(String),
    Other(String),
    #[cfg(feature = "u2f-server")]
    EndEntityError(webpki::Error),
    #[cfg(feature = "u2f-server")]
    SerdeJsonError(SJsonError),
}

impl StdError for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        use Error::*;
        match self {
            IoError(io_e) => io_e.fmt(f),
            U2FErrorCode(code) => write!(f, "U2f Error Code: {}", code),
            UnexpectedApdu(s) => write!(f, "{}", s),
            AsnFormatError(s) => write!(f, "{}", s),
            MalformedApdu => write!(f, "Unsupported version"),
            Version => write!(f, "Unsupported version"),
            RingKeyRejected(key_r_e) => key_r_e.fmt(f),
            Registration(s) => write!(f, "{}", s),
            Sign(s) => write!(f, "{}", s),
            Other(s) => write!(f, "{}", s),
            #[cfg(feature = "u2f-server")]
            EndEntityError(webpki_e) => webpki_e.fmt(f),
            #[cfg(feature = "u2f-server")]
            SerdeJsonError(s_j_e) => s_j_e.fmt(f),
        }
    }
}

#[cfg(feature = "u2f-server")]
impl From<webpki::Error> for Error {
    fn from(e: webpki::Error) -> Self {
        Error::EndEntityError(e)
    }
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::IoError(e)
    }
}

impl From<u16> for Error {
    fn from(sw: u16) -> Self {
        Error::U2FErrorCode(sw)
    }
}

impl From<Unspecified> for Error {
    fn from(_: Unspecified) -> Self {
        Error::Other("Unspecified".to_string())
    }
}

impl From<KeyRejected> for Error {
    fn from(e: KeyRejected) -> Self {
        Error::RingKeyRejected(e)
    }
}

#[cfg(feature = "u2f-server")]
impl From<SJsonError> for Error {
    fn from(e: SJsonError) -> Self {
        Error::SerdeJsonError(e)
    }
}

pub trait ResultExt<T, E> {
    fn then<U, N, F>(self, op: F) -> Result<U, N>
    where
        F: FnOnce(Result<T, E>) -> Result<U, N>;
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    fn then<U, N, F>(self, op: F) -> Result<U, N>
    where
        F: FnOnce(Result<T, E>) -> Result<U, N>,
    {
        op(self)
    }
}
