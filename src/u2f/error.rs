use std::io::Error as IoError;
use ring::error::{KeyRejected, Unspecified};

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
    EndEntityError(webpki::Error)
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

pub trait ResultExt<T, E> {
    fn then<U,N, F>(self, op: F) -> Result<U, N> where F: FnOnce(Result<T, E>) -> Result<U, N>;
}

impl<T,E> ResultExt<T, E> for Result<T, E> {
    fn then<U, N, F>(self, op: F) -> Result<U, N> where F: FnOnce(Result<T, E>) -> Result<U, N> {
        op(self)
    }
}