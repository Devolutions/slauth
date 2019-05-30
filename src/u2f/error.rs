use std::io::Error as IoError;

pub enum Error {
    IoError(IoError),
    ApduError(u16),
    UnexpectedApdu(String),
    AsnFormatError(String),
    MalformedApdu,
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::IoError(e)
    }
}

impl From<u16> for Error {
    fn from(sw: u16) -> Self {
        Error::ApduError(sw)
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