use std::fmt::{Display, Formatter};
use std::io::Error as IoError;

#[derive(Debug)]
pub enum Error {
    IoError(IoError),
    Version,
    Registration(String),
    Sign(String),
    Other(String),
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
        }
    }
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::IoError(e)
    }
}
