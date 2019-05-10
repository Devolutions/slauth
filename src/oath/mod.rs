pub mod utils;
pub mod hotp;
pub mod totp;

pub const OTP_DEFAULT_DIGITS_VALUE: usize = 6;
pub const OTP_DEFAULT_ALG_VALUE: utils::HashesAlgorithm = utils::HashesAlgorithm::SHA1;