use hmac::{
    digest::{generic_array::GenericArray, FixedOutputReset, InvalidLength, OutputSizeUser},
    Mac, SimpleHmac,
};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::fmt::Display;

pub mod hotp;
pub mod totp;

pub const OTP_DEFAULT_DIGITS_VALUE: usize = 6;
pub const OTP_DEFAULT_ALG_VALUE: HashesAlgorithm = HashesAlgorithm::SHA1;

#[derive(Clone)]
pub enum HashesAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

#[derive(Clone)]
pub(crate) struct MacHashKey {
    secret: Vec<u8>,
    alg: HashesAlgorithm,
}

impl MacHashKey {
    pub(crate) fn sign(&self, data: &[u8]) -> Result<HmacShaResult, InvalidLength> {
        match self.alg {
            HashesAlgorithm::SHA1 => {
                let mut context = SimpleHmac::<Sha1>::new_from_slice(&self.secret)?;
                context.update(data);
                Ok(HmacShaResult::RSHA1(context.finalize_fixed_reset()))
            }
            HashesAlgorithm::SHA256 => {
                let mut context = SimpleHmac::<Sha256>::new_from_slice(&self.secret)?;
                context.update(data);
                Ok(HmacShaResult::RSHA256(context.finalize_fixed_reset()))
            }
            HashesAlgorithm::SHA512 => {
                let mut context = SimpleHmac::<Sha512>::new_from_slice(&self.secret)?;
                context.update(data);
                Ok(HmacShaResult::RSHA512(context.finalize_fixed_reset()))
            }
        }
    }
}

pub(crate) enum HmacShaResult {
    RSHA1(GenericArray<u8, <Sha1 as OutputSizeUser>::OutputSize>),
    RSHA256(GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>),
    RSHA512(GenericArray<u8, <Sha512 as OutputSizeUser>::OutputSize>),
}

impl HmacShaResult {
    pub(crate) fn into_vec(self) -> Vec<u8> {
        match self {
            HmacShaResult::RSHA1(res) => res.to_vec(),
            HmacShaResult::RSHA256(res) => res.to_vec(),
            HmacShaResult::RSHA512(res) => res.to_vec(),
        }
    }
}

impl HashesAlgorithm {
    pub(crate) fn to_mac_hash_key(&self, key: &[u8]) -> MacHashKey {
        MacHashKey {
            secret: key.to_vec(),
            alg: self.clone(),
        }
    }
}

impl Display for HashesAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            HashesAlgorithm::SHA1 => "SHA1".to_string(),
            HashesAlgorithm::SHA256 => "SHA256".to_string(),
            HashesAlgorithm::SHA512 => "SHA512".to_string(),
        };
        write!(f, "{}", str)
    }
}

pub trait OtpAuth {
    fn to_uri(&self, label: Option<&str>, issuer: Option<&str>) -> String;
    fn from_uri(uri: &str) -> Result<Self, String>
    where
        Self: Sized;
}

#[inline]
pub(crate) fn dt(hmac_res: &[u8]) -> u32 {
    let offset_val = (hmac_res[hmac_res.len() - 1] & 0x0F) as usize;
    let h = &hmac_res[offset_val..offset_val + 4];

    ((h[0] as u32 & 0x7f) << 24) | ((h[1] as u32 & 0xff) << 16) | ((h[2] as u32 & 0xff) << 8) | (h[3] as u32 & 0xff)
}

#[inline]
pub(crate) fn decode_hex_or_base_32(encoded: &str) -> Option<Vec<u8>> {
    // Try base32 first then is it does not follows RFC4648, try HEX
    base32::decode(base32::Alphabet::RFC4648 { padding: false }, encoded).or_else(|| hex::decode(encoded).ok())
}

#[cfg(target_arch = "wasm32")]
pub fn get_time() -> u64 {
    let dt = js_sys::Date::new_0();
    let ut: f64 = dt.get_time();
    if ut < 0.0 {
        0
    } else {
        (ut.floor() as u64) / 1000
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn get_time() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp() as u64
}
