use hmac::{Hmac, Mac};
use hmac::crypto_mac::{InvalidKeyLength, MacResult};
use hmac::digest::FixedOutput;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

#[derive(Clone)]
pub enum HashesAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

pub(crate) struct MacHashKey {
    secret: Vec<u8>,
    alg: HashesAlgorithm,
}

impl MacHashKey {
    pub(crate) fn sign(&self, data: &[u8]) -> Result<HmacShaResult, InvalidKeyLength> {
        match self.alg {
            HashesAlgorithm::SHA1 => {
                let mut context = Hmac::<Sha1>::new_varkey(&self.secret)?;
                context.input(data);
                Ok(HmacShaResult::RSHA1(context.result_reset()))
            }
            HashesAlgorithm::SHA256 => {
                let mut context = Hmac::<Sha256>::new_varkey(&self.secret)?;
                context.input(data);
                Ok(HmacShaResult::RSHA256(context.result_reset()))
            }
            HashesAlgorithm::SHA512 => {
                let mut context = Hmac::<Sha512>::new_varkey(&self.secret)?;
                context.input(data);
                Ok(HmacShaResult::RSHA512(context.result_reset()))
            }
        }
    }
}

pub(crate) enum HmacShaResult {
    RSHA1(MacResult<<Sha1 as FixedOutput>::OutputSize>),
    RSHA256(MacResult<<Sha256 as FixedOutput>::OutputSize>),
    RSHA512(MacResult<<Sha512 as FixedOutput>::OutputSize>),
}

impl HmacShaResult {
    pub(crate) fn into_vec(self) -> Vec<u8> {
        match self {
            HmacShaResult::RSHA1(res) => res.code().as_slice().to_vec(),
            HmacShaResult::RSHA256(res) => res.code().as_slice().to_vec(),
            HmacShaResult::RSHA512(res) => res.code().as_slice().to_vec(),
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

impl ToString for HashesAlgorithm {
    fn to_string(&self) -> String {
        match self {
            HashesAlgorithm::SHA1 => "SHA1".to_string(),
            HashesAlgorithm::SHA256 => "SHA256".to_string(),
            HashesAlgorithm::SHA512 => "SHA512".to_string(),
        }
    }
}

pub trait OtpAuth {
    fn to_uri(&self, label: Option<&str>, issuer: Option<&str>) -> String;
    fn from_uri(uri: &str) -> Result<Self, String> where Self: Sized;
}

#[inline]
pub(crate) fn dt(hmac_res: &[u8]) -> u32 {
    let offset_val = (hmac_res[hmac_res.len() - 1] & 0x0F) as usize;
    let h = &hmac_res[offset_val..offset_val + 4];

    (((h[0] as u32 & 0x7f) << 24) | ((h[1] as u32 & 0xff) << 16) | ((h[2] as u32 & 0xff) << 8) | (h[3] as u32 & 0xff) as u32)
}

#[cfg(feature = "native-bindings")]
pub mod strings {
    use std::ffi::{
        CStr,
        CString,
    };
    use std::os::raw::c_char;

    pub fn c_char_to_string(cchar: *const c_char) -> String {
        let c_str = unsafe { CStr::from_ptr(cchar) };
        let r_str = match c_str.to_str() {
            Err(_) => "",
            Ok(string) => string,
        };
        r_str.to_string()
    }

    pub fn string_to_c_char(r_string: String) -> *mut c_char {
        CString::new(r_string).expect("Converting a string into a c_char should not fail").into_raw()
    }

    pub fn mut_c_char_to_string(cchar: *mut c_char) -> String {
        let c_string = unsafe {
            if cchar.is_null() {
                CString::from_vec_unchecked(vec![])
            } else {
                CString::from_raw(cchar)
            }
        };
        let c_str = c_string.as_c_str();
        let r_str = match c_str.to_str() {
            Err(_) => "",
            Ok(string) => string,
        };
        r_str.to_string()
    }
}