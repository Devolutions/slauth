use ring::digest::{Algorithm, SHA1, SHA256, SHA512};

pub enum SlauthAlgoritm {
    SHA1,
    SHA256,
    SHA512,
}

impl SlauthAlgoritm {
    pub fn alg_ref(&self) -> &'static Algorithm {
        match self {
            SlauthAlgoritm::SHA1 => &SHA1,
            SlauthAlgoritm::SHA256 => &SHA256,
            SlauthAlgoritm::SHA512 => &SHA512,
        }
    }
}

impl ToString for SlauthAlgoritm {
    fn to_string(&self) -> String {
        match self {
            SlauthAlgoritm::SHA1 => "SHA1".to_string(),
            SlauthAlgoritm::SHA256 => "SHA256".to_string(),
            SlauthAlgoritm::SHA512 => "SHA512".to_string(),
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