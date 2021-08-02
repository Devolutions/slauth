use wasm_bindgen::prelude::*;

use crate::oath::{
    hotp::{HOTPBuilder, HOTPContext},
    totp::{TOTPBuilder, TOTPContext},
    HashesAlgorithm, OtpAuth,
};

#[wasm_bindgen]
#[derive(Clone)]
pub struct OtpAlgorithm {
    inner: HashesAlgorithm,
}

#[wasm_bindgen]
impl OtpAlgorithm {
    #[wasm_bindgen(js_name = "sha1")]
    pub fn sha1() -> OtpAlgorithm {
        OtpAlgorithm {
            inner: HashesAlgorithm::SHA1,
        }
    }

    #[wasm_bindgen(js_name = "sha256")]
    pub fn sha256() -> OtpAlgorithm {
        OtpAlgorithm {
            inner: HashesAlgorithm::SHA256,
        }
    }

    #[wasm_bindgen(js_name = "sha512")]
    pub fn sha512() -> OtpAlgorithm {
        OtpAlgorithm {
            inner: HashesAlgorithm::SHA512,
        }
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Totp {
    inner: TOTPContext,
}

#[wasm_bindgen]
impl Totp {
    #[wasm_bindgen(js_name = "fromParts")]
    pub fn from_parts(secret: &[u8], period: i32, digits: i32, algo: OtpAlgorithm) -> Result<Totp, JsValue> {
        let inner = TOTPBuilder::new()
            .algorithm(algo.inner)
            .digits(digits as usize)
            .period(period as u64)
            .secret(secret)
            .build();

        Ok(Totp { inner })
    }

    #[wasm_bindgen(js_name = "fromUri")]
    pub fn from_uri(uri: String) -> Result<Totp, JsValue> {
        let inner = TOTPContext::from_uri(uri.as_str())?;

        Ok(Totp { inner })
    }

    #[wasm_bindgen(js_name = "toUri")]
    pub fn to_uri(&self, application: Option<String>, username: Option<String>) -> String {
        self.inner.to_uri(username.as_deref(), application.as_deref())
    }

    #[wasm_bindgen(js_name = "generateCode")]
    pub fn generate_code(&self) -> String {
        self.inner.gen()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Hotp {
    inner: HOTPContext,
}

#[wasm_bindgen]
impl Hotp {
    #[wasm_bindgen(js_name = "fromParts")]
    pub fn from_parts(secret: &[u8], counter: u64, digits: i32, algo: OtpAlgorithm) -> Result<Hotp, JsValue> {
        let inner = HOTPBuilder::new()
            .algorithm(algo.inner)
            .digits(digits as usize)
            .counter(counter)
            .secret(secret)
            .build();

        Ok(Hotp { inner })
    }

    #[wasm_bindgen(js_name = "fromUri")]
    pub fn from_uri(uri: String) -> Result<Hotp, JsValue> {
        let inner = HOTPContext::from_uri(uri.as_str())?;

        Ok(Hotp { inner })
    }

    #[wasm_bindgen(js_name = "toUri")]
    pub fn to_uri(&self, application: Option<String>, username: Option<String>) -> String {
        self.inner.to_uri(username.as_deref(), application.as_deref())
    }

    #[wasm_bindgen(js_name = "generateCode")]
    pub fn generate_code(&self) -> String {
        self.inner.gen()
    }
}
