use uuid::Uuid;
use wasm_bindgen::prelude::*;

use crate::{
    oath::{
        decode_hex_or_base_32,
        totp::{TOTPBuilder, TOTPContext},
        HashesAlgorithm, OtpAuth,
    },
    webauthn::{
        authenticator::WebauthnAuthenticator,
        proto::web_message::{PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions},
    },
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
    pub fn from_parts(secret: String, period: i32, digits: i32, algo: OtpAlgorithm) -> Result<Totp, JsValue> {
        let secret = decode_hex_or_base_32(secret.as_str()).ok_or_else(|| "Otpauth uri is malformed, missing secret value".to_string())?;
        let inner = TOTPBuilder::new()
            .algorithm(algo.inner)
            .digits(digits as usize)
            .period(period as u64)
            .secret(secret.as_slice())
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

#[cfg(feature = "webauthn")]
#[wasm_bindgen]
#[derive(Clone)]
pub struct PasskeyAuthenticator {
    aaguid: Uuid,
}

#[cfg(feature = "webauthn")]
#[wasm_bindgen]
impl PasskeyAuthenticator {
    #[wasm_bindgen(constructor)]
    pub fn new(aaguid: String) -> Result<PasskeyAuthenticator, String> {
        let aaguid = Uuid::parse_str(aaguid.as_str()).map_err(|_| "Failed to parse aaguid from string")?;
        Ok(PasskeyAuthenticator { aaguid })
    }

    #[wasm_bindgen(js_name = "generateCredentialCreationResponse")]
    pub fn generate_credential_creation_response(
        &self,
        options: JsValue,
        credential_id: Vec<u8>,
        attestation_flags: u8,
        origin: Option<String>,
    ) -> Result<JsValue, String> {
        let options: PublicKeyCredentialCreationOptions = serde_wasm_bindgen::from_value(options).map_err(|e| format!("{e:?}"))?;
        let cred =
            WebauthnAuthenticator::generate_credential_creation_response(options, self.aaguid, credential_id, origin, attestation_flags)
                .map_err(|e| format!("{e:?}"))?;
        serde_wasm_bindgen::to_value(&cred).map_err(|e| format!("{e:?}"))
    }

    #[wasm_bindgen(js_name = "generateCredentialRequestResponse")]
    pub fn generate_credential_request_response(
        &self,
        options: JsValue,
        credential_id: Vec<u8>,
        attestation_flags: u8,
        origin: Option<String>,
        user_handle: Option<Vec<u8>>,
        private_key: String,
    ) -> Result<JsValue, String> {
        let options: PublicKeyCredentialRequestOptions = serde_wasm_bindgen::from_value(options).map_err(|e| format!("{e:?}"))?;
        let cred = WebauthnAuthenticator::generate_credential_request_response(
            credential_id,
            attestation_flags,
            options,
            origin,
            user_handle,
            private_key,
        )
        .map_err(|e| format!("{e:?}"))?;
        serde_wasm_bindgen::to_value(&cred).map_err(|e| format!("{e:?}"))
    }
}
