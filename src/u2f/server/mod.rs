use std::sync::atomic::{AtomicU64, Ordering};

use ring::signature;
use sha2::{Digest, Sha256};
use webpki::{EndEntityCert, ECDSA_P256_SHA256};

use crate::u2f::{
    error::Error,
    proto::{
        constants::U2F_V2_VERSION_STR,
        raw_message,
        raw_message::{apdu::ApduFrame, Message},
        web_message::*,
    },
};

static REQUESTS_IDS: AtomicU64 = AtomicU64::new(0);

pub struct U2fRequestBuilder {
    rtype: U2fRequestType,
    app_id: Option<String>,
    challenge: Option<String>,
    timeout: Option<u64>,
    registered_keys: Option<Vec<RegisteredKey>>,
}

impl U2fRequestBuilder {
    fn new(typ: U2fRequestType) -> Self {
        U2fRequestBuilder {
            app_id: None,
            challenge: None,
            timeout: None,
            rtype: typ,
            registered_keys: None,
        }
    }

    pub fn register() -> Self {
        Self::new(U2fRequestType::Register)
    }

    pub fn sign() -> Self {
        Self::new(U2fRequestType::Sign)
    }

    pub fn app_id(mut self, app_id: String) -> Self {
        self.app_id = Some(app_id);
        self
    }

    pub fn challenge(mut self, challenge: String) -> Self {
        self.challenge = Some(base64::encode(challenge));
        self
    }

    pub fn timeout_sec(mut self, timeout: u64) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn registered_keys(mut self, regk: Vec<RegisteredKey>) -> Self {
        self.registered_keys = Some(regk);
        self
    }

    pub fn build(self) -> Result<U2fRequest, Error> {
        let U2fRequestBuilder {
            app_id,
            challenge,
            timeout,
            rtype,
            registered_keys,
        } = self;

        let challenge = base64::encode_config(
            challenge
                .as_ref()
                .ok_or_else(|| Error::Other("Unable to build a U2F request without a challenge".to_string()))?,
            base64::URL_SAFE_NO_PAD,
        );

        let data = match rtype {
            U2fRequestType::Register => Request::Register(U2fRegisterRequest {
                register_requests: vec![RegisterRequest {
                    version: U2F_V2_VERSION_STR.to_string(),
                    challenge,
                }],
                registered_keys: registered_keys.unwrap_or_default(),
            }),
            U2fRequestType::Sign => {
                let registered_keys = registered_keys
                    .ok_or_else(|| Error::Other("Unable to build a U2F Sign request without at least one registered key".to_string()))?;

                Request::Sign(U2fSignRequest {
                    challenge,
                    registered_keys,
                })
            }
        };

        Ok(U2fRequest {
            req_type: rtype,
            app_id,
            timeout_seconds: timeout,
            request_id: Some(REQUESTS_IDS.fetch_add(1, Ordering::Relaxed)),
            data,
        })
    }
}

impl U2fResponse {
    pub fn as_register_response(&self) -> Option<&U2fRegisterResponse> {
        match self.response_data {
            Response::Register(ref reg) => Some(reg),
            _ => None,
        }
    }

    pub fn as_sign_response(&self) -> Option<&U2fSignResponse> {
        match self.response_data {
            Response::Sign(ref sign) => Some(sign),
            _ => None,
        }
    }

    pub fn is_error_response(&self) -> bool {
        matches!(self.response_data, Response::Error(_))
    }

    pub fn as_error_response(&self) -> Option<&ClientError> {
        match self.response_data {
            Response::Error(ref e) => Some(e),
            _ => None,
        }
    }
}

impl U2fRegisterResponse {
    /// Attempt to parse and validate the registration response data and construct a Registration Object
    ///
    /// Returns a `Registration` struct if all conditions are satisfied and signature is validated, else will return an error
    pub fn get_registration(&self) -> Result<Registration, Error> {
        let U2fRegisterResponse {
            version,
            registration_data,
            client_data,
        } = &self;

        if version != U2F_V2_VERSION_STR {
            return Err(Error::Version);
        }

        // Validate that input is consistent with what's expected
        let registration_data_bytes =
            base64::decode_config(registration_data, base64::URL_SAFE_NO_PAD).map_err(|e| Error::Registration(e.to_string()))?;
        let raw_rsp = raw_message::apdu::Response::read_from(&registration_data_bytes)?;
        let raw_u2f_reg = raw_message::RegisterResponse::from_apdu(raw_rsp)?;

        let client_data_bytes =
            base64::decode_config(client_data, base64::URL_SAFE_NO_PAD).map_err(|e| Error::Registration(e.to_string()))?;

        let client_data: ClientData =
            serde_json::from_slice(client_data_bytes.as_slice()).map_err(|e| Error::Registration(e.to_string()))?;

        // Validate signature
        let attestation_cert = EndEntityCert::try_from(raw_u2f_reg.attestation_cert.as_slice())?;

        let mut hasher = Sha256::new();

        hasher.update(client_data_bytes.as_slice());

        let challenge_hash = hasher.finalize_reset();

        hasher.update(&client_data.origin);

        let app_id_hash = hasher.finalize_reset();

        let signature_data = {
            let mut data = vec![0x00];
            data.extend_from_slice(&app_id_hash);
            data.extend_from_slice(&challenge_hash);
            data.extend_from_slice(raw_u2f_reg.key_handle.as_bytes());
            data.extend_from_slice(&raw_u2f_reg.user_public_key);
            data
        };

        attestation_cert.verify_signature(&ECDSA_P256_SHA256, &signature_data, &raw_u2f_reg.signature)?;

        Ok(Registration {
            version: U2F_V2_VERSION_STR.to_string(),
            app_id: client_data.origin,
            key_handle: raw_u2f_reg.key_handle,
            pub_key: raw_u2f_reg.user_public_key.to_vec(),
            attestation_cert: raw_u2f_reg.attestation_cert,
        })
    }
}

impl Registration {
    pub fn get_registered_key(&self) -> RegisteredKey {
        RegisteredKey {
            version: self.version.clone(),
            key_handle: self.key_handle.clone(),
            transports: None,
            app_id: Some(self.app_id.clone()),
        }
    }
}

impl U2fSignResponse {
    ///
    pub fn validate_signature(&self, public_key: &[u8]) -> Result<bool, Error> {
        let U2fSignResponse {
            signature_data,
            client_data,
            ..
        } = &self;

        let signature_data_byte =
            base64::decode_config(signature_data, base64::URL_SAFE_NO_PAD).map_err(|e| Error::Registration(e.to_string()))?;
        let raw_rsp = raw_message::apdu::Response::read_from(&signature_data_byte)?;
        let raw_u2f_sign = raw_message::AuthenticateResponse::from_apdu(raw_rsp)?;

        let client_data_bytes =
            base64::decode_config(client_data, base64::URL_SAFE_NO_PAD).map_err(|e| Error::Registration(e.to_string()))?;

        let client_data: ClientData =
            serde_json::from_slice(client_data_bytes.as_slice()).map_err(|e| Error::Registration(e.to_string()))?;

        let mut hasher = Sha256::new();

        hasher.update(client_data_bytes.as_slice());

        let challenge_hash = hasher.finalize_reset();

        hasher.update(&client_data.origin);

        let app_id_hash = hasher.finalize_reset();

        let signature_data = {
            let mut data = Vec::new();
            data.extend_from_slice(&app_id_hash);
            data.push(raw_u2f_sign.user_presence);
            data.extend_from_slice(&raw_u2f_sign.counter.to_le_bytes());
            data.extend_from_slice(&challenge_hash);
            data
        };

        let public_key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key);

        public_key.verify(signature_data.as_slice(), raw_u2f_sign.signature.as_slice())?;

        Ok((raw_u2f_sign.user_presence & 0x01) == 0x01)
    }
}
