use std::io::Read;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ring::{
    digest,
    rand,
    signature::{self, KeyPair},
};

use crate::u2f::{
    error::Error,
    proto::{
        constants::*,
        raw_message::{
            apdu,
            AuthenticateRequest,
            AuthenticateResponse,
            RegisterRequest,
            RegisterResponse,
            VersionRequest,
            VersionResponse
        }
    },
};
use crate::u2f::proto::raw_message::Message;

pub struct U2FSToken {
    pub(crate) store: Box<KeyStore>,
    pub(crate) presence_validator: Box<PresenceValidator>,
    pub(crate) counter: AtomicU32,
}

impl U2FSToken {
    pub fn handle_apdu_request(&self, req: apdu::Request) -> apdu::Response {
        let res = match req.command_mode {
            U2F_REGISTER => {
                RegisterRequest::from_apdu(req).and_then(|reg| self.register(reg).and_then(|rsp| rsp.into_apdu()))
            }
            U2F_AUTHENTICATE => {
                AuthenticateRequest::from_apdu(req).and_then(|auth| self.authenticate(auth).and_then(|rsp| rsp.into_apdu()))
            }
            U2F_VERSION => {
                VersionRequest::from_apdu(req).and_then(|vers| self.version(vers).into_apdu())
            }
            com if com >= U2F_VENDOR_FIRST && com <= U2F_VENDOR_LAST => {
                Err(Error::U2FErrorCode(U2F_SW_INS_NOT_SUPPORTED))
            }
            _ => {
                Err(Error::U2FErrorCode(U2F_SW_COMMAND_NOT_ALLOWED))
            }
        };

        match res {
            Ok(rsp) => rsp,
            Err(e) => {
                match e {
                    Error::U2FErrorCode(sw) => apdu::Response::from_status(sw),
                    _ => apdu::Response::from_status(U2F_SW_WRONG_LENGTH),
                }
            }
        }
    }

    fn register(&self, req: RegisterRequest) -> Result<RegisterResponse, Error> {
        let RegisterRequest {
            challenge,
            application,
        } = req;

        if self.presence_validator.check_user_presence(Duration::from_secs(10)) {
            // Generate a key pair in PKCS#8 (v2) format.
            let rng = rand::SystemRandom::new();
            let pkcs8_doc = signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)?;

            let pkcs8_bytes = pkcs8_doc.as_ref();

            let key_handle = Self::gen_key_handle(&application, &challenge);

            if self.store.save(key_handle.clone(), pkcs8_bytes.to_vec()) {
                let key_pair = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, untrusted::Input::from(pkcs8_bytes))?;
                let pub_key = key_pair.public_key();
                let mut user_public_key = [0u8; U2F_EC_POINT_SIZE];

                pub_key.as_ref().read_exact(&mut user_public_key)?;

                let key_handle_lenght = key_handle.len() as u8;

                let mut tbs_vec = Vec::with_capacity(U2F_REGISTER_MAX_DATA_TBS_SIZE);

                tbs_vec.push(0x00);
                tbs_vec.extend_from_slice(&application);
                tbs_vec.extend_from_slice(&challenge);
                tbs_vec.extend_from_slice(key_handle.as_bytes());
                tbs_vec.extend_from_slice(&user_public_key);

                let sign_input = untrusted::Input::from(tbs_vec.as_slice());

                let att_key_pair = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, untrusted::Input::from(self.store.attestation_key()))?;

                let sig = att_key_pair.sign(&rng, sign_input)?;

                let signature = sig.as_ref().to_vec();

                Ok(RegisterResponse {
                    reserved: U2F_REGISTER_ID,
                    user_public_key,
                    key_handle_lenght,
                    key_handle,
                    attestation_cert: self.store.attestation_cert().to_vec(),
                    signature,
                })
            } else {
                Err(Error::Other("U2F Register: Unable to save private key".to_string()))
            }
        } else {
            Err(Error::U2FErrorCode(U2F_SW_CONDITIONS_NOT_SATISFIED))
        }
    }

    fn authenticate(&self, req: AuthenticateRequest) -> Result<AuthenticateResponse, Error> {
        let AuthenticateRequest {
            control,
            challenge,
            application,
            key_h_len,
            key_handle,
        } = req;

        let str_key_handle = String::from_utf8_lossy(key_handle.as_slice());
        let expected_key_handle = Self::gen_key_handle(&application, &challenge);

        match control {
            U2F_AUTH_CHECK_ONLY => {
                if str_key_handle == expected_key_handle && self.store.contains(str_key_handle.as_ref()) {
                    return Err(Error::U2FErrorCode(U2F_SW_CONDITIONS_NOT_SATISFIED));
                }

                Err(Error::U2FErrorCode(U2F_SW_WRONG_DATA))
            }
            U2F_AUTH_ENFORCE => {
                if self.presence_validator.check_user_presence(Duration::from_secs(10)) {
                    let user_presence = U2F_AUTH_FLAG_TUP;
                    let counter = self.counter.fetch_add(1, Ordering::SeqCst);

                    if str_key_handle == expected_key_handle {
                        if let Some(pk_bytes) = self.store.load(str_key_handle.as_ref()) {
                            let rng = rand::SystemRandom::new();
                            let key_pair = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, untrusted::Input::from(pk_bytes))?;

                            let mut tbs_vec = Vec::with_capacity(U2F_AUTH_MAX_DATA_TBS_SIZE);

                            tbs_vec.extend_from_slice(&application);
                            tbs_vec.push(user_presence);
                            tbs_vec.extend_from_slice(&counter.to_be_bytes());
                            tbs_vec.extend_from_slice(&challenge);

                            let sign_input = untrusted::Input::from(tbs_vec.as_slice());

                            let sig = key_pair.sign(&rng, sign_input)?;

                            let signature = sig.as_ref().to_vec();

                            return Ok(AuthenticateResponse {
                                user_presence,
                                counter,
                                signature,
                            });
                        }
                    }

                    Err(Error::U2FErrorCode(U2F_SW_WRONG_DATA))
                } else {
                    Err(Error::U2FErrorCode(U2F_SW_CONDITIONS_NOT_SATISFIED))
                }
            }
            U2F_AUTH_DONT_ENFORCE => {
                let user_presence = U2F_AUTH_FLAG_TDOWN;
                let counter = self.counter.fetch_add(1, Ordering::SeqCst);

                if str_key_handle == expected_key_handle {
                    if let Some(pk_bytes) = self.store.load(str_key_handle.as_ref()) {
                        let rng = rand::SystemRandom::new();
                        let key_pair = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, untrusted::Input::from(pk_bytes))?;

                        let mut tbs_vec = Vec::with_capacity(U2F_AUTH_MAX_DATA_TBS_SIZE);

                        tbs_vec.extend_from_slice(&application);
                        tbs_vec.push(user_presence);
                        tbs_vec.extend_from_slice(&counter.to_be_bytes());
                        tbs_vec.extend_from_slice(&challenge);

                        let sign_input = untrusted::Input::from(tbs_vec.as_slice());

                        let sig = key_pair.sign(&rng, sign_input)?;

                        let signature = sig.as_ref().to_vec();

                        return Ok(AuthenticateResponse {
                            user_presence,
                            counter,
                            signature,
                        });
                    }
                }

                Err(Error::U2FErrorCode(U2F_SW_WRONG_DATA))
            }
            _ => {
                Err(Error::U2FErrorCode(U2F_SW_INS_NOT_SUPPORTED))
            }
        }
    }

    fn version(&self, _: VersionRequest) -> VersionResponse {
        VersionResponse {
            version: U2F_V2_VERSION_STR.to_string()
        }
    }

    fn gen_key_handle(app_id: &[u8], chall: &[u8]) -> String {
        let mut data = Vec::with_capacity(app_id.len() + chall.len());
        data.extend_from_slice(app_id);
        data.extend_from_slice(chall);
        format!("{:x?}", digest::digest(&digest::SHA512, data.as_slice()).as_ref())
    }
}

pub trait KeyStore {
    fn contains(&self, handle: &str) -> bool;
    fn load(&self, handle: &str) -> Option<&[u8]>;
    fn save(&self, handle: String, key: Vec<u8>) -> bool;
    fn attestation_cert(&self) -> &[u8];
    fn attestation_key(&self) -> &[u8];
}

pub trait PresenceValidator {
    fn check_user_presence(&self, timeout: Duration) -> bool;
}