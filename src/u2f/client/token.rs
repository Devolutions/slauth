use std::io::Read;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ring::{
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
            VersionResponse,
        },
    },
};
use crate::u2f::client::SigningKey;
use crate::u2f::proto::raw_message::Message;

pub(crate) fn gen_key_handle(app_id: &[u8], chall: &[u8]) -> String {
    let mut data = Vec::with_capacity(app_id.len() + chall.len());
    data.extend_from_slice(app_id);
    data.extend_from_slice(chall);
    base32::encode(base32::Alphabet::RFC4648 { padding: false }, &data)
}

pub fn register(req: RegisterRequest, attestation_cert: &[u8], attestation_key: &[u8]) -> Result<(RegisterResponse, SigningKey), Error> {
    let RegisterRequest {
        challenge,
        application,
    } = req;

    // Generate a key pair in PKCS#8 (v2) format.
    let rng = rand::SystemRandom::new();
    let registered_key_pkcs8_doc = signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)?;

    let registered_key_pkcs8_bytes = registered_key_pkcs8_doc.as_ref();

    let key_handle = gen_key_handle(&application, &challenge);

    let registered_key_pair = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, registered_key_pkcs8_bytes)?;
    let registered_pub_key = registered_key_pair.public_key();
    let mut user_public_key = [0u8; U2F_EC_POINT_SIZE];

    registered_pub_key.as_ref().read_exact(&mut user_public_key)?;

    let key_handle_length = key_handle.len() as u8;

    let mut tbs_vec = Vec::with_capacity(U2F_REGISTER_MAX_DATA_TBS_SIZE);

    tbs_vec.push(0x00);
    tbs_vec.extend_from_slice(&application);
    tbs_vec.extend_from_slice(&challenge);
    tbs_vec.extend_from_slice(key_handle.as_bytes());
    tbs_vec.extend_from_slice(&user_public_key);

    let att_key_pair = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, attestation_key)?;

    let sig = att_key_pair.sign(&rng, tbs_vec.as_slice())?;

    let signature = sig.as_ref().to_vec();

    Ok(
        (
            RegisterResponse {
                reserved: U2F_REGISTER_ID,
                user_public_key,
                key_handle_length,
                key_handle: key_handle.clone(),
                attestation_cert: attestation_cert.to_vec(),
                signature,
            },
            SigningKey {
                key_handle,
                private_key: registered_key_pkcs8_bytes.to_vec(),
            }
        )
    )
}

pub fn sign(req: AuthenticateRequest, signing_key: &SigningKey, counter: u32, user_presence: bool) -> Result<AuthenticateResponse, Error> {
    let AuthenticateRequest {
        control,
        challenge,
        application,
        ..
    } = req;

    if !user_presence && control == U2F_AUTH_ENFORCE {
        return Err(Error::U2FErrorCode(U2F_SW_CONDITIONS_NOT_SATISFIED));
    }

    let user_presence = if user_presence { U2F_AUTH_FLAG_TUP } else { U2F_AUTH_FLAG_TDOWN };

    match control {
        U2F_AUTH_CHECK_ONLY => {
            Err(Error::U2FErrorCode(U2F_SW_CONDITIONS_NOT_SATISFIED))
        }
        U2F_AUTH_ENFORCE | U2F_AUTH_DONT_ENFORCE => {
            let rng = rand::SystemRandom::new();
            let key_pair = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, signing_key.private_key.as_slice())?;

            let mut tbs_vec = Vec::with_capacity(U2F_AUTH_MAX_DATA_TBS_SIZE);
            tbs_vec.extend_from_slice(&application);
            tbs_vec.push(user_presence);
            tbs_vec.extend_from_slice(&counter.to_be_bytes());
            tbs_vec.extend_from_slice(&challenge);

            let sig = key_pair.sign(&rng, tbs_vec.as_slice())?;
            let signature = sig.as_ref().to_vec();

            Ok(AuthenticateResponse {
                user_presence,
                counter,
                signature,
            })
        }
        _ => {
            Err(Error::U2FErrorCode(U2F_SW_INS_NOT_SUPPORTED))
        }
    }
}

pub struct U2FSToken {
    pub(crate) store: Box<dyn KeyStore>,
    pub(crate) presence_validator: Box<dyn PresenceValidator>,
    pub(crate) counter: AtomicU32,
}

impl U2FSToken {
    pub fn handle_apdu_request_with_timeout(&self, req: apdu::Request, timeout: Option<Duration>) -> apdu::Response {
        let res = match req.command_mode {
            U2F_REGISTER => {
                RegisterRequest::from_apdu(req).and_then(|reg| self.register(reg, timeout).and_then(|rsp| rsp.into_apdu()))
            }
            U2F_AUTHENTICATE => {
                AuthenticateRequest::from_apdu(req).and_then(|auth| self.authenticate(auth, timeout).and_then(|rsp| rsp.into_apdu()))
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

    pub fn handle_apdu_request(&self, req: apdu::Request) -> apdu::Response {
        self.handle_apdu_request_with_timeout(req, Some(Duration::from_secs(10)))
    }

    fn register(&self, req: RegisterRequest, timeout: Option<Duration>) -> Result<RegisterResponse, Error> {
        if self.presence_validator.check_user_presence(timeout.unwrap_or_else(|| Duration::from_secs(10))) {
            let (rsp, signing_key) = register(req, self.store.attestation_cert(), self.store.attestation_key())?;

            if self.store.save(signing_key.key_handle, signing_key.private_key) {
                Ok(rsp)
            } else {
                Err(Error::Other("U2F Register: Unable to save private key".to_string()))
            }
        } else {
            Err(Error::U2FErrorCode(U2F_SW_CONDITIONS_NOT_SATISFIED))
        }
    }

    fn authenticate(&self, req: AuthenticateRequest, timeout: Option<Duration>) -> Result<AuthenticateResponse, Error> {
        let expected_key_handle = String::from_utf8_lossy(req.key_handle.as_slice()).to_string();

        if let Some(pk_bytes) = self.store.load(expected_key_handle.as_str()) {
            return sign(
                req,
                &SigningKey {
                    key_handle: expected_key_handle,
                    private_key: pk_bytes.to_vec(),
                },
                self.counter.fetch_add(1, Ordering::Relaxed),
                self.presence_validator.check_user_presence(timeout.unwrap_or_else(|| Duration::from_secs(10))),
            );
        }

        Err(Error::U2FErrorCode(U2F_SW_WRONG_DATA))
    }

    fn version(&self, _: VersionRequest) -> VersionResponse {
        VersionResponse {
            version: U2F_V2_VERSION_STR.to_string()
        }
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