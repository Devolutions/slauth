pub(crate) mod responses;

#[cfg(feature = "native-bindings")]
pub(crate) mod native;

use crate::{
    base64::*,
    webauthn::{
        authenticator::responses::AuthenticatorCredentialCreationResponse,
        error::Error,
        proto::{
            constants::{ECDAA_CURVE_ED25519, ECDSA_CURVE_P256, WEBAUTHN_FORMAT_NONE, WEBAUTHN_REQUEST_TYPE_CREATE},
            raw_message::{
                AttestationFlags, AttestationObject, AttestedCredentialData, AuthenticatorData, Coordinates, CoseAlgorithmIdentifier,
                CoseKeyInfo, CredentialPublicKey, Message, Rsa, EC2, OKP,
            },
            web_message::{CollectedClientData, PublicKeyCredentialCreationOptions, UserVerificationRequirement},
        },
    },
};
use ed25519_dalek::{pkcs8::EncodePublicKey, SignatureError, Signer};
use hmac::digest::Digest;
use p256::ecdsa::VerifyingKey;
use rand_core::OsRng;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    signature::SignatureEncoding,
    traits::PublicKeyParts,
};
use serde_cbor::Value;
use sha2::Sha256;
use uuid::Uuid;

use crate::webauthn::{
    authenticator::responses::{AuthenticatorCredentialCreationResponseAdditionalData, PrivateKeyResponse},
    proto::{
        constants::WEBAUTHN_REQUEST_TYPE_GET,
        raw_message::AttestationStatement,
        web_message::{
            get_default_rp_id, AuthenticatorAttestationResponseRaw, PublicKeyCredentialRaw, PublicKeyCredentialRequestOptions, Transport,
        },
    },
};
#[cfg(test)]
use crate::webauthn::{
    proto::web_message::{
        Extensions, PublicKeyCredentialDescriptor, PublicKeyCredentialRpEntity, PublicKeyCredentialType, PublicKeyCredentialUserEntity,
    },
    server::{CredentialCreationVerifier, CredentialRequestVerifier},
};

#[derive(Debug)]
pub enum WebauthnCredentialRequestError {
    UserVerificationRequired,
    AlgorithmNotSupported,
    CouldNotGenerateKey,
    RpIdOrOriginRequired,
    RpIdHashInvalidLength(usize),
    SerdeJsonError(serde_json::Error),
    SerdeCborError(serde_cbor::Error),
    WebauthnError(Error),
    RsaError(rsa::pkcs1::Error),
    Base64Error(base64::DecodeError),
    Ed25519Error(ed25519_dalek::SignatureError),
    Ed25519SPKIError(ed25519_dalek::pkcs8::spki::Error),
}

impl From<serde_json::Error> for WebauthnCredentialRequestError {
    fn from(e: serde_json::Error) -> Self {
        WebauthnCredentialRequestError::SerdeJsonError(e)
    }
}

impl From<serde_cbor::Error> for WebauthnCredentialRequestError {
    fn from(e: serde_cbor::Error) -> Self {
        WebauthnCredentialRequestError::SerdeCborError(e)
    }
}

impl From<Error> for WebauthnCredentialRequestError {
    fn from(e: Error) -> Self {
        WebauthnCredentialRequestError::WebauthnError(e)
    }
}

impl From<rsa::pkcs1::Error> for WebauthnCredentialRequestError {
    fn from(value: rsa::pkcs1::Error) -> Self {
        WebauthnCredentialRequestError::RsaError(value)
    }
}

impl From<base64::DecodeError> for WebauthnCredentialRequestError {
    fn from(value: base64::DecodeError) -> Self {
        WebauthnCredentialRequestError::Base64Error(value)
    }
}

impl From<SignatureError> for WebauthnCredentialRequestError {
    fn from(value: SignatureError) -> Self {
        WebauthnCredentialRequestError::Ed25519Error(value)
    }
}

impl From<ed25519_dalek::pkcs8::spki::Error> for WebauthnCredentialRequestError {
    fn from(e: ed25519_dalek::pkcs8::spki::Error) -> Self {
        WebauthnCredentialRequestError::Ed25519SPKIError(e)
    }
}

pub struct WebauthnAuthenticator;

impl WebauthnAuthenticator {
    pub fn generate_credential_creation_response(
        credential_creation_options: PublicKeyCredentialCreationOptions,
        aaguid: Uuid,
        credential_id: Vec<u8>,
        origin: Option<String>,
        attestation_flags: u8,
    ) -> Result<AuthenticatorCredentialCreationResponse, WebauthnCredentialRequestError> {
        if credential_creation_options
            .authenticator_selection
            .as_ref()
            .and_then(|auth_selection| auth_selection.user_verification.as_ref())
            .filter(|user_verif| **user_verif == UserVerificationRequirement::Required)
            .is_some()
            && (attestation_flags & AttestationFlags::UserVerified as u8 == 0)
        {
            return Err(WebauthnCredentialRequestError::UserVerificationRequired);
        }

        let binding = origin.as_ref().map(|o| get_default_rp_id(o.as_str()));
        let rp_id = credential_creation_options
            .rp
            .id
            .as_ref()
            .or(binding.as_ref())
            .ok_or(WebauthnCredentialRequestError::RpIdOrOriginRequired)?;

        let algs: Vec<CoseAlgorithmIdentifier> = credential_creation_options
            .pub_key_cred_params
            .into_iter()
            .map(|x| x.alg.into())
            .collect();
        let alg = Self::find_best_supported_algorithm(algs.as_slice())?;

        let (attestation_object, private_key_response, der) =
            Self::generate_attestation_object(alg, aaguid, &credential_id, rp_id, attestation_flags)?;

        let challenge = match BASE64.decode(credential_creation_options.challenge.as_str()) {
            Ok(challenge) => challenge,
            Err(_) => BASE64_URLSAFE_NOPAD.decode(credential_creation_options.challenge)?,
        };

        let collected_client_data = CollectedClientData {
            request_type: WEBAUTHN_REQUEST_TYPE_CREATE.to_owned(),
            challenge: BASE64_URLSAFE_NOPAD.encode(challenge),
            origin: origin.as_ref().unwrap_or(rp_id).clone(),
            cross_origin: false,
            token_binding: None,
        };

        let auth_data = attestation_object.auth_data.clone();
        let credential = PublicKeyCredentialRaw {
            id: BASE64_URLSAFE_NOPAD.encode(credential_id.clone()),
            raw_id: credential_id,
            response: Some(AuthenticatorAttestationResponseRaw {
                attestation_object: Some(attestation_object.to_bytes()?),
                client_data_json: serde_json::to_string(&collected_client_data)?.into_bytes(),
                authenticator_data: auth_data.to_vec().ok(),
                signature: None,
                user_handle: None,
                transports: vec![Transport::Internal],
            }),
        };

        Ok(AuthenticatorCredentialCreationResponse {
            credential_response: credential,
            private_key_response,
            additional_data: AuthenticatorCredentialCreationResponseAdditionalData {
                public_key_der: der,
                public_key_alg: alg.into(),
            },
        })
    }

    pub fn generate_attestation_object(
        alg: CoseAlgorithmIdentifier,
        aaguid: Uuid,
        credential_id: &[u8],
        rp_id: &str,
        attestation_flags: u8,
    ) -> Result<(AttestationObject, String, Vec<u8>), WebauthnCredentialRequestError> {
        let (key_info, private_key_response, der) = match alg {
            CoseAlgorithmIdentifier::Ed25519 => {
                let keypair = ed25519_dalek::SigningKey::generate(&mut OsRng);
                let bytes = keypair.verifying_key().to_bytes();
                let private_key = PrivateKeyResponse {
                    private_key: keypair.to_bytes().to_vec(),
                    key_alg: alg,
                };
                (
                    CoseKeyInfo::OKP(OKP {
                        curve: ECDAA_CURVE_ED25519,
                        coords: Coordinates::Compressed {
                            y: if bytes[31] & 1 == 0 { 0x02 } else { 0x03 },
                            x: bytes,
                        },
                    }),
                    BASE64.encode(serde_cbor::to_vec(&private_key)?),
                    keypair.verifying_key().to_public_key_der()?.to_vec(),
                )
            }

            CoseAlgorithmIdentifier::ES256 => {
                let secret_key = p256::ecdsa::SigningKey::random(&mut OsRng);
                let verifying_key = VerifyingKey::from(&secret_key);
                let points = verifying_key.to_encoded_point(false);
                let y = points.y().ok_or(WebauthnCredentialRequestError::CouldNotGenerateKey)?;
                let x = points.x().ok_or(WebauthnCredentialRequestError::CouldNotGenerateKey)?;
                let private_key = PrivateKeyResponse {
                    private_key: secret_key.to_bytes().to_vec(),
                    key_alg: alg,
                };
                (
                    CoseKeyInfo::EC2(EC2 {
                        curve: ECDSA_CURVE_P256,
                        coords: Coordinates::Uncompressed {
                            y: (*y).into(),
                            x: (*x).into(),
                        },
                    }),
                    BASE64.encode(serde_cbor::to_vec(&private_key)?),
                    verifying_key.to_public_key_der()?.to_vec(),
                )
            }

            CoseAlgorithmIdentifier::RSA => {
                let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).map_err(|_| WebauthnCredentialRequestError::CouldNotGenerateKey)?;
                let private_key = PrivateKeyResponse {
                    private_key: key.to_pkcs1_der()?.to_bytes().to_vec(),
                    key_alg: alg,
                };
                (
                    CoseKeyInfo::RSA(Rsa {
                        n: key.n().to_bytes_be(),
                        e: key.e().to_bytes_be(),
                    }),
                    BASE64.encode(serde_cbor::to_vec(&private_key)?),
                    key.to_public_key().to_public_key_der()?.to_vec(),
                )
            }

            _ => return Err(WebauthnCredentialRequestError::AlgorithmNotSupported),
        };

        let attested_credential_data = if attestation_flags & AttestationFlags::AttestedCredentialDataIncluded as u8 != 0 {
            Some(AttestedCredentialData {
                aaguid: aaguid.into_bytes(),
                credential_id: credential_id.to_owned(),
                credential_public_key: CredentialPublicKey {
                    key_type: key_info.key_type(),
                    alg: alg.into(),
                    key_info,
                },
            })
        } else {
            None
        };

        let auth_data = Self::generate_authenticator_data(rp_id, attestation_flags, attested_credential_data)?;

        Ok((
            AttestationObject {
                auth_data: auth_data.clone(),
                raw_auth_data: vec![],
                fmt: WEBAUTHN_FORMAT_NONE.to_owned(),
                att_stmt: Some(AttestationStatement::None),
            },
            private_key_response,
            der,
        ))
    }

    pub fn generate_credential_request_response(
        credential_id: Vec<u8>,
        attestation_flags: u8,
        credential_request_options: PublicKeyCredentialRequestOptions,
        origin: Option<String>,
        user_handle: Option<Vec<u8>>,
        private_key: String,
    ) -> Result<PublicKeyCredentialRaw, WebauthnCredentialRequestError> {
        if credential_request_options
            .user_verification
            .as_ref()
            .filter(|user_verif| **user_verif == UserVerificationRequirement::Required)
            .is_some()
            && (attestation_flags & AttestationFlags::UserVerified as u8 == 0)
        {
            return Err(WebauthnCredentialRequestError::UserVerificationRequired);
        }

        let binding = origin.as_ref().map(|o| get_default_rp_id(o.as_str()));
        let rp_id = credential_request_options
            .rp_id
            .as_ref()
            .or(binding.as_ref())
            .ok_or(WebauthnCredentialRequestError::RpIdOrOriginRequired)?;

        let auth_data_bytes = Self::generate_authenticator_data(rp_id, attestation_flags, None)?.to_vec()?;

        let challenge = BASE64
            .decode(credential_request_options.challenge.as_str())
            .or(BASE64_URLSAFE_NOPAD.decode(credential_request_options.challenge))?;
        let collected_client_data = CollectedClientData {
            request_type: WEBAUTHN_REQUEST_TYPE_GET.to_owned(),
            challenge: BASE64_URLSAFE_NOPAD.encode(challenge),
            origin: origin.as_ref().unwrap_or(rp_id).clone(),
            cross_origin: false,
            token_binding: None,
        };
        let client_data_bytes = serde_json::to_string(&collected_client_data)?.into_bytes();
        let mut hasher = Sha256::new();
        hasher.update(client_data_bytes.as_slice());
        let hash = hasher.finalize_reset().to_vec();

        let signature = Self::generate_signature(auth_data_bytes.as_slice(), hash.as_slice(), private_key)?;

        Ok(PublicKeyCredentialRaw {
            id: BASE64_URLSAFE_NOPAD.encode(credential_id.clone()),
            raw_id: credential_id,
            response: Some(AuthenticatorAttestationResponseRaw {
                attestation_object: None,
                client_data_json: client_data_bytes,
                authenticator_data: Some(auth_data_bytes),
                signature: Some(signature),
                user_handle,
                transports: vec![Transport::Internal],
            }),
        })
    }

    pub fn generate_authenticator_data(
        rp_id: &str,
        attestation_flags: u8,
        attested_credential_data: Option<AttestedCredentialData>,
    ) -> Result<AuthenticatorData, WebauthnCredentialRequestError> {
        let mut hasher = Sha256::new();
        hasher.update(rp_id);

        Ok(AuthenticatorData {
            rp_id_hash: hasher
                .finalize_reset()
                .to_vec()
                .try_into()
                .map_err(|e: Vec<u8>| WebauthnCredentialRequestError::RpIdHashInvalidLength(e.len()))?,
            flags: attestation_flags,
            sign_count: 0,
            attested_credential_data,
            extensions: Value::Null,
        })
    }

    pub fn generate_signature(
        auth_data_bytes: &[u8],
        client_data_hash: &[u8],
        private_key: String,
    ) -> Result<Vec<u8>, WebauthnCredentialRequestError> {
        let private_key_response: PrivateKeyResponse = serde_cbor::from_slice(
            &BASE64
                .decode(private_key.as_str())
                .or(BASE64_URLSAFE_NOPAD.decode(private_key.as_str()))?,
        )?;

        match private_key_response.key_alg {
            CoseAlgorithmIdentifier::Ed25519 => {
                let key = ed25519_dalek::SigningKey::try_from(private_key_response.private_key.as_slice())?;
                Ok(key.sign([auth_data_bytes, client_data_hash].concat().as_slice()).to_vec())
            }
            CoseAlgorithmIdentifier::ES256 => {
                let key = p256::ecdsa::SigningKey::try_from(private_key_response.private_key.as_slice())?;
                let (sig, _) = key.sign([auth_data_bytes, client_data_hash].concat().as_slice());
                Ok(sig.to_der().to_vec())
            }
            CoseAlgorithmIdentifier::RSA => {
                let key = rsa::RsaPrivateKey::from_pkcs1_der(&private_key_response.private_key)?;
                let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key);
                Ok(signing_key.sign([auth_data_bytes, client_data_hash].concat().as_slice()).to_vec())
            }
            _ => Err(WebauthnCredentialRequestError::AlgorithmNotSupported),
        }
    }

    fn find_best_supported_algorithm(
        pub_key_cred_params: &[CoseAlgorithmIdentifier],
    ) -> Result<CoseAlgorithmIdentifier, WebauthnCredentialRequestError> {
        //Order of preference for credential type is: Ed25519 > EC2 > RSA > RS1
        let mut possible_credential_types = vec![
            CoseAlgorithmIdentifier::RSA,
            CoseAlgorithmIdentifier::ES256,
            CoseAlgorithmIdentifier::Ed25519,
        ];

        let mut best_alg_index = None;
        let iterator = pub_key_cred_params.iter();
        for param in iterator {
            if let Some(alg_index) = possible_credential_types.iter().position(|r| r == param) {
                if best_alg_index.filter(|x| x > &alg_index).is_none() {
                    best_alg_index = Some(alg_index);
                }

                if alg_index == possible_credential_types.len() - 1 {
                    break;
                }
            }
        }

        match best_alg_index {
            None => Err(WebauthnCredentialRequestError::AlgorithmNotSupported),
            Some(index) => Ok(possible_credential_types.remove(index)),
        }
    }
}

#[test]
fn test_best_alg() {
    let params = vec![
        CoseAlgorithmIdentifier::Ed25519,
        CoseAlgorithmIdentifier::ES256,
        CoseAlgorithmIdentifier::RS1,
        CoseAlgorithmIdentifier::RSA,
    ];

    let alg = WebauthnAuthenticator::find_best_supported_algorithm(&params).unwrap();
    assert_eq!(alg, CoseAlgorithmIdentifier::Ed25519);

    let params2 = vec![
        CoseAlgorithmIdentifier::ES256,
        CoseAlgorithmIdentifier::RS1,
        CoseAlgorithmIdentifier::RSA,
    ];

    let alg = WebauthnAuthenticator::find_best_supported_algorithm(&params2).unwrap();
    assert_eq!(alg, CoseAlgorithmIdentifier::ES256);
}

#[test]
fn test_credential_generation() {
    for alg in [
        CoseAlgorithmIdentifier::Ed25519,
        CoseAlgorithmIdentifier::ES256,
        CoseAlgorithmIdentifier::RSA,
    ] {
        let user_uuid = Uuid::new_v4();
        let option = PublicKeyCredentialCreationOptions {
            challenge: "test".to_owned(),
            rp: PublicKeyCredentialRpEntity {
                id: Some("localhost".to_owned()),
                name: "localhost".to_owned(),
                icon: None,
            },
            user: PublicKeyCredentialUserEntity {
                id: user_uuid.to_string(),
                name: "test".to_owned(),
                display_name: "test".to_owned(),
                icon: None,
            },
            pub_key_cred_params: vec![crate::webauthn::proto::web_message::PublicKeyCredentialParameters {
                auth_type: PublicKeyCredentialType::PublicKey,
                alg: alg.into(),
            }],
            timeout: None,
            exclude_credentials: vec![],
            authenticator_selection: None,
            attestation: None,
            extensions: Extensions::default(),
        };

        let cred_uuid = Uuid::new_v4().into_bytes().to_vec();
        let credential = WebauthnAuthenticator::generate_credential_creation_response(
            option.clone(),
            Uuid::from_u128(0xde503f9c_21a4_4f76_b4b7_558eb55c6f89),
            cred_uuid.clone(),
            Some("http://localhost".to_owned()),
            AttestationFlags::AttestedCredentialDataIncluded as u8 + AttestationFlags::UserPresent as u8,
        );

        match credential {
            Ok(cred) => {
                let mut verifier = CredentialCreationVerifier::new(cred.credential_response.into(), option, "http://localhost");
                let verif_res = verifier.verify();
                assert!(verif_res.is_ok());

                let req_option = PublicKeyCredentialRequestOptions {
                    challenge: "test".to_owned(),
                    timeout: None,
                    rp_id: Some("localhost".to_owned()),
                    allow_credentials: vec![PublicKeyCredentialDescriptor {
                        cred_type: PublicKeyCredentialType::PublicKey,
                        id: BASE64_URLSAFE_NOPAD.encode(&cred_uuid),
                        transports: None,
                    }],
                    extensions: Extensions::default(),
                    user_verification: None,
                };

                let req_credential = WebauthnAuthenticator::generate_credential_request_response(
                    cred_uuid,
                    AttestationFlags::UserVerified as u8 + AttestationFlags::UserPresent as u8,
                    req_option.clone(),
                    Some("http://localhost".to_owned()),
                    Some(user_uuid.into_bytes().to_vec()),
                    cred.private_key_response,
                )
                .unwrap();

                let mut req_verifier = CredentialRequestVerifier::new(
                    req_credential.into(),
                    verif_res.unwrap().public_key,
                    req_option,
                    "http://localhost",
                    user_uuid.as_bytes().as_slice(),
                    0,
                );
                assert!(req_verifier.verify().is_ok())
            }
            Err(e) => {
                panic!("{e:?}")
            }
        }
    }
}
