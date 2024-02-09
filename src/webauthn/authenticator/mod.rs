pub(crate) mod responses;

use crate::webauthn::{
    authenticator::responses::AuthenticatorCredentialCreationResponse,
    error::Error,
    proto::{
        constants::{ECDAA_CURVE_ED25519, ECDSA_CURVE_P256, WEBAUTHN_FORMAT_NONE, WEBAUTHN_REQUEST_TYPE_CREATE},
        raw_message::{
            AttestationFlags, AttestationObject, AttestedCredentialData, AuthenticatorData, Coordinates, CoseAlgorithmIdentifier,
            CoseKeyInfo, CredentialPublicKey, Message, Rsa, EC2, OKP,
        },
        web_message::{
            CollectedClientData, PublicKeyCredentialCreationOptions, PublicKeyCredentialParameters, UserVerificationRequirement,
        },
    },
};
use base64::URL_SAFE_NO_PAD;
use ed25519_dalek::{SignatureError, Signer};
use hmac::digest::Digest;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
use serde_cbor::Value;
use sha2::Sha256;
use uuid::Uuid;

use crate::webauthn::{
    authenticator::responses::PrivateKeyResponse,
    proto::{
        constants::WEBAUTHN_REQUEST_TYPE_GET,
        web_message::{get_default_rp_id, AuthenticatorAttestationResponseRaw, PublicKeyCredentialRaw, PublicKeyCredentialRequestOptions},
    },
};
#[cfg(test)]
use crate::webauthn::{
    proto::web_message::{PublicKeyCredentialRpEntity, PublicKeyCredentialType, PublicKeyCredentialUserEntity},
    server::CredentialCreationVerifier,
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

pub struct WebauthnAuthenticator;

impl WebauthnAuthenticator {
    pub fn generate_credential_creation_response(
        credential_creation_options: PublicKeyCredentialCreationOptions,
        aaguid: Uuid,
        connection_id: Vec<u8>,
        origin: Option<String>,
        attestation_flags: u8,
    ) -> Result<AuthenticatorCredentialCreationResponse, WebauthnCredentialRequestError> {
        if credential_creation_options
            .authenticator_selection
            .as_ref()
            .and_then(|auth_selection| auth_selection.user_verification.as_ref())
            .filter(|user_verif| *user_verif == &UserVerificationRequirement::Required)
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
        let mut hasher = Sha256::new();
        hasher.update(rp_id);

        let alg = Self::find_best_supported_algorithm(&credential_creation_options.pub_key_cred_params)?;
        let (key_info, private_key_response) = match alg {
            CoseAlgorithmIdentifier::Ed25519 => {
                let keypair = ed25519_dalek::SigningKey::generate(&mut OsRng);
                let bytes = keypair.verifying_key().to_bytes();
                let private_key = PrivateKeyResponse {
                    private_key: keypair.to_bytes().to_vec(),
                    key_alg: alg.clone(),
                };
                (
                    CoseKeyInfo::OKP(OKP {
                        curve: ECDAA_CURVE_ED25519,
                        coords: Coordinates::Compressed {
                            y: if bytes[31] & 1 == 0 { 0x02 } else { 0x03 },
                            x: bytes,
                        },
                    }),
                    base64::encode(serde_cbor::to_vec(&private_key)?),
                )
            }

            CoseAlgorithmIdentifier::EC2 => {
                let secret_key = p256::SecretKey::random(&mut OsRng);
                let keypair = secret_key.public_key().to_encoded_point(false);
                let y = keypair.y().ok_or(WebauthnCredentialRequestError::CouldNotGenerateKey)?;
                let x = keypair.x().ok_or(WebauthnCredentialRequestError::CouldNotGenerateKey)?;
                let private_key = PrivateKeyResponse {
                    private_key: secret_key.to_bytes().to_vec(),
                    key_alg: alg.clone(),
                };
                (
                    CoseKeyInfo::EC2(EC2 {
                        curve: ECDSA_CURVE_P256,
                        coords: Coordinates::Uncompressed {
                            y: (*y).into(),
                            x: (*x).into(),
                        },
                    }),
                    base64::encode(serde_cbor::to_vec(&private_key)?),
                )
            }

            CoseAlgorithmIdentifier::RSA | CoseAlgorithmIdentifier::RS1 => {
                let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).map_err(|_| WebauthnCredentialRequestError::CouldNotGenerateKey)?;
                let private_key = PrivateKeyResponse {
                    private_key: key.to_pkcs1_der()?.to_bytes().to_vec(),
                    key_alg: alg.clone(),
                };
                (
                    CoseKeyInfo::RSA(Rsa {
                        n: key.n().to_bytes_be(),
                        e: key.e().to_bytes_be(),
                    }),
                    base64::encode(serde_cbor::to_vec(&private_key)?),
                )
            }

            _ => return Err(WebauthnCredentialRequestError::AlgorithmNotSupported),
        };

        let attested_credential_data = if attestation_flags & AttestationFlags::AttestedCredentialDataIncluded as u8 != 0 {
            Some(AttestedCredentialData {
                aaguid: aaguid.into_bytes(),
                credential_id: connection_id.clone(),
                credential_public_key: CredentialPublicKey {
                    key_type: key_info.key_type(),
                    alg: alg.into(),
                    key_info,
                },
            })
        } else {
            None
        };

        let attestation_object = AttestationObject {
            auth_data: AuthenticatorData {
                rp_id_hash: hasher
                    .finalize_reset()
                    .to_vec()
                    .try_into()
                    .map_err(|e: Vec<u8>| WebauthnCredentialRequestError::RpIdHashInvalidLength(e.len()))?,
                flags: attestation_flags,
                sign_count: 0,
                attested_credential_data,
                extensions: Value::Null,
            },
            raw_auth_data: vec![],
            fmt: WEBAUTHN_FORMAT_NONE.to_owned(),
            att_stmt: None,
        }
        .to_bytes()?;

        let challenge = base64::decode(credential_creation_options.challenge)?;
        let collected_client_data = CollectedClientData {
            request_type: WEBAUTHN_REQUEST_TYPE_CREATE.to_owned(),
            challenge: base64::encode_config(challenge, URL_SAFE_NO_PAD),
            origin: origin.as_ref().unwrap_or_else(|| &rp_id).clone(),
            cross_origin: false,
            token_binding: None,
        };

        let credential = PublicKeyCredentialRaw {
            id: base64::encode_config(connection_id.clone(), URL_SAFE_NO_PAD),
            raw_id: connection_id,
            response: Some(AuthenticatorAttestationResponseRaw {
                attestation_object: Some(attestation_object),
                client_data_json: serde_json::to_string(&collected_client_data)?.into_bytes(),
                authenticator_data: None,
                signature: None,
                user_handle: None,
            }),
        };

        Ok(AuthenticatorCredentialCreationResponse {
            credential_response: credential,
            private_key_response,
        })
    }

    pub fn generate_credential_request_response(
        connection_id: Vec<u8>,
        attestation_flags: u8,
        credential_request_options: PublicKeyCredentialRequestOptions,
        origin: Option<String>,
        private_key: String,
    ) -> Result<PublicKeyCredentialRaw, WebauthnCredentialRequestError> {
        if credential_request_options
            .user_verification
            .as_ref()
            .filter(|user_verif| *user_verif == &UserVerificationRequirement::Required)
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
        let mut hasher = Sha256::new();
        hasher.update(rp_id);

        let auth_data = AuthenticatorData {
            rp_id_hash: hasher
                .finalize_reset()
                .to_vec()
                .try_into()
                .map_err(|e: Vec<u8>| WebauthnCredentialRequestError::RpIdHashInvalidLength(e.len()))?,
            flags: attestation_flags,
            sign_count: 0,
            attested_credential_data: None,
            extensions: Value::Null,
        };
        let auth_data_bytes = auth_data.to_vec()?;

        let challenge = base64::decode(credential_request_options.challenge)?;
        let collected_client_data = CollectedClientData {
            request_type: WEBAUTHN_REQUEST_TYPE_GET.to_owned(),
            challenge: base64::encode_config(challenge, URL_SAFE_NO_PAD),
            origin: origin.as_ref().unwrap_or_else(|| &rp_id).clone(),
            cross_origin: false,
            token_binding: None,
        };
        let client_data_bytes = serde_json::to_string(&collected_client_data)?.into_bytes();

        let private_key_response: PrivateKeyResponse = serde_cbor::from_slice(&base64::decode(private_key)?)?;

        let signature = match private_key_response.key_alg {
            CoseAlgorithmIdentifier::Ed25519 => {
                let key = ed25519_dalek::SigningKey::try_from(private_key_response.private_key.as_slice())?;
                key.sign(
                    [auth_data_bytes.as_slice(), "||".as_bytes(), client_data_bytes.as_slice()]
                        .concat()
                        .as_slice(),
                )
                .to_vec()
            }
            CoseAlgorithmIdentifier::EC2 => Vec::new(),
            CoseAlgorithmIdentifier::RSA => Vec::new(),
            CoseAlgorithmIdentifier::RS1 => Vec::new(),
            CoseAlgorithmIdentifier::NotSupported => return Err(WebauthnCredentialRequestError::AlgorithmNotSupported),
        };

        Ok(PublicKeyCredentialRaw {
            id: base64::encode_config(connection_id.clone(), URL_SAFE_NO_PAD),
            raw_id: connection_id,
            response: Some(AuthenticatorAttestationResponseRaw {
                attestation_object: None,
                client_data_json: client_data_bytes,
                authenticator_data: Some(auth_data_bytes),
                signature: Some(signature),
                user_handle: None,
            }),
        })
    }

    fn find_best_supported_algorithm(
        pub_key_cred_params: &Vec<PublicKeyCredentialParameters>,
    ) -> Result<CoseAlgorithmIdentifier, WebauthnCredentialRequestError> {
        //Order of preference for credential type is: Ed25519 > EC2 > RSA > RS1
        let mut possible_credential_types = vec![
            CoseAlgorithmIdentifier::RS1,
            CoseAlgorithmIdentifier::RSA,
            CoseAlgorithmIdentifier::EC2,
            CoseAlgorithmIdentifier::Ed25519,
        ];

        let mut best_alg_index = None;
        let mut iterator = pub_key_cred_params.iter();
        while let Some(param) = iterator.next() {
            if let Some(alg_index) = possible_credential_types
                .iter()
                .position(|r| *r == CoseAlgorithmIdentifier::from(param.alg))
            {
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
        PublicKeyCredentialParameters {
            auth_type: PublicKeyCredentialType::PublicKey,
            alg: CoseAlgorithmIdentifier::Ed25519.into(),
        },
        PublicKeyCredentialParameters {
            auth_type: PublicKeyCredentialType::PublicKey,
            alg: CoseAlgorithmIdentifier::EC2.into(),
        },
        PublicKeyCredentialParameters {
            auth_type: PublicKeyCredentialType::PublicKey,
            alg: CoseAlgorithmIdentifier::RS1.into(),
        },
        PublicKeyCredentialParameters {
            auth_type: PublicKeyCredentialType::PublicKey,
            alg: CoseAlgorithmIdentifier::RSA.into(),
        },
    ];

    let alg = WebauthnAuthenticator::find_best_supported_algorithm(&params).unwrap();
    assert_eq!(alg, CoseAlgorithmIdentifier::Ed25519);

    let params2 = vec![
        PublicKeyCredentialParameters {
            auth_type: PublicKeyCredentialType::PublicKey,
            alg: CoseAlgorithmIdentifier::EC2.into(),
        },
        PublicKeyCredentialParameters {
            auth_type: PublicKeyCredentialType::PublicKey,
            alg: CoseAlgorithmIdentifier::RS1.into(),
        },
        PublicKeyCredentialParameters {
            auth_type: PublicKeyCredentialType::PublicKey,
            alg: CoseAlgorithmIdentifier::RSA.into(),
        },
    ];

    let alg = WebauthnAuthenticator::find_best_supported_algorithm(&params2).unwrap();
    assert_eq!(alg, CoseAlgorithmIdentifier::EC2);
}

#[test]
fn test_credential_generation() {
    let option = PublicKeyCredentialCreationOptions {
        challenge: "test".to_owned(),
        rp: PublicKeyCredentialRpEntity {
            id: Some("localhost".to_owned()),
            name: "localhost".to_owned(),
            icon: None,
        },
        user: PublicKeyCredentialUserEntity {
            id: Uuid::new_v4().to_string(),
            name: "test".to_owned(),
            display_name: "test".to_owned(),
            icon: None,
        },
        pub_key_cred_params: vec![PublicKeyCredentialParameters {
            auth_type: PublicKeyCredentialType::PublicKey,
            alg: CoseAlgorithmIdentifier::Ed25519.into(),
        }],
        timeout: None,
        exclude_credentials: vec![],
        authenticator_selection: None,
        attestation: None,
        extensions: None,
    };

    let credential = WebauthnAuthenticator::generate_credential_creation_response(
        option.clone(),
        Uuid::from_u128(0xDE503f9c_21a4_4f76_b4b7_558eb55c6f89),
        Uuid::new_v4().into_bytes().to_vec(),
        Some("http://localhost".to_owned()),
        AttestationFlags::AttestedCredentialDataIncluded as u8 + AttestationFlags::UserPresent as u8,
    );

    match credential {
        Ok(cred) => {
            let mut verifier = CredentialCreationVerifier::new(cred.credential_response.into(), option, "http://localhost");
            assert_eq!(verifier.verify().is_ok(), true)
        }
        Err(e) => {
            panic!("{e:?}")
        }
    }
}
