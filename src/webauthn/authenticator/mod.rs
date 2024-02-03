mod responses;

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
            AuthenticatorAttestationResponse, CollectedClientData, PublicKeyCredential, PublicKeyCredentialCreationOptions,
            PublicKeyCredentialParameters, UserVerificationRequirement,
        },
    },
};
use hmac::digest::Digest;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use serde_cbor::Value;
use sha2::Sha256;
use uuid::Uuid;

#[cfg(test)]
use crate::webauthn::{
    proto::web_message::{PublicKeyCredentialRpEntity, PublicKeyCredentialType, PublicKeyCredentialUserEntity},
    server::CredentialCreationVerifier,
};

//String Reprensentation of the AAGUID: DE503f9-c21a-4f76-b4b7-558eb55c6f89
pub const AAGUID: Uuid = Uuid::from_u128(0xDE503f9c_21a4_4f76_b4b7_558eb55c6f89);

#[derive(Debug)]
pub enum WebauthnCredentialCreationError {
    UserVerificationRequired,
    AlgorithmNotSupported,
    CouldNotGenerateKey,
    RpIdOrOriginRequired,
    RpIdHashInvalidLength(usize),
    SerdeError(serde_json::Error),
    WebauthnError(Error),
}

impl From<serde_json::Error> for WebauthnCredentialCreationError {
    fn from(e: serde_json::Error) -> Self {
        WebauthnCredentialCreationError::SerdeError(e)
    }
}

impl From<Error> for WebauthnCredentialCreationError {
    fn from(e: Error) -> Self {
        WebauthnCredentialCreationError::WebauthnError(e)
    }
}

pub struct WebauthnAuthenticator;

impl WebauthnAuthenticator {
    pub fn generate_credential_response(
        credential_creation_options: PublicKeyCredentialCreationOptions,
        connection_id: String,
        origin: Option<String>,
        attestation_flags: Vec<AttestationFlags>,
    ) -> Result<AuthenticatorCredentialCreationResponse, WebauthnCredentialCreationError> {
        if credential_creation_options
            .authenticator_selection
            .as_ref()
            .and_then(|auth_selection| auth_selection.user_verification.as_ref())
            .filter(|user_verif| *user_verif == &UserVerificationRequirement::Required)
            .is_some()
            && !attestation_flags.contains(&AttestationFlags::UserVerified)
        {
            return Err(WebauthnCredentialCreationError::UserVerificationRequired);
        }

        let rp_id = credential_creation_options
            .rp
            .id
            .as_ref()
            .or(origin.as_ref())
            .ok_or(WebauthnCredentialCreationError::RpIdOrOriginRequired)?;
        let mut hasher = Sha256::new();
        hasher.update(rp_id);

        let alg = Self::find_best_supported_algorithm(&credential_creation_options.pub_key_cred_params)?;
        let (key_info, private_key) = match alg {
            CoseAlgorithmIdentifier::Ed25519 => {
                let keypair = ed25519_dalek::SigningKey::generate(&mut OsRng);
                let bytes = keypair.verifying_key().to_bytes();
                (
                    CoseKeyInfo::OKP(OKP {
                        curve: ECDAA_CURVE_ED25519,
                        coords: Coordinates::Compressed {
                            y: if bytes[31] & 1 == 0 { 0x02 } else { 0x03 },
                            x: bytes,
                        },
                    }),
                    base64::encode(keypair.to_bytes()),
                )
            }

            CoseAlgorithmIdentifier::EC2 => {
                let secret_key = p256::SecretKey::random(&mut OsRng);
                let keypair = secret_key.public_key().to_encoded_point(false);
                let y = keypair.y().ok_or(WebauthnCredentialCreationError::CouldNotGenerateKey)?;
                let x = keypair.x().ok_or(WebauthnCredentialCreationError::CouldNotGenerateKey)?;
                (
                    CoseKeyInfo::EC2(EC2 {
                        curve: ECDSA_CURVE_P256,
                        coords: Coordinates::Uncompressed {
                            y: (*y).into(),
                            x: (*x).into(),
                        },
                    }),
                    base64::encode(keypair.to_bytes()),
                )
            }

            CoseAlgorithmIdentifier::RSA | CoseAlgorithmIdentifier::RS1 => {
                let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).map_err(|_| WebauthnCredentialCreationError::CouldNotGenerateKey)?;
                (
                    CoseKeyInfo::RSA(Rsa {
                        n: key.n().to_bytes_be(),
                        e: key.e().to_bytes_be(),
                    }),
                    base64::encode(key.d().to_bytes_be()),
                )
            }

            _ => return Err(WebauthnCredentialCreationError::AlgorithmNotSupported),
        };

        let attested_credential_data = if attestation_flags.contains(&AttestationFlags::AttestedCredentialDataIncluded) {
            Some(AttestedCredentialData {
                aaguid: AAGUID.into_bytes(),
                credential_id: connection_id.clone().into_bytes(),
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
                    .map_err(|e: Vec<u8>| WebauthnCredentialCreationError::RpIdHashInvalidLength(e.len()))?,
                flags: attestation_flags.into_iter().map(|f| f as u8).sum(),
                sign_count: 0,
                attested_credential_data,
                extensions: Value::Null,
            },
            raw_auth_data: vec![],
            fmt: WEBAUTHN_FORMAT_NONE.to_owned(),
            att_stmt: None,
        }
        .to_bytes()?;

        let collected_client_data = CollectedClientData {
            request_type: WEBAUTHN_REQUEST_TYPE_CREATE.to_owned(),
            challenge: credential_creation_options.challenge,
            origin: origin.as_ref().unwrap_or_else(|| &rp_id).clone(),
            cross_origin: false,
            token_binding: None,
        };

        let credential = PublicKeyCredential {
            id: connection_id,
            response: Some(AuthenticatorAttestationResponse {
                attestation_object: Some(base64::encode(attestation_object)),
                client_data_json: base64::encode(serde_json::to_string(&collected_client_data)?.into_bytes()),
                authenticator_data: None,
                signature: None,
                user_handle: None,
            }),
        };

        Ok(AuthenticatorCredentialCreationResponse {
            credential_response: credential,
            private_key,
        })
    }

    fn find_best_supported_algorithm(
        pub_key_cred_params: &Vec<PublicKeyCredentialParameters>,
    ) -> Result<CoseAlgorithmIdentifier, WebauthnCredentialCreationError> {
        //Order of preference for credential type is: Ed25519 > EC2 > RSA > RS1
        let mut possible_credential_types = vec![
            CoseAlgorithmIdentifier::RS1,
            CoseAlgorithmIdentifier::RSA,
            CoseAlgorithmIdentifier::EC2,
            CoseAlgorithmIdentifier::Ed25519,
        ];

        let mut best_alg_index = None;
        while let Some(param) = pub_key_cred_params.iter().next() {
            if let Some(alg_index) = possible_credential_types
                .iter()
                .position(|r| *r == CoseAlgorithmIdentifier::from(param.alg))
            {
                if best_alg_index.filter(|x| x < &alg_index).is_none() {
                    best_alg_index = Some(alg_index);
                }

                if alg_index == possible_credential_types.len() - 1 {
                    break;
                }
            }
        }

        match best_alg_index {
            None => Err(WebauthnCredentialCreationError::AlgorithmNotSupported),
            Some(index) => Ok(possible_credential_types.remove(index)),
        }
    }
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
    let credential = WebauthnAuthenticator::generate_credential_response(
        option.clone(),
        Uuid::new_v4().to_string(),
        Some("http://localhost".to_owned()),
        vec![AttestationFlags::AttestedCredentialDataIncluded, AttestationFlags::UserPresent],
    );

    match credential {
        Ok(cred) => {
            let mut verifier = CredentialCreationVerifier::new(cred.credential_response, option, "http://localhost");
            assert_eq!(dbg!(verifier.verify()).is_ok(), true)
        }
        Err(e) => {
            panic!("{e:?}")
        }
    }
}
