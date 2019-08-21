use crate::webauthn::proto::web_message::{PublicKeyCredentialCreationOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, PublicKeyCredentialParameters, PublicKeyCredentialType, AuthenticatorSelectionCriteria, UserVerificationRequirement, AttestationConveyancePreference};
use crate::webauthn::proto::constants::{WEBAUTHN_CHALLENGE_LENGTH, WEBAUTHN_CREDENTIAL_ID_LENGTH, WEBAUTHN_COSE_ALGORITHM_IDENTIFIER_ES256};
use crate::webauthn::error::Error;

pub struct CredentialCreationBuilder {
    challenge: Option<[u8; WEBAUTHN_CHALLENGE_LENGTH]>,
    user: Option<User>,
    rp: Option<Rp>,
}

impl CredentialCreationBuilder {
    pub fn new() -> Self {
        CredentialCreationBuilder {
            challenge: None,
            user: None,
            rp: None,
        }
    }

    pub fn user(mut self, id: [u8; WEBAUTHN_CREDENTIAL_ID_LENGTH], name: String, display_name: String, icon: Option<String>) -> Self {
        self.user = Some(
            User {
                id,
                name,
                display_name,
                icon,
            }
        );
        self
    }

    pub fn rp(mut self, name: String, icon: Option<String>) -> Self {
        self.rp = Some(
            Rp {
                name,
                icon,
            }
        );
        self
    }

    pub fn build (self) -> Result<PublicKeyCredentialCreationOptions, Error> {
        let challenge = self.challenge.ok_or_else(|| Error::Other("Unable to build a WebAuthn request without a challenge".to_string()))?;
        
        let user = self.user.map(|user| PublicKeyCredentialUserEntity {
            id: user.id,
            name: user.name,
            display_name: user.display_name,
            icon: user.icon,
        }).ok_or_else(Error::Other("Unable to build a WebAuthn request without a user".to_string()))?;
        
        let rp = self.rp.map(|rp| PublicKeyCredentialRpEntity {
            id: None,
            name: rp.name,
            icon: rp.icon,
        }).ok_or_else(Error::Other("Unable to build a WebAuthn request without a relying party".to_string()))?;
        
        Ok(PublicKeyCredentialCreationOptions {
            rp,
            user,
            challenge,
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                auth_type: PublicKeyCredentialType::PublicKey,
                alg: WEBAUTHN_COSE_ALGORITHM_IDENTIFIER_ES256
            }],
            timeout: None,
            exclude_credentials: vec![],
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: None,
                require_resident_key: None,
                user_verification: Some(UserVerificationRequirement::Preferred)
            }),
            attestation: Some(AttestationConveyancePreference::Direct),
            extensions: None
        })
    }
}

struct User {
    pub id: [u8; WEBAUTHN_CREDENTIAL_ID_LENGTH],
    pub name: String,
    pub display_name: String,
    pub icon: Option<String>,
}

struct Rp {
    pub name: String,
    pub icon: Option<String>,
}

pub struct CredentialRequestBuilder {}