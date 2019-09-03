use crate::webauthn::proto::web_message::{PublicKeyCredentialCreationOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, PublicKeyCredentialParameters, PublicKeyCredentialType, AuthenticatorSelectionCriteria, UserVerificationRequirement, AttestationConveyancePreference, PublicKeyCredentialRequestOptions, PublicKeyCredentialDescriptor, PublicKeyCredential, CollectedClientData};
use crate::webauthn::proto::constants::{WEBAUTHN_COSE_ALGORITHM_IDENTIFIER_ES256};
use crate::webauthn::error::Error;
use crate::webauthn::proto::raw_message::{AttestationObject, Message};

pub struct CredentialCreationBuilder {
    challenge: Option<String>,
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

    pub fn challenge(mut self, challenge: String) -> Self {
        self.challenge = Some(challenge);
        self
    }

    pub fn user(mut self, id: String, name: String, display_name: String, icon: Option<String>) -> Self {
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

    pub fn rp(mut self, name: String, icon: Option<String>, id: Option<String>) -> Self {
        self.rp = Some(
            Rp {
                name,
                icon,
                id
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
        }).ok_or_else(|| Error::Other("Unable to build a WebAuthn request without a user".to_string()))?;
        
        let rp = self.rp.map(|rp| PublicKeyCredentialRpEntity {
            id: rp.id,
            name: rp.name,
            icon: rp.icon,
        }).ok_or_else(|| Error::Other("Unable to build a WebAuthn request without a relying party".to_string()))?;
        
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
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub icon: Option<String>,
}

struct Rp {
    pub name: String,
    pub icon: Option<String>,
    pub id: Option<String>,
}

pub struct CredentialCreationVerifier {
    pub credential: PublicKeyCredential,
    pub context: PublicKeyCredentialCreationOptions,
}

impl CredentialCreationVerifier {
    pub fn verify(&self) -> Result<bool, Error> {
        let response = self.credential.response.clone().ok_or_else(|| Error::Other("Client data must be present for verification".to_string()))?;

        let client_data_json = base64::decode(&response.client_data_json)?;
        let client_data = serde_json::from_slice::<CollectedClientData>(client_data_json.as_slice())?;

        let attestation = AttestationObject::from_base64(&response.attestation_object)?;

        Ok(true)
    }
}

pub struct CredentialRequestBuilder {
    challenge: Option<String>,
    rp: Option<String>,
    allow_credentials: Vec<String>,
}

impl CredentialRequestBuilder {
    pub fn new() -> Self {
        CredentialRequestBuilder {
            challenge: None,
            rp: None,
            allow_credentials: Vec::new(),
        }
    }

    pub fn challenge(mut self, challenge: String) -> Self {
        self.challenge = Some(challenge);
        self
    }

    pub fn rp(mut self, rp_id: String) -> Self {
        self.rp = Some(rp_id);
        self
    }

    pub fn allow_credential(mut self, id: String) -> Self {
        self.allow_credentials.push(id);
        self
    }

    pub fn build(self) -> Result<PublicKeyCredentialRequestOptions, Error> {
        let challenge = self.challenge.ok_or_else(|| Error::Other("Unable to build a WebAuthn request without a challenge".to_string()))?;
        let mut allow_credentials = Vec::new();
        self.allow_credentials.iter().for_each(|id| allow_credentials.push(PublicKeyCredentialDescriptor {
            cred_type: PublicKeyCredentialType::PublicKey,
            id: id.clone(),
            transports: None,
        }));

        Ok(PublicKeyCredentialRequestOptions {
            challenge,
            timeout: None,
            rp_id: self.rp,
            allow_credentials,
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: None,
                require_resident_key: None,
                user_verification: Some(UserVerificationRequirement::Required)
            }),
            extensions: None
        })
    }
}