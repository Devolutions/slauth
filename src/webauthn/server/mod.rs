use crate::webauthn::proto::web_message::{PublicKeyCredentialCreationOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, PublicKeyCredentialParameters, PublicKeyCredentialType, AuthenticatorSelectionCriteria, UserVerificationRequirement, AttestationConveyancePreference, PublicKeyCredentialRequestOptions, PublicKeyCredentialDescriptor, PublicKeyCredential, CollectedClientData};
use crate::webauthn::proto::constants::{WEBAUTHN_COSE_ALGORITHM_IDENTIFIER_ES256, WEBAUTHN_USER_PRESENT_FLAG, WEBAUTHN_USER_VERIFIED_FLAG, WEBAUTHN_FORMAT_PACKED, WEBAUTHN_FORMAT_FIDO_U2F, WEBAUTHN_COSE_ALGORITHM_IDENTIFIER_RS256};
use crate::webauthn::error::Error;
use crate::webauthn::proto::raw_message::{AttestationObject, Message, CredentialPublicKey};
use sha2::{Sha256, Digest};
use webpki::{SignatureAlgorithm, EndEntityCert};

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
                id,
            }
        );
        self
    }

    pub fn build(self) -> Result<PublicKeyCredentialCreationOptions, Error> {
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
                alg: WEBAUTHN_COSE_ALGORITHM_IDENTIFIER_ES256,
            }],
            timeout: None,
            exclude_credentials: vec![],
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: None,
                require_resident_key: None,
                user_verification: Some(UserVerificationRequirement::Preferred),
            }),
            attestation: Some(AttestationConveyancePreference::Direct),
            extensions: None,
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
    origin: String,
    cert: Option<Vec<u8>>,
}

impl CredentialCreationVerifier {
    pub fn new(credential: PublicKeyCredential, context: PublicKeyCredentialCreationOptions, origin: &str) -> Self {
        CredentialCreationVerifier {
            credential,
            context,
            cert: None,
            origin: origin.to_string(),
        }
    }

    pub fn get_cert(&self) -> Result<EndEntityCert, Error> {
        if let Some(cert) = &self.cert {
            webpki::EndEntityCert::from(cert.as_slice()).map_err(|e| Error::WebPkiError(e))
        } else {
            Err(Error::Other("certificate is missing or has not been verified yet".to_string()))
        }
    }

    pub fn verify(&mut self) -> Result<CredentialPublicKey, Error> {
        let response = self.credential.reg_response.clone().ok_or_else(|| Error::Other("Client data must be present for verification".to_string()))?;

        let client_data_json = base64::decode(&response.client_data_json)?;
        let client_data = serde_json::from_slice::<CollectedClientData>(client_data_json.as_slice())?;

        let attestation = AttestationObject::from_base64(&response.attestation_object)?;

        if client_data.request_type != "webauthn.create" {
            return Err(Error::Registration("Wrong request type".to_string()));
        }

        if client_data.challenge != self.context.challenge {
            return Err(Error::Registration("Challenges do not match".to_string()));
        }

        if client_data.origin != self.origin {
            return Err(Error::Registration("Wrong origin".to_string()));
        }

        let mut hasher = Sha256::new();
        hasher.input(client_data_json);
        let mut client_data_hash = hasher.clone().result().to_vec();

        hasher.reset();
        hasher.input(self.context.rp.id.as_ref().unwrap_or(&self.origin));
        if attestation.auth_data.rp_id_hash != hasher.result().as_slice() {
            return Err(Error::Registration("Wrong rp ID".to_string()));
        }

        if (attestation.auth_data.flags & WEBAUTHN_USER_PRESENT_FLAG) == 0 {
            return Err(Error::Registration("Missing user present flag".to_string()));
        }

        if let Some(Some(user_verification)) = self.context.authenticator_selection.as_ref().map(|auth_select| auth_select.user_verification.as_ref()) {
            match user_verification {
                UserVerificationRequirement::Required => if (attestation.auth_data.flags & WEBAUTHN_USER_VERIFIED_FLAG) == 0 {
                    return Err(Error::Registration("Missing user verified flag".to_string()));
                }
                _ => {}
            }
        }

        if let Some(extensions) = &self.context.extensions {
            if !extensions.is_null() {
                return Err(Error::Registration("Extensions should not be present".to_string()));
            }
        }

        let mut msg = attestation.raw_auth_data.clone();
        msg.append(&mut client_data_hash);

        match attestation.fmt.as_str() {
            WEBAUTHN_FORMAT_PACKED => {
                match attestation.att_stmt.x5c {
                    Some(serde_cbor::Value::Array(mut cert_arr)) => {
                        match cert_arr.pop() {
                            Some(serde_cbor::Value::Bytes(cert)) => {
                                self.cert = Some(cert.clone());
                                let web_cert = webpki::EndEntityCert::from(cert.as_slice())?;
                                if let Err(e) = web_cert.verify_signature(get_alg_from_cose(attestation.att_stmt.alg), msg.as_slice(), attestation.att_stmt.sig.as_slice()) {
                                    return Err(Error::WebPkiError(e));
                                }
                            },

                            _ => {}
                        }
                    }
                    _ => {}
                }
            }

            WEBAUTHN_FORMAT_FIDO_U2F => {
                //unimplemented
            }

            _ => {
                //unimplemented
            }
        }

        Ok(attestation.auth_data.attested_credential_data.credential_public_key)
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
                user_verification: Some(UserVerificationRequirement::Required),
            }),
            extensions: None,
        })
    }
}

fn get_alg_from_cose(id: i64) -> &'static SignatureAlgorithm {
    match id {
        WEBAUTHN_COSE_ALGORITHM_IDENTIFIER_ES256 => &webpki::ECDSA_P256_SHA256,
        WEBAUTHN_COSE_ALGORITHM_IDENTIFIER_RS256 => &webpki::RSA_PKCS1_2048_8192_SHA256,
        _ => &webpki::ECDSA_P256_SHA256,
    }
}

pub struct CredentialRequestVerifier {
    pub credential: PublicKeyCredential,
    pub context: PublicKeyCredentialRequestOptions,
    origin: String,
}

impl CredentialRequestVerifier {
    pub fn new(credential: PublicKeyCredential, context: PublicKeyCredentialRequestOptions, origin: &str) -> Self {
        CredentialRequestVerifier {
            credential,
            context,
            origin: origin.to_string(),
        }
    }

    pub fn verify(&mut self) -> Result<(), Error> {
        let response = self.credential.reg_response.clone().ok_or_else(|| Error::Other("Client data must be present for verification".to_string()))?;

        let client_data_json = base64::decode(&response.client_data_json)?;
        let client_data = serde_json::from_slice::<CollectedClientData>(client_data_json.as_slice())?;

        let attestation = AttestationObject::from_base64(&response.attestation_object)?;

        let descriptor = PublicKeyCredentialDescriptor {
            cred_type: PublicKeyCredentialType::PublicKey,
            id: self.credential.id.clone(),
            transports: None
        };

        if !self.context.allow_credentials.contains(&descriptor) {
            return Err(Error::Sign("Specified credential is not allowed".to_string()));
        }



        Ok(())
    }
}