use crate::webauthn::proto::{raw_message::CoseAlgorithmIdentifier, web_message::PublicKeyCredentialRaw};
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Clone)]
pub struct AuthenticatorCredentialCreationResponse {
    pub credential_response: PublicKeyCredentialRaw,
    pub private_key_response: String,
}

#[derive(Serialize, Deserialize)]
pub struct PrivateKeyResponse {
    pub private_key: Vec<u8>,
    #[serde(default)]
    pub key_alg: CoseAlgorithmIdentifier,
}
