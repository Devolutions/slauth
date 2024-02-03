use crate::webauthn::proto::web_message::PublicKeyCredential;

pub struct AuthenticatorCredentialCreationResponse {
    pub credential_response: PublicKeyCredential,
    pub private_key: String,
}
