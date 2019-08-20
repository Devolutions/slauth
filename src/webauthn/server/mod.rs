use crate::webauthn::proto::web_message::PublicKeyCredentialCreationOptions;
use crate::webauthn::proto::constants::{WEBAUTHN_CHALLENGE_LENGTH, WEBAUTHN_CREDENTIAL_ID_LENGTH};

pub struct CredentialCreationBuilder {
    pub challenge: Option<[u8; WEBAUTHN_CHALLENGE_LENGTH]>,
    pub user: Option<User>,
    pub rp: Option<Rp>,
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

    pub fn build () -> Result<PublicKeyCredentialCreationOptions, Error> {

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