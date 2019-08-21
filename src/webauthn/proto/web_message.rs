use serde_derive::*;
use serde_json::Value;
use crate::webauthn::proto::constants::{WEBAUTHN_CHALLENGE_LENGTH, WEBAUTHN_CREDENTIAL_ID_LENGTH};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename = "publicKey", rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub challenge: [u8; WEBAUTHN_CHALLENGE_LENGTH],
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename = "publicKey")]
pub struct PublicKeyCredentialRequestOptions {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeyCredentialRpEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialUserEntity {
    pub id: [u8; WEBAUTHN_CREDENTIAL_ID_LENGTH],
    pub name: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub auth_type: PublicKeyCredentialType,
    pub alg: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: PublicKeyCredentialType,
    pub id: [u8; WEBAUTHN_CREDENTIAL_ID_LENGTH],
    pub transports: Vec<AuthenticatorTransport>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PublicKeyCredentialType {
    #[serde(rename = "public-key")]
    PublicKey
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AuthenticatorTransport {
    #[serde(rename = "usb")]
    Usb,
    #[serde(rename = "nfc")]
    Nfc,
    #[serde(rename = "ble")]
    BluetoothLE,
    #[serde(rename = "internal")]
    Internal,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelectionCriteria {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AuthenticatorAttachment {
    #[serde(rename = "platform")]
    Platform,
    #[serde(rename = "cross-platform")]
    CrossPlatform,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub enum AttestationConveyancePreference {
    None,
    Indirect,
    Direct,
}