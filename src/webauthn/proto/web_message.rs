use serde_derive::*;
use serde_json::Value;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename = "publicKey", rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub challenge: String,
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
#[serde(rename = "publicKey", rename_all = "camelCase")]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

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
    pub id: String,
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
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
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
#[serde(rename_all = "camelCase")]
pub enum AuthenticatorAttachment {
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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredential {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<AuthenticatorAttestationResponse>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAttestationResponse  {
    pub attestation_object: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CollectedClientData {
    #[serde(rename = "type")]
    client_type: String,
    challenge: String,
    origin: String,
    token_binding: Option<TokenBinding>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TokenBinding {
    status: TokenBindingStatus,
    id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub enum TokenBindingStatus {
    Present,
    Supported,
}
