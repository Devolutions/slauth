use http::Uri;
use serde_derive::*;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename = "publicKey", rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,
    #[serde(default, skip_serializing_if = "Extensions::is_empty")]
    pub extensions: Extensions,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename = "publicKey", rename_all = "camelCase")]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
    #[serde(default, skip_serializing_if = "Extensions::is_empty")]
    pub extensions: Extensions,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyCredentialRpEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub auth_type: PublicKeyCredentialType,
    pub alg: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq)]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: PublicKeyCredentialType,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

impl PartialEq for PublicKeyCredentialDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum PublicKeyCredentialType {
    #[serde(rename = "public-key")]
    PublicKey,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
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

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelectionCriteria {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum AuthenticatorAttachment {
    Platform,
    #[serde(rename = "cross-platform")]
    CrossPlatform,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum AttestationConveyancePreference {
    None,
    Indirect,
    Direct,
    Enterprise,
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
pub struct PublicKeyCredentialRaw {
    pub id: String,
    pub raw_id: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<AuthenticatorAttestationResponseRaw>,
}

impl From<PublicKeyCredentialRaw> for PublicKeyCredential {
    fn from(raw: PublicKeyCredentialRaw) -> Self {
        PublicKeyCredential {
            id: raw.id,
            response: raw.response.map(|response| AuthenticatorAttestationResponse {
                attestation_object: response.attestation_object.map(base64::encode),
                client_data_json: base64::encode(&response.client_data_json),
                authenticator_data: response.authenticator_data.map(base64::encode),
                signature: response.signature.map(base64::encode),
                user_handle: response.user_handle.map(base64::encode),
            }),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAttestationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_object: Option<String>,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAttestationResponseRaw {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_object: Option<Vec<u8>>,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<Transport>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub enum Transport {
    Usb,
    Nfc,
    Ble,
    Internal,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CollectedClientData {
    #[serde(rename = "type")]
    pub request_type: String,
    pub challenge: String,
    pub origin: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cross_origin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_binding: Option<TokenBinding>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TokenBinding {
    pub status: TokenBindingStatus,
    pub id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub enum TokenBindingStatus {
    Present,
    Supported,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Extensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<PrfExtension>,
}

impl Extensions {
    pub fn is_empty(&self) -> bool {
        self.prf.is_none()
    }
}

// https://w3c.github.io/webauthn/#dictdef-authenticationextensionsprfinputs
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PrfExtension {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval: Option<AuthenticationExtensionsPRFValues>,

    // Only supported in authentication, not creation
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub eval_by_credential: HashMap<String, AuthenticationExtensionsPRFValues>,
}

// https://w3c.github.io/webauthn/#dictdef-authenticationextensionsprfvalues
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtensionsPRFValues {
    pub first: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second: Option<Vec<u8>>,
}

pub fn get_default_rp_id(origin: &str) -> String {
    origin
        .parse::<Uri>()
        .ok()
        .and_then(|u| u.authority().map(|a| a.host().to_string()))
        .unwrap_or(origin.to_string())
}

#[test]
fn test_default_rp_id() {
    assert_eq!(get_default_rp_id("https://login.example.com:1337"), "login.example.com");
    assert_eq!(get_default_rp_id("https://login.example.com"), "login.example.com");
    assert_eq!(get_default_rp_id("http://login.example.com:1337"), "login.example.com");
    assert_eq!(get_default_rp_id("http://login.example.com"), "login.example.com");
    assert_eq!(get_default_rp_id("login.example.com:1337"), "login.example.com");
    assert_eq!(get_default_rp_id("login.example.com"), "login.example.com");
}
