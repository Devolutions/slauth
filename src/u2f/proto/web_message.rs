use serde_repr::*;
use serde_derive::*;

#[derive(Serialize, Deserialize)]
/// FIDO U2F Transports
pub enum Transport {
    /// Bluetooth Classic
    #[serde(rename = "bt")]
    Bluetooth,
    /// Bluetooth Low-Energy
    #[serde(rename = "ble")]
    BluetoothLE,
    /// Near field communication
    #[serde(rename = "nfc")]
    Nfc,
    /// Usb removable device
    #[serde(rename = "usb")]
    Usb,
    /// Usb non-removable device
    #[serde(rename = "usb-internal")]
    UsbInternal,
}

///
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    /// The version of the protocol that the to-be-registered token must speak. E.g. "U2F_V2".
    version: String,
    /// The websafe-base64-encoded challenge.
    challenge: String,
}

///
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredKey {
    /// The version of the protocol that the to-be-registered token must speak. E.g. "U2F_V2".
    version: String,
    /// The registered keyHandle to use for signing, as a websafe-base64 encoding of the key handle bytes returned by the U2F token during registration.
    key_handle: String,
    /// The transport(s) this token supports, if known by the RP.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    transports: Option<Vec<Transport>>,
    /// The application id that the RP would like to assert for this key handle, if it's distinct from the application id for the overall request. (Ordinarily this will be omitted.)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    app_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub enum U2fRequestType {
    #[serde(rename = "u2f_register_request")]
    Register,
    #[serde(rename = "u2f_sign_request")]
    Sign,
}

#[derive(Serialize, Deserialize)]
pub enum U2fResponseType {
    #[serde(rename = "u2f_register_response")]
    Register,
    #[serde(rename = "u2f_sign_response")]
    Sign,
}

///
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct U2fRequest {
    /// The type of request, either Register ("u2f_register_request") or  Sign ("u2f_sign_request").
    #[serde(rename = "type")]
    req_type: U2fRequestType,
    /// An application identifier for the request. If none is given, the origin of the calling web page is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    app_id: Option<String>,
    /// A timeout for the FIDO Client's processing, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    timeout_seconds: Option<u64>,
    /// An integer identifying this request from concurrent requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    request_id: Option<u64>,
    /// The specific request data
    #[serde(flatten)]
    data: Request,
}

///
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct U2fRegisterRequest {
    ///
    register_requests: Vec<RegisterRequest>,
    /// An array of RegisteredKeys representing the U2F tokens registered to this user.
    registered_keys: Vec<RegisteredKey>,
}

///
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct U2fSignRequest {
    /// The websafe-base64-encoded challenge.
    challenge: String,
    /// An array of RegisteredKeys representing the U2F tokens registered to this user.
    registered_keys: Vec<RegisteredKey>,
}

///
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum Request {
    Register(U2fRegisterRequest),
    Sign(U2fSignRequest),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct U2fResponse {
    /// The type of request, either Register ("u2f_register_response") or  Sign ("u2f_sign_response").
    #[serde(rename = "type")]
    req_type: U2fResponseType,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    request_id: Option<u64>,
    response_data: Response,
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug)]
#[repr(u8)]
pub enum ErrorCode {
    Ok = 0,
    OtherError = 1,
    BadRequest = 2,
    ConfigurationUnsupported = 3,
    DeviceIneligible = 4,
    Timeout = 5,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Error {
    error_code: ErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    error_message: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct U2fRegisterResponse {
    version: String,
    registration_data: String,
    client_data: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct U2fSignResponse {
    key_handle: String,
    signature_data: String,
    client_data: String,
}

///
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Register(U2fRegisterResponse),
    Sign(U2fSignResponse),
    Error(Error),
}