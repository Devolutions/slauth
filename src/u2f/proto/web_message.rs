use serde_derive::*;
use serde_repr::*;

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq)]
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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub version: String,
    pub app_id: String,
    pub key_handle: String,
    #[serde(with = "serde_bytes")]
    pub pub_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub attestation_cert: Vec<u8>,
}

///
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    /// The version of the protocol that the to-be-registered token must speak. E.g. "U2F_V2".
    pub version: String,
    /// The websafe-base64-encoded challenge.
    pub challenge: String,
}

///
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredKey {
    /// The version of the protocol that the to-be-registered token must speak. E.g. "U2F_V2".
    pub version: String,
    /// The registered keyHandle to use for signing, as a websafe-base64 encoding of the key handle bytes returned by the U2F token during registration.
    pub key_handle: String,
    /// The transport(s) this token supports, if known by the RP.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub transports: Option<Vec<Transport>>,
    /// The application id that the RP would like to assert for this key handle, if it's distinct from the application id for the overall request. (Ordinarily this will be omitted.)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub app_id: Option<String>,
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

impl From<U2fRequestType> for U2fResponseType {
    fn from(t: U2fRequestType) -> Self {
        if let U2fRequestType::Register = t {
            U2fResponseType::Register
        } else {
            U2fResponseType::Sign
        }
    }
}

impl<'a> From<&'a U2fRequestType> for U2fResponseType {
    fn from(t: &'a U2fRequestType) -> Self {
        if let U2fRequestType::Register = t {
            U2fResponseType::Register
        } else {
            U2fResponseType::Sign
        }
    }
}

///
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct U2fRequest {
    /// The type of request, either Register ("u2f_register_request") or  Sign ("u2f_sign_request").
    #[serde(rename = "type")]
    pub req_type: U2fRequestType,
    /// An application identifier for the request. If none is given, the origin of the calling web page is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub app_id: Option<String>,
    /// A timeout for the FIDO Client's processing, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// An integer identifying this request from concurrent requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub request_id: Option<u64>,
    /// The specific request data
    #[serde(flatten)]
    pub data: Request,
}

///
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct U2fRegisterRequest {
    ///
    pub register_requests: Vec<RegisterRequest>,
    /// An array of RegisteredKeys representing the U2F tokens registered to this user.
    pub registered_keys: Vec<RegisteredKey>,
}

///
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct U2fSignRequest {
    /// The websafe-base64-encoded challenge.
    pub challenge: String,
    /// An array of RegisteredKeys representing the U2F tokens registered to this user.
    pub registered_keys: Vec<RegisteredKey>,
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
    pub rsp_type: U2fResponseType,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub request_id: Option<u64>,
    pub response_data: Response,
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
pub struct ClientError {
    pub error_code: ErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub error_message: Option<String>,
}

impl ClientError {
    pub fn bad_request(msg: Option<String>) -> ClientError {
        ClientError {
            error_code: ErrorCode::BadRequest,
            error_message: msg,
        }
    }

    pub fn other_error(msg: Option<String>) -> ClientError {
        ClientError {
            error_code: ErrorCode::OtherError,
            error_message: msg,
        }
    }

    pub fn configuration_unsupported(msg: Option<String>) -> ClientError {
        ClientError {
            error_code: ErrorCode::ConfigurationUnsupported,
            error_message: msg,
        }
    }

    pub fn device_ineligible(msg: Option<String>) -> ClientError {
        ClientError {
            error_code: ErrorCode::DeviceIneligible,
            error_message: msg,
        }
    }

    pub fn timeout(msg: Option<String>) -> ClientError {
        ClientError {
            error_code: ErrorCode::Timeout,
            error_message: msg,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct U2fRegisterResponse {
    pub version: String,
    pub registration_data: String,
    pub client_data: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct U2fSignResponse {
    pub key_handle: String,
    pub signature_data: String,
    pub client_data: String,
}

///
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Register(U2fRegisterResponse),
    Sign(U2fSignResponse),
    Error(ClientError),
}

#[derive(Serialize, Deserialize)]
pub enum ClientDataType {
    #[serde(rename = "navigator.id.getAssertion")]
    Authentication,
    #[serde(rename = "navigator.id.finishEnrollment")]
    Registration,
}

#[derive(Serialize, Deserialize)]
pub struct ClientData {
    pub typ: ClientDataType,
    pub challenge: String,
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub cid_pubkey: Option<String>,
}

#[test]
fn request_json_format() {
    let sign_req_str = "{\"type\": \"u2f_sign_request\",\"appId\": \"https://example.com\",\"challenge\": \"YWM3OGQ5YWJhODljNzlhMDU0NTZjZDhiNmU3NWY3NGE\",\"registeredKeys\": [{\"version\": \"U2F_V2\", \"keyHandle\": \"test\", \"transports\": [\"usb\", \"nfc\"]}],\"timeoutSeconds\": 30}";

    let sign_req = serde_json::from_str::<U2fRequest>(sign_req_str).unwrap();

    if let U2fRequestType::Sign = sign_req.req_type {
        assert_eq!(sign_req.app_id.unwrap(), "https://example.com");
        assert!(sign_req.request_id.is_none());
        assert_eq!(sign_req.timeout_seconds, Some(30));

        if let Request::Sign(sign) = &sign_req.data {
            assert_eq!(sign.challenge, "YWM3OGQ5YWJhODljNzlhMDU0NTZjZDhiNmU3NWY3NGE");
            assert_eq!(sign.registered_keys.len(), 1);

            assert!(sign.registered_keys[0].app_id.is_none());
            assert_eq!(sign.registered_keys[0].version, "U2F_V2");
            assert_eq!(sign.registered_keys[0].key_handle, "test");
            assert_eq!(sign.registered_keys[0].transports, Some(vec![Transport::Usb, Transport::Nfc]));
        }
    } else {
        assert!(false);
    }
}
