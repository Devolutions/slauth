pub const WEBAUTHN_CHALLENGE_LENGTH: usize = 32;
pub const WEBAUTHN_CREDENTIAL_ID_LENGTH: usize = 16;

pub const WEBAUTHN_COSE_ALGORITHM_IDENTIFIER_EC2: i64 = -7;
pub const WEBAUTHN_COSE_ALGORITHM_IDENTIFIER_RSA: i64 = -257;

pub const WEBAUTHN_USER_PRESENT_FLAG: u8 = 0b00000001;
pub const WEBAUTHN_USER_VERIFIED_FLAG: u8 = 0b00000100;
pub const WEBAUTHN_ATTESTED_CREDENTIAL_DATA_FLAG: u8 = 0b01000000;
pub const WEBAUTHN_EXTENSION_DATA_FLAG: u8 = 0b10000000;

pub const WEBAUTHN_FORMAT_PACKED: &str = "packed";
pub const WEBAUTHN_FORMAT_FIDO_U2F: &str = "fido-u2f";
pub const WEBAUTHN_FORMAT_NONE: &str = "none";
pub const WEBAUTHN_FORMAT_ANDROID_SAFETYNET: &str = "android-safetynet";
pub const WEBAUTHN_FORMAT_ANDROID_KEY: &str = "android-key";
pub const WEBAUTHN_FORMAT_TPM: &str = "tpm";

pub const WEBAUTH_PUBLIC_KEY_TYPE_EC2: i64 = 2;

pub const WEBAUTHN_REQUEST_TYPE_CREATE: &str = "webauthn.create";
pub const WEBAUTHN_REQUEST_TYPE_GET: &str = "webauthn.get";

pub const ECDSA_Y_PREFIX_POSITIVE: u8 = 2;
pub const ECDSA_Y_PREFIX_NEGATIVE: u8 = 3;
pub const ECDSA_Y_PREFIX_UNCOMPRESSED: u8 = 4;

pub const ECDSA_CURVE_P256: i64 = 1;
pub const ECDSA_CURVE_P384: i64 = 2;
pub const ECDSA_CURVE_P521: i64 = 3;
