#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

static const uintptr_t OTP_DEFAULT_DIGITS_VALUE = 6;

static const uintptr_t OTP_ALG_SHA1 = 0;

static const uintptr_t OTP_ALG_SHA256 = 1;

static const uintptr_t OTP_ALG_SHA512 = 2;

static const uint64_t HOTP_DEFAULT_COUNTER_VALUE = 0;

static const uint16_t HOTP_DEFAULT_RESYNC_VALUE = 2;

static const uint64_t TOTP_DEFAULT_PERIOD_VALUE = 30;

static const uint64_t TOTP_DEFAULT_BACK_RESYNC_VALUE = 1;

static const uint64_t TOTP_DEFAULT_FORWARD_RESYNC_VALUE = 1;

static const uintptr_t MAX_RESPONSE_LEN_SHORT = 256;

static const uintptr_t MAX_RESPONSE_LEN_EXTENDED = 65536;

static const uint8_t ASN1_SEQ_TYPE = 48;

static const uint8_t ASN1_DEFINITE_SHORT_MASK = 128;

static const uint8_t ASN1_DEFINITE_LONG_FOLLOWING_MASK = 127;

static const uintptr_t ASN1_MAX_FOLLOWING_LEN_BYTES = 126;

static const uintptr_t U2F_EC_KEY_SIZE = 32;

static const uintptr_t U2F_EC_POINT_SIZE = ((U2F_EC_KEY_SIZE * 2) + 1);

static const uintptr_t U2F_MAX_KH_SIZE = 128;

static const uintptr_t U2F_MAX_ATT_CERT_SIZE = 2048;

static const uintptr_t U2F_MAX_EC_SIG_SIZE = 72;

static const uintptr_t U2F_CTR_SIZE = 4;

static const uintptr_t U2F_APPID_SIZE = 32;

static const uintptr_t U2F_CHAL_SIZE = 32;

static const uintptr_t U2F_REGISTER_MAX_DATA_TBS_SIZE = ((((1 + U2F_APPID_SIZE) + U2F_CHAL_SIZE) + U2F_MAX_KH_SIZE) + U2F_EC_POINT_SIZE);

static const uintptr_t U2F_AUTH_MAX_DATA_TBS_SIZE = ((((1 + U2F_APPID_SIZE) + U2F_CHAL_SIZE) + 1) + 4);

static const uint8_t U2F_POINT_UNCOMPRESSED = 4;

static const uint8_t U2F_REGISTER = 1;

static const uint8_t U2F_AUTHENTICATE = 2;

static const uint8_t U2F_VERSION = 3;

static const uint8_t U2F_VENDOR_FIRST = 64;

static const uint8_t U2F_VENDOR_LAST = 191;

static const uint8_t U2F_REGISTER_ID = 5;

static const uint8_t U2F_REGISTER_HASH_ID = 0;

static const uint8_t U2F_AUTH_DONT_ENFORCE = 8;

static const uint8_t U2F_AUTH_ENFORCE = 3;

static const uint8_t U2F_AUTH_CHECK_ONLY = 7;

static const uint8_t U2F_AUTH_FLAG_TUP = 1;

static const uint8_t U2F_AUTH_FLAG_TDOWN = 0;

static const uint16_t U2F_SW_NO_ERROR = 36864;

static const uint16_t U2F_SW_WRONG_DATA = 27264;

static const uint16_t U2F_SW_CONDITIONS_NOT_SATISFIED = 27013;

static const uint16_t U2F_SW_COMMAND_NOT_ALLOWED = 27014;

static const uint16_t U2F_SW_WRONG_LENGTH = 26368;

static const uint16_t U2F_SW_CLA_NOT_SUPPORTED = 28160;

static const uint16_t U2F_SW_INS_NOT_SUPPORTED = 27904;

static const uintptr_t HID_RPT_SIZE = 64;

static const uint32_t CID_BROADCAST = 4294967295;

static const uint8_t TYPE_MASK = 128;

static const uint8_t TYPE_INIT = 128;

static const uint8_t TYPE_CONT = 0;

static const uint16_t FIDO_USAGE_PAGE = 61904;

static const uint8_t FIDO_USAGE_U2FHID = 1;

static const uint8_t FIDO_USAGE_DATA_IN = 32;

static const uint8_t FIDO_USAGE_DATA_OUT = 33;

static const uintptr_t U2FHID_IF_VERSION = 2;

static const uintptr_t U2FHID_TRANS_TIMEOUT = 3000;

static const uint8_t U2FHID_PING = (TYPE_INIT | 1);

static const uint8_t U2FHID_MSG = (TYPE_INIT | 3);

static const uint8_t U2FHID_LOCK = (TYPE_INIT | 4);

static const uint8_t U2FHID_INIT = (TYPE_INIT | 6);

static const uint8_t U2FHID_WINK = (TYPE_INIT | 8);

static const uint8_t U2FHID_SYNC = (TYPE_INIT | 60);

static const uint8_t U2FHID_ERROR = (TYPE_INIT | 63);

static const uint8_t U2FHID_VENDOR_FIRST = (TYPE_INIT | 64);

static const uint8_t U2FHID_VENDOR_LAST = (TYPE_INIT | 127);

static const uintptr_t INIT_NONCE_SIZE = 8;

static const uint8_t CAPFLAG_WINK = 1;

static const uint8_t ERR_NONE = 0;

static const uint8_t ERR_INVALID_CMD = 1;

static const uint8_t ERR_INVALID_PAR = 2;

static const uint8_t ERR_INVALID_LEN = 3;

static const uint8_t ERR_INVALID_SEQ = 4;

static const uint8_t ERR_MSG_TIMEOUT = 5;

static const uint8_t ERR_CHANNEL_BUSY = 6;

static const uint8_t ERR_LOCK_REQUIRED = 10;

static const uint8_t ERR_SYNC_FAIL = 11;

static const uint8_t ERR_OTHER = 127;

static const uintptr_t WEBAUTHN_CHALLENGE_LENGTH = 32;

static const uintptr_t WEBAUTHN_CREDENTIAL_ID_LENGTH = 16;

static const int64_t WEBAUTHN_COSE_ALGORITHM_IDENTIFIER_EC2 = -7;

static const int64_t WEBAUTHN_COSE_ALGORITHM_IDENTIFIER_RSA = -257;

static const uint8_t WEBAUTHN_USER_PRESENT_FLAG = 1;

static const uint8_t WEBAUTHN_USER_VERIFIED_FLAG = 4;

static const uint8_t WEBAUTHN_ATTESTED_CREDENTIAL_DATA_FLAG = 64;

static const uint8_t WEBAUTHN_EXTENSION_DATA_FLAG = 128;

static const int64_t WEBAUTH_PUBLIC_KEY_TYPE_EC2 = 2;

static const uint8_t ECDSA_Y_PREFIX_POSITIVE = 2;

static const uint8_t ECDSA_Y_PREFIX_NEGATIVE = 3;

static const uint8_t ECDSA_Y_PREFIX_UNCOMPRESSED = 4;

static const int64_t ECDSA_CURVE_P256 = 1;

static const int64_t ECDSA_CURVE_P384 = 2;

static const int64_t ECDSA_CURVE_P521 = 3;

struct ClientWebResponse;

struct HOTPContext;

struct SigningKey;

struct TOTPContext;

///
struct U2fRequest;

using WebRequest = U2fRequest;

extern "C" {

HOTPContext *hotp_from_uri(const char *uri);

HOTPContext *hotp_from_parts(const uint8_t *secret,
                             uintptr_t secret_len,
                             uintptr_t counter,
                             uintptr_t digits,
                             uintptr_t algo);

void hotp_free(HOTPContext *hotp);

char *hotp_to_uri(HOTPContext *hotp, const char *label, const char *issuer);

char *hotp_gen(HOTPContext *hotp);

void hotp_inc(HOTPContext *hotp);

bool hotp_verify(HOTPContext *hotp, const char *code);

bool hotp_validate_current(HOTPContext *hotp, const char *code);

TOTPContext *totp_from_uri(const char *uri);

TOTPContext *totp_from_parts(const uint8_t *secret,
                             uintptr_t secret_len,
                             uintptr_t period,
                             uintptr_t digits,
                             uintptr_t algo);

void totp_free(TOTPContext *totp);

char *totp_to_uri(TOTPContext *totp, const char *label, const char *issuer);

char *totp_gen(TOTPContext *totp);

char *totp_gen_with(TOTPContext *totp, unsigned long elapsed);

bool totp_verify(TOTPContext *totp, const char *code);

bool totp_validate_current(TOTPContext *totp, const char *code);

WebRequest *web_request_from_json(const char *req);

void web_request_free(WebRequest *req);

bool web_request_is_register(WebRequest *req);

bool web_request_is_sign(WebRequest *req);

char *web_request_origin(WebRequest *req);

unsigned long long web_request_timeout(WebRequest *req);

char *web_request_key_handle(WebRequest *req, const char *origin);

ClientWebResponse *web_request_sign(WebRequest *req,
                                    SigningKey *signing_key,
                                    const char *origin,
                                    unsigned long counter,
                                    bool user_presence);

ClientWebResponse *web_request_register(WebRequest *req,
                                        const char *origin,
                                        const unsigned char *attestation_cert,
                                        unsigned long long attestation_cert_len,
                                        const unsigned char *attestation_key,
                                        unsigned long long attestation_key_len);

void client_web_response_free(ClientWebResponse *rsp);

char *client_web_response_to_json(ClientWebResponse *rsp);

SigningKey *client_web_response_signing_key(ClientWebResponse *rsp);

void signing_key_free(SigningKey *s);

char *signing_key_to_string(SigningKey *s);

char *signing_key_get_key_handle(SigningKey *s);

SigningKey *signing_key_from_string(const char *s);

} // extern "C"
