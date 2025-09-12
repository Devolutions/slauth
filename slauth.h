#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define OTP_DEFAULT_DIGITS_VALUE 6

#define HOTP_DEFAULT_COUNTER_VALUE 0

#define HOTP_DEFAULT_RESYNC_VALUE 2

#define TOTP_DEFAULT_PERIOD_VALUE 30

#define TOTP_DEFAULT_BACK_RESYNC_VALUE 1

#define TOTP_DEFAULT_FORWARD_RESYNC_VALUE 1

#define MAX_RESPONSE_LEN_SHORT 256

#define MAX_RESPONSE_LEN_EXTENDED 65536

#define ASN1_SEQ_TYPE 48

#define ASN1_DEFINITE_SHORT_MASK 128

#define ASN1_DEFINITE_LONG_FOLLOWING_MASK 127

#define ASN1_MAX_FOLLOWING_LEN_BYTES 126

#define U2F_EC_KEY_SIZE 32

#define U2F_EC_POINT_SIZE ((U2F_EC_KEY_SIZE * 2) + 1)

#define U2F_MAX_KH_SIZE 128

#define U2F_MAX_ATT_CERT_SIZE 2048

#define U2F_MAX_EC_SIG_SIZE 72

#define U2F_CTR_SIZE 4

#define U2F_APPID_SIZE 32

#define U2F_CHAL_SIZE 32

#define U2F_REGISTER_MAX_DATA_TBS_SIZE ((((1 + U2F_APPID_SIZE) + U2F_CHAL_SIZE) + U2F_MAX_KH_SIZE) + U2F_EC_POINT_SIZE)

#define U2F_AUTH_MAX_DATA_TBS_SIZE ((((1 + U2F_APPID_SIZE) + U2F_CHAL_SIZE) + 1) + 4)

#define U2F_POINT_UNCOMPRESSED 4

#define U2F_REGISTER 1

#define U2F_AUTHENTICATE 2

#define U2F_VERSION 3

#define U2F_VENDOR_FIRST 64

#define U2F_VENDOR_LAST 191

#define U2F_REGISTER_ID 5

#define U2F_REGISTER_HASH_ID 0

#define U2F_AUTH_DONT_ENFORCE 8

#define U2F_AUTH_ENFORCE 3

#define U2F_AUTH_CHECK_ONLY 7

#define U2F_AUTH_FLAG_TUP 1

#define U2F_AUTH_FLAG_TDOWN 0

#define U2F_SW_NO_ERROR 36864

#define U2F_SW_WRONG_DATA 27264

#define U2F_SW_CONDITIONS_NOT_SATISFIED 27013

#define U2F_SW_COMMAND_NOT_ALLOWED 27014

#define U2F_SW_WRONG_LENGTH 26368

#define U2F_SW_CLA_NOT_SUPPORTED 28160

#define U2F_SW_INS_NOT_SUPPORTED 27904

#define HID_RPT_SIZE 64

#define CID_BROADCAST 4294967295

#define TYPE_MASK 128

#define TYPE_INIT 128

#define TYPE_CONT 0

#define FIDO_USAGE_PAGE 61904

#define FIDO_USAGE_U2FHID 1

#define FIDO_USAGE_DATA_IN 32

#define FIDO_USAGE_DATA_OUT 33

#define U2FHID_IF_VERSION 2

#define U2FHID_TRANS_TIMEOUT 3000

#define U2FHID_PING (TYPE_INIT | 1)

#define U2FHID_MSG (TYPE_INIT | 3)

#define U2FHID_LOCK (TYPE_INIT | 4)

#define U2FHID_INIT (TYPE_INIT | 6)

#define U2FHID_WINK (TYPE_INIT | 8)

#define U2FHID_SYNC (TYPE_INIT | 60)

#define U2FHID_ERROR (TYPE_INIT | 63)

#define U2FHID_VENDOR_FIRST (TYPE_INIT | 64)

#define U2FHID_VENDOR_LAST (TYPE_INIT | 127)

#define INIT_NONCE_SIZE 8

#define CAPFLAG_WINK 1

#define ERR_NONE 0

#define ERR_INVALID_CMD 1

#define ERR_INVALID_PAR 2

#define ERR_INVALID_LEN 3

#define ERR_INVALID_SEQ 4

#define ERR_MSG_TIMEOUT 5

#define ERR_CHANNEL_BUSY 6

#define ERR_LOCK_REQUIRED 10

#define ERR_SYNC_FAIL 11

#define ERR_OTHER 127

#define WEBAUTHN_CHALLENGE_LENGTH 32

#define WEBAUTHN_CREDENTIAL_ID_LENGTH 16

#define WEBAUTHN_USER_PRESENT_FLAG 1

#define WEBAUTHN_USER_VERIFIED_FLAG 4

#define WEBAUTHN_ATTESTED_CREDENTIAL_DATA_FLAG 64

#define WEBAUTHN_EXTENSION_DATA_FLAG 128

#define WEBAUTH_PUBLIC_KEY_TYPE_OKP 1

#define WEBAUTH_PUBLIC_KEY_TYPE_EC2 2

#define WEBAUTH_PUBLIC_KEY_TYPE_RSA 3

#define ECDSA_Y_PREFIX_POSITIVE 2

#define ECDSA_Y_PREFIX_NEGATIVE 3

#define ECDSA_Y_PREFIX_UNCOMPRESSED 4

#define ECDSA_CURVE_P256 1

#define ECDSA_CURVE_P384 2

#define ECDSA_CURVE_P521 3

#define ECDAA_CURVE_ED25519 6

#define TPM_GENERATED_VALUE 4283712327

typedef struct AuthenticatorCreationResponse AuthenticatorCreationResponse;

typedef struct AuthenticatorRequestResponse AuthenticatorRequestResponse;

typedef struct ClientWebResponse ClientWebResponse;

typedef struct HOTPContext HOTPContext;

typedef struct HashesAlgorithm HashesAlgorithm;

typedef struct SigningKey SigningKey;

typedef struct TOTPContext TOTPContext;

/**
 *
 */
typedef struct U2fRequest U2fRequest;

typedef struct U2fRequest WebRequest;

typedef struct Buffer {
  uint8_t *data;
  uintptr_t len;
} Buffer;



struct HOTPContext *hotp_from_uri(const char *uri);

void hotp_free(struct HOTPContext *hotp);

char *hotp_to_uri(struct HOTPContext *hotp, const char *label, const char *issuer);

char *hotp_gen(struct HOTPContext *hotp);

void hotp_inc(struct HOTPContext *hotp);

bool hotp_verify(struct HOTPContext *hotp, const char *code);

bool hotp_validate_current(struct HOTPContext *hotp, const char *code);

struct TOTPContext *totp_from_uri(const char *uri);

void totp_free(struct TOTPContext *totp);

char *totp_to_uri(struct TOTPContext *totp, const char *label, const char *issuer);

char *totp_gen(struct TOTPContext *totp);

char *totp_gen_with(struct TOTPContext *totp, unsigned long elapsed);

bool totp_verify(struct TOTPContext *totp, const char *code);

bool totp_validate_current(struct TOTPContext *totp, const char *code);

WebRequest *web_request_from_json(const char *req);

void web_request_free(WebRequest *req);

bool web_request_is_register(WebRequest *req);

bool web_request_is_sign(WebRequest *req);

char *web_request_origin(WebRequest *req);

unsigned long long web_request_timeout(WebRequest *req);

char *web_request_key_handle(WebRequest *req, const char *origin);

struct ClientWebResponse *web_request_sign(WebRequest *req,
                                           struct SigningKey *signing_key,
                                           const char *origin,
                                           unsigned long counter,
                                           bool user_presence);

struct ClientWebResponse *web_request_register(WebRequest *req,
                                               const char *origin,
                                               const unsigned char *attestation_cert,
                                               unsigned long long attestation_cert_len,
                                               const unsigned char *attestation_key,
                                               unsigned long long attestation_key_len);

void client_web_response_free(struct ClientWebResponse *rsp);

char *client_web_response_to_json(struct ClientWebResponse *rsp);

struct SigningKey *client_web_response_signing_key(struct ClientWebResponse *rsp);

void signing_key_free(struct SigningKey *s);

char *signing_key_to_string(struct SigningKey *s);

char *signing_key_get_key_handle(struct SigningKey *s);

struct SigningKey *signing_key_from_string(const char *s);

char *get_private_key_from_response(struct AuthenticatorCreationResponse *res);

struct Buffer get_attestation_object_from_response(struct AuthenticatorCreationResponse *res);

void response_free(struct AuthenticatorCreationResponse *res);

struct AuthenticatorCreationResponse *generate_credential_creation_response(const char *aaguid,
                                                                            const unsigned char *credential_id,
                                                                            uintptr_t credential_id_length,
                                                                            const char *rp_id,
                                                                            uint8_t attestation_flags,
                                                                            const int *cose_algorithm_identifiers,
                                                                            uintptr_t cose_algorithm_identifiers_length);

struct AuthenticatorRequestResponse *generate_credential_request_response(const char *rp_id,
                                                                          const char *private_key,
                                                                          uint8_t attestation_flags,
                                                                          const unsigned char *client_data_hash,
                                                                          uintptr_t client_data_hash_length);

struct Buffer get_auth_data_from_response(struct AuthenticatorRequestResponse *res);

struct Buffer get_signature_from_response(struct AuthenticatorRequestResponse *res);

char *get_error_message(struct AuthenticatorRequestResponse *res);

bool is_success(struct AuthenticatorRequestResponse *res);

char *private_key_to_pkcs8_der(const char *private_key);

char *pkcs8_to_custom_private_key(const char *pkcs8_key);
