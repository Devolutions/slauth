#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define ASN1_DEFINITE_LONG_FOLLOWING_MASK 127

#define ASN1_DEFINITE_SHORT_MASK 128

#define ASN1_MAX_FOLLOWING_LEN_BYTES 126

#define ASN1_SEQ_TYPE 48

#define CAPFLAG_WINK 1

#define CID_BROADCAST 4294967295

#define ERR_CHANNEL_BUSY 6

#define ERR_INVALID_CMD 1

#define ERR_INVALID_LEN 3

#define ERR_INVALID_PAR 2

#define ERR_INVALID_SEQ 4

#define ERR_LOCK_REQUIRED 10

#define ERR_MSG_TIMEOUT 5

#define ERR_NONE 0

#define ERR_OTHER 127

#define ERR_SYNC_FAIL 11

#define FIDO_USAGE_DATA_IN 32

#define FIDO_USAGE_DATA_OUT 33

#define FIDO_USAGE_PAGE 61904

#define FIDO_USAGE_U2FHID 1

#define HID_RPT_SIZE 64

#define HOTP_DEFAULT_COUNTER_VALUE 0

#define HOTP_DEFAULT_RESYNC_VALUE 2

#define INIT_NONCE_SIZE 8

#define MAX_RESPONSE_LEN_EXTENDED 65536

#define MAX_RESPONSE_LEN_SHORT 256

#define OTP_DEFAULT_DIGITS_VALUE 6

#define TOTP_DEFAULT_BACK_RESYNC_VALUE 1

#define TOTP_DEFAULT_FORWARD_RESYNC_VALUE 1

#define TOTP_DEFAULT_PERIOD_VALUE 30

#define TYPE_CONT 0

#define TYPE_INIT 128

#define TYPE_MASK 128

#define U2FHID_IF_VERSION 2

#define U2FHID_TRANS_TIMEOUT 3000

#define U2F_APPID_SIZE 32

#define U2F_AUTHENTICATE 2

#define U2F_AUTH_CHECK_ONLY 7

#define U2F_AUTH_DONT_ENFORCE 8

#define U2F_AUTH_ENFORCE 3

#define U2F_AUTH_FLAG_TDOWN 0

#define U2F_AUTH_FLAG_TUP 1

#define U2F_CHAL_SIZE 32

#define U2F_CTR_SIZE 4

#define U2F_EC_KEY_SIZE 32

#define U2F_MAX_ATT_CERT_SIZE 2048

#define U2F_MAX_EC_SIG_SIZE 72

#define U2F_MAX_KH_SIZE 128

#define U2F_POINT_UNCOMPRESSED 4

#define U2F_REGISTER 1

#define U2F_REGISTER_HASH_ID 0

#define U2F_REGISTER_ID 5

#define U2F_SW_CLA_NOT_SUPPORTED 28160

#define U2F_SW_COMMAND_NOT_ALLOWED 27014

#define U2F_SW_CONDITIONS_NOT_SATISFIED 27013

#define U2F_SW_INS_NOT_SUPPORTED 27904

#define U2F_SW_NO_ERROR 36864

#define U2F_SW_WRONG_DATA 27264

#define U2F_SW_WRONG_LENGTH 26368

#define U2F_VENDOR_FIRST 64

#define U2F_VENDOR_LAST 191

#define U2F_VERSION 3

typedef struct ClientWebResponse ClientWebResponse;

typedef struct HOTPContext HOTPContext;

typedef struct SigningKey SigningKey;

typedef struct TOTPContext TOTPContext;

typedef struct U2fRequest U2fRequest;

typedef U2fRequest WebRequest;

void client_web_response_free(ClientWebResponse *rsp);

SigningKey *client_web_response_signing_key(ClientWebResponse *rsp);

char *client_web_response_to_json(ClientWebResponse *rsp);

void hotp_free(HOTPContext *hotp);

HOTPContext *hotp_from_uri(const char *uri);

char *hotp_gen(HOTPContext *hotp);

void hotp_inc(HOTPContext *hotp);

char *hotp_to_uri(HOTPContext *hotp, const char *label, const char *issuer);

bool hotp_validate_current(HOTPContext *hotp, const char *code);

bool hotp_verify(HOTPContext *hotp, const char *code);

void signing_key_free(SigningKey *s);

SigningKey *signing_key_from_string(const char *s);

char *signing_key_to_string(SigningKey *s);

void totp_free(TOTPContext *totp);

TOTPContext *totp_from_uri(const char *uri);

char *totp_gen(TOTPContext *totp);

char *totp_gen_with(TOTPContext *totp, unsigned long elapsed);

char *totp_to_uri(TOTPContext *totp, const char *label, const char *issuer);

bool totp_validate_current(TOTPContext *totp, const char *code);

bool totp_verify(TOTPContext *totp, const char *code);

void web_request_free(WebRequest *req);

WebRequest *web_request_from_json(const char *req);

bool web_request_is_register(WebRequest *req);

bool web_request_is_sign(WebRequest *req);

char *web_request_key_handle(WebRequest *req, const char *origin);

char *web_request_origin(WebRequest *req);

ClientWebResponse *web_request_register(WebRequest *req,
                                        const char *origin,
                                        const unsigned char *attestation_cert,
                                        unsigned long long attestation_cert_len,
                                        const unsigned char *attestation_key,
                                        unsigned long long attestation_key_len);

ClientWebResponse *web_request_sign(WebRequest *req,
                                    SigningKey *signing_key,
                                    const char *origin,
                                    unsigned long counter,
                                    bool user_presence);

unsigned long long web_request_timeout(WebRequest *req);
