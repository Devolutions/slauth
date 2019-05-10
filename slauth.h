#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define AUTHENTICATE_CHECK_ONLY 7

#define AUTHENTICATE_COMMAND_CODE 2

#define AUTHENTICATE_DONT_ENFORCE_PRESENCE 8

#define AUTHENTICATE_ENFORCE_PRESENCE 3

#define AUTHENTICATE_REQUEST_DATA_FIXED_LEN 34

#define CLASS_BYTE_DEFAULT 0

#define HOTP_DEFAULT_COUNTER_VALUE 0

#define HOTP_DEFAULT_RESYNC_VALUE 2

#define MAX_RESPONSE_LEN_EXTENDED 65536

#define MAX_RESPONSE_LEN_SHORT 256

#define OTP_DEFAULT_DIGITS_VALUE 6

#define REGISTER_COMMAND_CODE 1

#define REGISTER_REQUEST_DATA_LEN 64

#define REGISTER_RESPONSE_RESERVED 5

#define SW_CLASS_NOT_SUPPORTED 28160

#define SW_COMMAND_NOT_SUPPORTED 27904

#define SW_CONDITION_NOT_SATISFIED 27013

#define SW_NO_ERROR 36864

#define SW_WRONG_DATA 27264

#define SW_WRONG_LENGTH 26368

#define TOTP_DEFAULT_BACK_RESYNC_VALUE 1

#define TOTP_DEFAULT_FORWARD_RESYNC_VALUE 1

#define TOTP_DEFAULT_PERIOD_VALUE 30

#define VENDOR_FIRST_COMMAND_CODE 64

#define VENDOR_LAST_COMMAND_CODE 191

#define VERSION_COMMAND_CODE 3

typedef struct HOTPContext HOTPContext;

typedef struct TOTPContext TOTPContext;

void hotp_free(HOTPContext *hotp);

HOTPContext *hotp_from_uri(const char *uri);

char *hotp_gen(HOTPContext *hotp);

void hotp_inc(HOTPContext *hotp);

char *hotp_to_uri(HOTPContext *hotp, const char *label, const char *issuer);

bool hotp_validate_current(HOTPContext *hotp, const char *code);

bool hotp_verify(HOTPContext *hotp, const char *code);

void totp_free(TOTPContext *totp);

TOTPContext *totp_from_uri(const char *uri);

char *totp_gen(TOTPContext *totp);

char *totp_to_uri(TOTPContext *totp, const char *label, const char *issuer);

bool totp_validate_current(TOTPContext *totp, const char *code);

bool totp_verify(TOTPContext *totp, const char *code);
