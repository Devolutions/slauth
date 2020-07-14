# slauth
[![doc](https://docs.rs/slauth/badge.svg)](https://docs.rs/slauth/)
[![crate](https://img.shields.io/crates/v/slauth.svg)](https://crates.io/crates/slauth)
[![issue](https://img.shields.io/github/issues/devolutions/slauth.svg)](https://github.com/devolutions/slauth/issues)
![downloads](https://img.shields.io/crates/d/slauth.svg)
[![license](https://img.shields.io/crates/l/slauth.svg)](https://github.com/devolutions/slauth/blob/master/LICENSE)
[![dependency status](https://deps.rs/repo/github/devolutions/slauth/status.svg)](https://deps.rs/repo/github/devolutions/slauth)

## Slauth is a Rust only, OpenSource implementation of Multiple authenticator utils / specification

### Current Implementation Status
Status is describe by : ✓ as implemented, ❌ as not implemented and ⚠️ as partially implemented.

### OATH Authentication ([specs](https://openauthentication.org/specifications-technical-resources/))

#### Authentication Methods

| Name | Status |                        Ref                       |
|:----:|:------:|:-------------------------------------------------:|
| HOTP |    ✓   |  [RFC 4226](https://tools.ietf.org/html/rfc4226) |
| TOTP |    ✓   |  [RFC 6238](https://tools.ietf.org/html/rfc6238) |
| OCRA |    ❌   |  [RFC 6287](https://tools.ietf.org/html/rfc6287) |

#### Provisioning

| Name | Status |                        Ref                       |
|:----:|:------:|:-------------------------------------------------:|
| PSKC |    ❌   | [RFC 6030](https://tools.ietf.org/html/rfc6030) |
| DSKPP |    ❌   |  [RFC 6063](https://tools.ietf.org/html/rfc6063) |


### FIDO & W3C Specification ([specs](https://fidoalliance.org/specifications/download/))

#### Universal 2nd Factor (U2F)

| Name | Status |                        Ref                       |
|:----:|:------:|:-------------------------------------------------:|
| Server-Side Verification |    ✓   |  |
| Raw Message |    ✓   |  [Spec](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html) |
| HID Protocol |    ❌   |  [Spec](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html) |

#### WebAuthN

| Name | Status |                        Ref                       |
|:----:|:------:|:-------------------------------------------------:|
| Server-Side Verification |    ⚠️   | [Spec](https://www.w3.org/TR/webauthn/) |
| Raw Message |    ✓   |  [Spec](https://www.w3.org/TR/webauthn/) |
| COSE |    ⚠️   |  [Spec](https://tools.ietf.org/html/rfc8152) |

For the server side validation, only ECDSA P256 and P384 key validation is supported at this time. Eventually RSA and ECDAA Key validation will be added. 

#### Universal Authentication Framework (UAF)

Not Implemented