# Devolutions.Slauth

Managed bindings for slauth's WebAuthn authenticator: credential creation, assertion signing, and
conversion between slauth's credential envelope and PKCS#8.

The package ships the native library per RID under `runtimes/<rid>/native/`, so the .NET host resolves
`DllImport("slauth")` with no extra setup from the consumer.

## Usage

```csharp
using Devolutions.Slauth;

// Create a credential. slauth generates the key pair and returns the private key in its own envelope.
using WebAuthnCreationResponse created = WebAuthnCreationResponse.Create(
    aaguid:           "0F0E0D0C0B0A09080706050403020100",
    credentialId:     credentialId,
    rpId:             "example.com",
    attestationFlags: AttestationFlags.UserPresent
                      | AttestationFlags.UserVerified
                      | AttestationFlags.AttestedCredentialDataIncluded,
    CoseAlgorithm.Es256, CoseAlgorithm.Rs256, CoseAlgorithm.EdDsa);

string privateKey = created.PrivateKey;              // store this
byte[] attestation = created.AttestationObject;      // return this to the relying party

// Later, sign an assertion with the stored key.
using WebAuthnRequestResponse assertion = WebAuthnRequestResponse.CreateOrThrow(
    rpId:             "example.com",
    privateKey:       privateKey,
    attestationFlags: AttestationFlags.UserPresent | AttestationFlags.UserVerified,
    clientDataHash:   clientDataHash);

byte[] authenticatorData = assertion.AuthenticatorData;
byte[] signature = assertion.Signature;
```

`Create` reports a failed assertion through `IsSuccess`/`ErrorMessage`; `CreateOrThrow` turns that into
a `SlauthException`.

To move a key between slauth's envelope and PKCS#8:

```csharp
string pkcs8 = PrivateKeyConverter.ToPkcs8Der(privateKey);
string envelope = PrivateKeyConverter.FromPkcs8Der(pkcs8);
```

## Ownership rules the wrapper handles for you

The C ABI has three rules that are easy to get wrong, so the wrapper enforces all of them and never
exposes a raw pointer:

- Response pointers are owned by `SafeHandle`s, so they are always released.
- `char*` returns are Rust `CString::into_raw` allocations and must go back through
  `slauth_string_free` — the caller's `free` is a different allocator.
- A returned `Buffer` borrows the response's own storage, so it is only valid until the response is
  freed. Every byte array the wrapper hands out is an owned managed copy taken while the handle is alive.

## Building

```powershell
./build.ps1
```

Builds the cdylib for each target, stages it into `Devolutions.Slauth/runtimes/<rid>/native/`, runs the
managed tests, and packs. Defaults to `win-x64` and `win-arm64`; pass `-Targets` for others and
`-SkipTests` to skip the test run.

Adding a platform means one entry in `$RidByTarget` in `build.ps1` — the wrapper and csproj need no change.

### Prerequisite for cross-compiling

`ring` needs a C compiler for some targets. Building `aarch64-pc-windows-msvc` requires LLVM/clang on
`PATH`; without it the build fails with `failed to find tool "clang"`. GitHub's Windows runners already
ship LLVM. The host-architecture build (`x86_64-pc-windows-msvc`) does not need it.

## Tests

The tests exercise the real C ABI rather than a mock — they create credentials for ES256, EdDSA and
RS256, sign assertions, verify the rpIdHash, round-trip a key through PKCS#8 and confirm it still signs,
and loop the create/free cycle so a bad free surfaces as a crash. They need the host cdylib in
`target/release`, which `build.ps1` produces.
