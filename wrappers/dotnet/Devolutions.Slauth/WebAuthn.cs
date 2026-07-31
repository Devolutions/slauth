namespace Devolutions.Slauth;

using System;

/// <summary>authenticatorData flag bits (WebAuthn §6.1).</summary>
[Flags]
public enum AttestationFlags : byte
{
    /// <summary>No flags set.</summary>
    None = 0,

    /// <summary>UP: the user was present.</summary>
    UserPresent = 1,

    /// <summary>UV: the user was verified.</summary>
    UserVerified = 4,

    /// <summary>BE: the credential may be backed up.</summary>
    BackupEligible = 8,

    /// <summary>BS: the credential is currently backed up.</summary>
    BackedUp = 16,

    /// <summary>AT: attested credential data follows. Required when creating a credential.</summary>
    AttestedCredentialDataIncluded = 64,

    /// <summary>
    /// ED: extension data follows. Defined for completeness only — slauth never serializes an extension
    /// map, so both entry points reject this flag.
    /// </summary>
    ExtensionDataIncluded = 128,
}

/// <summary>Flag checks shared by the registration and assertion paths.</summary>
internal static class AttestationFlagGuard
{
    /// <summary>
    /// Rejects ED on either path. slauth's <c>AuthenticatorData::to_vec</c> never serializes an extension
    /// map, so the bit would advertise a CBOR map that no consumer will find.
    /// </summary>
    internal static void RejectExtensionData(AttestationFlags attestationFlags)
    {
        if ((attestationFlags & AttestationFlags.ExtensionDataIncluded) != 0)
        {
            throw new ArgumentException(
                "ExtensionDataIncluded is not supported; slauth does not serialize extension data.",
                nameof(attestationFlags));
        }
    }
}

/// <summary>COSE algorithm identifiers slauth can create and sign with.</summary>
public enum CoseAlgorithm
{
    /// <summary>ECDSA over P-256 with SHA-256.</summary>
    Es256 = -7,

    /// <summary>EdDSA over Ed25519.</summary>
    EdDsa = -8,

    /// <summary>RSASSA-PKCS1-v1_5 with SHA-256.</summary>
    Rs256 = -257,
}

/// <summary>Raised when slauth rejects a request or cannot produce a result.</summary>
public class SlauthException : Exception
{
    /// <summary>Initializes a new instance with the supplied message.</summary>
    public SlauthException(string message)
        : base(message)
    {
    }
}

/// <summary>
/// A credential created by the authenticator: the generated private key plus the attestation object
/// to hand back to the relying party.
/// </summary>
public sealed class WebAuthnCreationResponse : IDisposable
{
    /// <summary>Largest credential id the attested credential data's two-byte length field can hold.</summary>
    public const int MaxCredentialIdLength = ushort.MaxValue;

    private readonly CreationResponseHandle handle;

    private WebAuthnCreationResponse(CreationResponseHandle handle)
    {
        this.handle = handle;
        this.PrivateKey = Utf8.ConsumeSlauthString(Native.GetPrivateKeyFromResponse(handle))
            ?? throw new SlauthException("slauth returned no private key for the created credential.");
        this.AttestationObject = Native.CopyBuffer(Native.GetAttestationObjectFromResponse(handle));
    }

    /// <summary>The generated private key, in slauth's own credential envelope.</summary>
    public string PrivateKey { get; }

    /// <summary>CBOR attestation object (fmt "none").</summary>
    public byte[] AttestationObject { get; }

    /// <summary>Generates a credential and its attestation object.</summary>
    /// <param name="aaguid">Authenticator AAGUID as hex, without separators.</param>
    /// <param name="credentialId">
    /// Credential id to embed in the attested credential data; at most <see cref="MaxCredentialIdLength"/> bytes.
    /// </param>
    /// <param name="rpId">Relying party id; its SHA-256 becomes the rpIdHash in authenticatorData.</param>
    /// <param name="attestationFlags">
    /// authenticatorData flags. Must include <see cref="AttestationFlags.AttestedCredentialDataIncluded"/>
    /// and must not include <see cref="AttestationFlags.ExtensionDataIncluded"/>.
    /// </param>
    /// <param name="algorithms">
    /// Algorithms the relying party will accept, in preference order. slauth picks the first it supports.
    /// </param>
    public static WebAuthnCreationResponse Create(
        string aaguid,
        byte[] credentialId,
        string rpId,
        AttestationFlags attestationFlags,
        params CoseAlgorithm[] algorithms)
    {
        if (aaguid is null)
        {
            throw new ArgumentNullException(nameof(aaguid));
        }

        if (credentialId is null)
        {
            throw new ArgumentNullException(nameof(credentialId));
        }

        if (rpId is null)
        {
            throw new ArgumentNullException(nameof(rpId));
        }

        if (algorithms is null || algorithms.Length == 0)
        {
            throw new ArgumentException("At least one algorithm is required.", nameof(algorithms));
        }

        // Without AT, slauth omits the attested credential data and still reports success, yielding an
        // attestation object no relying party can use. Fail here rather than hand back a broken credential.
        if ((attestationFlags & AttestationFlags.AttestedCredentialDataIncluded) == 0)
        {
            throw new ArgumentException(
                "AttestedCredentialDataIncluded is required when creating a credential.",
                nameof(attestationFlags));
        }

        AttestationFlagGuard.RejectExtensionData(attestationFlags);

        // The attested credential data encodes this length in two bytes, and slauth casts to u16 without
        // checking, so a longer id wraps while every byte is still written and the relying party reads
        // the overflow as the start of the COSE key.
        if (credentialId.Length > MaxCredentialIdLength)
        {
            throw new ArgumentException(
                $"Credential id must be at most {MaxCredentialIdLength} bytes; got {credentialId.Length}.",
                nameof(credentialId));
        }

        int[] rawAlgorithms = new int[algorithms.Length];
        for (int i = 0; i < algorithms.Length; i++)
        {
            rawAlgorithms[i] = (int)algorithms[i];
        }

        IntPtr aaguidPointer = Utf8.Allocate(aaguid);
        IntPtr rpIdPointer = Utf8.Allocate(rpId);
        try
        {
            CreationResponseHandle handle = Native.GenerateCredentialCreationResponse(
                aaguidPointer,
                credentialId,
                (UIntPtr)credentialId.Length,
                rpIdPointer,
                (byte)attestationFlags,
                rawAlgorithms,
                (UIntPtr)rawAlgorithms.Length);

            if (handle.IsInvalid)
            {
                handle.Dispose();
                throw new SlauthException(
                    "slauth rejected the credential creation request (check the aaguid, rpId, and algorithm list).");
            }

            // Reads everything out of the response while the handle is alive; the caller only ever sees
            // owned managed copies.
            return new WebAuthnCreationResponse(handle);
        }
        finally
        {
            Utf8.Free(aaguidPointer);
            Utf8.Free(rpIdPointer);
        }
    }

    /// <summary>Releases the underlying slauth response.</summary>
    public void Dispose() => this.handle.Dispose();
}

/// <summary>An assertion produced by signing a relying party's challenge with a stored credential.</summary>
public sealed class WebAuthnRequestResponse : IDisposable
{
    /// <summary>Length of the SHA-256 client data hash WebAuthn signs over.</summary>
    public const int ClientDataHashLength = 32;

    private readonly RequestResponseHandle handle;

    private WebAuthnRequestResponse(RequestResponseHandle handle)
    {
        this.handle = handle;
        this.IsSuccess = Native.IsSuccess(handle);
        this.ErrorMessage = Utf8.ConsumeSlauthString(Native.GetErrorMessage(handle));
        this.AuthenticatorData = Native.CopyBuffer(Native.GetAuthDataFromResponse(handle));
        this.Signature = Native.CopyBuffer(Native.GetSignatureFromResponse(handle));
    }

    /// <summary>Whether slauth produced a usable assertion.</summary>
    public bool IsSuccess { get; }

    /// <summary>Failure detail from slauth; empty or null when <see cref="IsSuccess"/> is true.</summary>
    public string? ErrorMessage { get; }

    /// <summary>authenticatorData that was signed.</summary>
    public byte[] AuthenticatorData { get; }

    /// <summary>Signature over authenticatorData concatenated with the client data hash.</summary>
    public byte[] Signature { get; }

    /// <summary>
    /// Signs <paramref name="clientDataHash"/> with <paramref name="privateKey"/>. slauth reports a failed
    /// assertion through the response rather than a null handle, so inspect <see cref="IsSuccess"/>; use
    /// <see cref="CreateOrThrow"/> to turn that into an exception.
    /// </summary>
    /// <param name="rpId">Relying party id; its SHA-256 becomes the rpIdHash in authenticatorData.</param>
    /// <param name="privateKey">A private key in slauth's credential envelope.</param>
    /// <param name="attestationFlags">
    /// authenticatorData flags. Structural flags belong to registration, so neither
    /// <see cref="AttestationFlags.AttestedCredentialDataIncluded"/> nor
    /// <see cref="AttestationFlags.ExtensionDataIncluded"/> may be set here.
    /// </param>
    /// <param name="clientDataHash">
    /// The <see cref="ClientDataHashLength"/>-byte SHA-256 digest of the collected client data.
    /// </param>
    public static WebAuthnRequestResponse Create(
        string rpId,
        string privateKey,
        AttestationFlags attestationFlags,
        byte[] clientDataHash)
    {
        if (rpId is null)
        {
            throw new ArgumentNullException(nameof(rpId));
        }

        if (privateKey is null)
        {
            throw new ArgumentNullException(nameof(privateKey));
        }

        if (clientDataHash is null)
        {
            throw new ArgumentNullException(nameof(clientDataHash));
        }

        // The assertion ABI has no way to pass attested credential data — it always hands slauth None — so
        // AT here only sets a bit promising a payload that never gets appended.
        if ((attestationFlags & AttestationFlags.AttestedCredentialDataIncluded) != 0)
        {
            throw new ArgumentException(
                "AttestedCredentialDataIncluded is not valid for an assertion; it belongs to registration.",
                nameof(attestationFlags));
        }

        AttestationFlagGuard.RejectExtensionData(attestationFlags);

        // clientDataHash is a SHA-256 digest by definition. slauth signs whatever length it is given and
        // still reports success, so a wrong-sized hash only fails later at the relying party.
        if (clientDataHash.Length != ClientDataHashLength)
        {
            throw new ArgumentException(
                $"clientDataHash must be a {ClientDataHashLength}-byte SHA-256 digest; got {clientDataHash.Length} bytes.",
                nameof(clientDataHash));
        }

        IntPtr rpIdPointer = Utf8.Allocate(rpId);
        IntPtr privateKeyPointer = Utf8.Allocate(privateKey);
        try
        {
            RequestResponseHandle handle = Native.GenerateCredentialRequestResponse(
                rpIdPointer,
                privateKeyPointer,
                (byte)attestationFlags,
                clientDataHash,
                (UIntPtr)clientDataHash.Length);

            if (handle.IsInvalid)
            {
                handle.Dispose();
                throw new SlauthException("slauth rejected the assertion request.");
            }

            return new WebAuthnRequestResponse(handle);
        }
        finally
        {
            Utf8.Free(rpIdPointer);
            Utf8.Free(privateKeyPointer);
        }
    }

    /// <summary>Signs as <see cref="Create"/> does, throwing when slauth reports failure.</summary>
    public static WebAuthnRequestResponse CreateOrThrow(
        string rpId,
        string privateKey,
        AttestationFlags attestationFlags,
        byte[] clientDataHash)
    {
        WebAuthnRequestResponse response = Create(rpId, privateKey, attestationFlags, clientDataHash);
        if (!response.IsSuccess)
        {
            string message = string.IsNullOrEmpty(response.ErrorMessage)
                ? "slauth could not produce an assertion."
                : response.ErrorMessage!;
            response.Dispose();
            throw new SlauthException(message);
        }

        return response;
    }

    /// <summary>Releases the underlying slauth response.</summary>
    public void Dispose() => this.handle.Dispose();
}

/// <summary>Converts between slauth's credential envelope and PKCS#8.</summary>
public static class PrivateKeyConverter
{
    /// <summary>Converts a slauth credential envelope to base64 PKCS#8 DER.</summary>
    public static string ToPkcs8Der(string privateKey)
    {
        if (privateKey is null)
        {
            throw new ArgumentNullException(nameof(privateKey));
        }

        IntPtr pointer = Utf8.Allocate(privateKey);
        try
        {
            return Utf8.ConsumeSlauthString(Native.PrivateKeyToPkcs8Der(pointer))
                ?? throw new SlauthException("slauth could not convert the private key to PKCS#8.");
        }
        finally
        {
            Utf8.Free(pointer);
        }
    }

    /// <summary>Converts base64 PKCS#8 DER into slauth's credential envelope.</summary>
    public static string FromPkcs8Der(string pkcs8Key)
    {
        if (pkcs8Key is null)
        {
            throw new ArgumentNullException(nameof(pkcs8Key));
        }

        IntPtr pointer = Utf8.Allocate(pkcs8Key);
        try
        {
            return Utf8.ConsumeSlauthString(Native.Pkcs8ToCustomPrivateKey(pointer))
                ?? throw new SlauthException("slauth could not convert the PKCS#8 key.");
        }
        finally
        {
            Utf8.Free(pointer);
        }
    }
}
