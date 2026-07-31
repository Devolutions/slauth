namespace Devolutions.Slauth.Tests;

using System;
using System.Security.Cryptography;
using Devolutions.Slauth;
using Xunit;

/// <summary>
/// Round-trips the real C ABI: create a credential, sign an assertion with the key it produced, and
/// convert that key to PKCS#8 and back. These also cover the string and response free paths, so a
/// regression in the ownership rules shows up as a crash here rather than as a slow leak in a consumer.
/// </summary>
public class WebAuthnTests
{
    // Arbitrary 16-byte fixture. Nothing here asserts on it; slauth only splices it into the attested
    // credential data, so the value is irrelevant to what these tests check.
    private const string Aaguid = "0F0E0D0C0B0A09080706050403020100";

    private const string RpId = "webauthn.io";

    private static readonly AttestationFlags CreationFlags =
        AttestationFlags.UserPresent | AttestationFlags.UserVerified | AttestationFlags.AttestedCredentialDataIncluded;

    private static readonly AttestationFlags AssertionFlags =
        AttestationFlags.UserPresent | AttestationFlags.UserVerified;

    [Theory]
    [InlineData(CoseAlgorithm.Es256)]
    [InlineData(CoseAlgorithm.EdDsa)]
    [InlineData(CoseAlgorithm.Rs256)]
    public void Create_ProducesPrivateKeyAndAttestationObject(CoseAlgorithm algorithm)
    {
        using WebAuthnCreationResponse created = WebAuthnCreationResponse.Create(
            Aaguid, NewCredentialId(), RpId, CreationFlags, algorithm);

        Assert.False(string.IsNullOrWhiteSpace(created.PrivateKey));
        Assert.NotEmpty(created.AttestationObject);
    }

    [Theory]
    [InlineData(CoseAlgorithm.Es256)]
    [InlineData(CoseAlgorithm.EdDsa)]
    [InlineData(CoseAlgorithm.Rs256)]
    public void Assertion_VerifiesAgainstTheAttestedPublicKey(CoseAlgorithm algorithm)
    {
        byte[] clientDataHash = SHA256.HashData(new byte[] { 1, 2, 3, 4 });

        using WebAuthnCreationResponse created = WebAuthnCreationResponse.Create(
            Aaguid, NewCredentialId(), RpId, CreationFlags, algorithm);

        using WebAuthnRequestResponse assertion = WebAuthnRequestResponse.CreateOrThrow(
            RpId, created.PrivateKey, AssertionFlags, clientDataHash);

        Assert.True(assertion.IsSuccess);

        // authenticatorData is rpIdHash(32) + flags(1) + signCount(4) at minimum.
        Assert.True(assertion.AuthenticatorData.Length >= 37);
        Assert.Equal(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(RpId)), assertion.AuthenticatorData[..32]);

        // The signature must actually verify against the public key the registration attested, which is
        // what a relying party checks. Non-empty bytes would pass an incorrectly signed assertion.
        byte[] authData = AttestationParser.ReadAuthData(created.AttestationObject);
        AttestationParser.CredentialPublicKey publicKey = AttestationParser.ReadPublicKey(authData);

        Assert.Equal((int)algorithm, publicKey.Algorithm);
        Assert.True(
            AttestationParser.Verify(publicKey, assertion.AuthenticatorData, clientDataHash, assertion.Signature),
            $"{algorithm} assertion did not verify against the attested public key.");
    }

    [Fact]
    public void Assertion_DoesNotVerifyForADifferentChallenge()
    {
        byte[] clientDataHash = SHA256.HashData(new byte[] { 1, 2, 3, 4 });

        using WebAuthnCreationResponse created = WebAuthnCreationResponse.Create(
            Aaguid, NewCredentialId(), RpId, CreationFlags, CoseAlgorithm.Es256);

        using WebAuthnRequestResponse assertion = WebAuthnRequestResponse.CreateOrThrow(
            RpId, created.PrivateKey, AssertionFlags, clientDataHash);

        byte[] authData = AttestationParser.ReadAuthData(created.AttestationObject);
        AttestationParser.CredentialPublicKey publicKey = AttestationParser.ReadPublicKey(authData);

        // Guards the verification helper itself: if it returned true unconditionally, the test above
        // would pass no matter what slauth produced.
        byte[] otherHash = SHA256.HashData(new byte[] { 9, 9, 9, 9 });
        Assert.False(
            AttestationParser.Verify(publicKey, assertion.AuthenticatorData, otherHash, assertion.Signature));
    }

    [Fact]
    public void Create_WithoutAttestedCredentialDataFlag_Throws()
    {
        // slauth would omit the attested credential data and still report success, so the wrapper rejects it.
        Assert.Throws<ArgumentException>(() => WebAuthnCreationResponse.Create(
            Aaguid, NewCredentialId(), RpId, AttestationFlags.UserPresent, CoseAlgorithm.Es256));
    }

    [Fact]
    public void Create_WithExtensionDataFlag_Throws()
    {
        // slauth never serializes an extension map, so ED would advertise CBOR that is not there.
        Assert.Throws<ArgumentException>(() => WebAuthnCreationResponse.Create(
            Aaguid, NewCredentialId(), RpId, CreationFlags | AttestationFlags.ExtensionDataIncluded, CoseAlgorithm.Es256));
    }

    [Fact]
    public void Create_WithOversizedCredentialId_Throws()
    {
        // The attested credential data length field is two bytes and slauth casts to u16 unchecked, so a
        // longer id wraps and the relying party reads the overflow as the start of the COSE key.
        byte[] oversized = new byte[WebAuthnCreationResponse.MaxCredentialIdLength + 1];

        Assert.Throws<ArgumentException>(() => WebAuthnCreationResponse.Create(
            Aaguid, oversized, RpId, CreationFlags, CoseAlgorithm.Es256));
    }

    [Fact]
    public void Create_WithLargestPermittedCredentialId_Succeeds()
    {
        // Guards the boundary itself: the check must reject only what genuinely overflows the length field.
        byte[] largest = RandomNumberGenerator.GetBytes(WebAuthnCreationResponse.MaxCredentialIdLength);

        using WebAuthnCreationResponse created = WebAuthnCreationResponse.Create(
            Aaguid, largest, RpId, CreationFlags, CoseAlgorithm.Es256);

        byte[] authData = AttestationParser.ReadAuthData(created.AttestationObject);
        int encodedLength = (authData[53] << 8) | authData[54];
        Assert.Equal(largest.Length, encodedLength);
    }

    [Theory]
    [InlineData(AttestationFlags.AttestedCredentialDataIncluded)]
    [InlineData(AttestationFlags.ExtensionDataIncluded)]
    public void Assertion_WithStructuralFlag_Throws(AttestationFlags unsupported)
    {
        // Both flags promise bytes the assertion path never appends: it always passes slauth None for
        // attested credential data and slauth serializes no extensions. authenticatorData would be
        // malformed while IsSuccess stayed true.
        Assert.Throws<ArgumentException>(() => WebAuthnRequestResponse.Create(
            RpId, "not-a-key", AssertionFlags | unsupported, SHA256.HashData(new byte[] { 9 })));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void Assertion_WithWrongClientDataHashLength_Throws(int length)
    {
        // slauth signs whatever it is handed and reports success, so a wrong-sized digest would only fail
        // later at the relying party.
        Assert.Throws<ArgumentException>(() => WebAuthnRequestResponse.Create(
            RpId, "not-a-key", AssertionFlags, new byte[length]));
    }

    [Fact]
    public void Assertion_WithGarbageKey_ReportsFailureRatherThanCrashing()
    {
        // The failure path still returns a response object, so this also frees an error-message string.
        using WebAuthnRequestResponse assertion = WebAuthnRequestResponse.Create(
            RpId, "not-a-key", AssertionFlags, SHA256.HashData(new byte[] { 9 }));

        Assert.False(assertion.IsSuccess);
    }

    [Fact]
    public void Assertion_WithGarbageKey_OrThrowThrows()
    {
        Assert.Throws<SlauthException>(() => WebAuthnRequestResponse.CreateOrThrow(
            RpId, "not-a-key", AssertionFlags, SHA256.HashData(new byte[] { 9 })));
    }

    [Fact]
    public void PrivateKey_RoundTripsThroughPkcs8()
    {
        using WebAuthnCreationResponse created = WebAuthnCreationResponse.Create(
            Aaguid, NewCredentialId(), RpId, CreationFlags, CoseAlgorithm.Es256);

        string pkcs8 = PrivateKeyConverter.ToPkcs8Der(created.PrivateKey);
        Assert.False(string.IsNullOrWhiteSpace(pkcs8));

        string envelope = PrivateKeyConverter.FromPkcs8Der(pkcs8);
        Assert.False(string.IsNullOrWhiteSpace(envelope));

        // The recovered envelope must still sign, which is the property consumers actually depend on.
        using WebAuthnRequestResponse assertion = WebAuthnRequestResponse.CreateOrThrow(
            RpId, envelope, AssertionFlags, SHA256.HashData(new byte[] { 7 }));

        Assert.True(assertion.IsSuccess);
    }

    [Fact]
    public void Create_WithNoAlgorithms_Throws()
    {
        Assert.Throws<ArgumentException>(() => WebAuthnCreationResponse.Create(
            Aaguid, NewCredentialId(), RpId, CreationFlags));
    }

    [Fact]
    public void Create_RepeatedlyDoesNotFault()
    {
        // Exercises the create/free cycle enough times that a double free or a bad free surfaces.
        for (int i = 0; i < 50; i++)
        {
            using WebAuthnCreationResponse created = WebAuthnCreationResponse.Create(
                Aaguid, NewCredentialId(), RpId, CreationFlags, CoseAlgorithm.Es256);

            Assert.False(string.IsNullOrWhiteSpace(created.PrivateKey));
        }
    }

    private static byte[] NewCredentialId() => RandomNumberGenerator.GetBytes(16);
}
