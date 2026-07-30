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
    public void Assertion_SignsWithTheCreatedKey(CoseAlgorithm algorithm)
    {
        using WebAuthnCreationResponse created = WebAuthnCreationResponse.Create(
            Aaguid, NewCredentialId(), RpId, CreationFlags, algorithm);

        using WebAuthnRequestResponse assertion = WebAuthnRequestResponse.CreateOrThrow(
            RpId, created.PrivateKey, AssertionFlags, SHA256.HashData(new byte[] { 1, 2, 3, 4 }));

        Assert.True(assertion.IsSuccess);
        Assert.NotEmpty(assertion.Signature);

        // authenticatorData is rpIdHash(32) + flags(1) + signCount(4) at minimum.
        Assert.True(assertion.AuthenticatorData.Length >= 37);
        Assert.Equal(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(RpId)), assertion.AuthenticatorData[..32]);
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
