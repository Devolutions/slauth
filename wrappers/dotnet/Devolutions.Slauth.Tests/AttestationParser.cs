namespace Devolutions.Slauth.Tests;

using System;
using System.Formats.Cbor;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

/// <summary>
/// Pulls the credential public key out of an attestation object so tests can verify an assertion
/// signature for real, rather than just asserting the bytes are non-empty.
/// </summary>
internal static class AttestationParser
{
    internal sealed record CredentialPublicKey(
        int Algorithm,
        byte[]? X,
        byte[]? Y,
        byte[]? Modulus,
        byte[]? Exponent);

    /// <summary>Reads the authData member out of a CBOR attestation object.</summary>
    internal static byte[] ReadAuthData(byte[] attestationObject)
    {
        CborReader reader = new CborReader(attestationObject);
        int members = reader.ReadStartMap() ?? throw new InvalidOperationException("Indefinite-length attestation object.");
        byte[]? authData = null;

        for (int i = 0; i < members; i++)
        {
            string key = reader.ReadTextString();
            if (key == "authData")
            {
                authData = reader.ReadByteString();
            }
            else
            {
                reader.SkipValue();
            }
        }

        reader.ReadEndMap();
        return authData ?? throw new InvalidOperationException("Attestation object has no authData.");
    }

    /// <summary>
    /// Reads the COSE credential public key from the attested credential data.
    /// Layout: rpIdHash(32) flags(1) signCount(4) aaguid(16) credIdLen(2) credId COSE.
    /// </summary>
    internal static CredentialPublicKey ReadPublicKey(byte[] authData)
    {
        const int AttestedCredentialDataOffset = 37;

        int credentialIdLength = (authData[AttestedCredentialDataOffset + 16] << 8)
            | authData[AttestedCredentialDataOffset + 17];
        int coseOffset = AttestedCredentialDataOffset + 16 + 2 + credentialIdLength;

        CborReader reader = new CborReader(authData[coseOffset..]);
        int members = reader.ReadStartMap() ?? throw new InvalidOperationException("Indefinite-length COSE key.");

        int algorithm = 0;
        byte[]? x = null, y = null, modulus = null, exponent = null;
        int keyType = 0;

        for (int i = 0; i < members; i++)
        {
            int label = reader.ReadInt32();
            switch (label)
            {
                case 1:
                    keyType = reader.ReadInt32();
                    break;
                case 3:
                    algorithm = reader.ReadInt32();
                    break;
                case -1:
                    // crv for EC2/OKP, modulus for RSA — the key type disambiguates.
                    if (keyType == 3)
                    {
                        modulus = reader.ReadByteString();
                    }
                    else
                    {
                        reader.SkipValue();
                    }

                    break;
                case -2:
                    if (keyType == 3)
                    {
                        exponent = reader.ReadByteString();
                    }
                    else
                    {
                        x = reader.ReadByteString();
                    }

                    break;
                case -3:
                    // y, but only for EC2. slauth also emits -3 on OKP keys — a bool left over from the
                    // EC2 branch it was copied from — which RFC 8152 does not define for that key type.
                    if (keyType == 2)
                    {
                        y = reader.ReadByteString();
                    }
                    else
                    {
                        reader.SkipValue();
                    }

                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();
        return new CredentialPublicKey(algorithm, x, y, modulus, exponent);
    }

    /// <summary>
    /// Verifies a WebAuthn assertion signature, which covers authenticatorData concatenated with the
    /// client data hash.
    /// </summary>
    internal static bool Verify(
        CredentialPublicKey key,
        byte[] authenticatorData,
        byte[] clientDataHash,
        byte[] signature)
    {
        byte[] signed = new byte[authenticatorData.Length + clientDataHash.Length];
        Buffer.BlockCopy(authenticatorData, 0, signed, 0, authenticatorData.Length);
        Buffer.BlockCopy(clientDataHash, 0, signed, authenticatorData.Length, clientDataHash.Length);

        switch (key.Algorithm)
        {
            case (int)CoseAlgorithm.Es256:
            {
                using ECDsa ecdsa = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = key.X, Y = key.Y },
                });

                // WebAuthn ES256 signatures are DER; accept the raw r||s form too so the test reports a
                // genuine verification failure rather than an encoding mismatch.
                return ecdsa.VerifyData(signed, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)
                    || ecdsa.VerifyData(signed, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }

            case (int)CoseAlgorithm.Rs256:
            {
                using RSA rsa = RSA.Create(new RSAParameters { Modulus = key.Modulus, Exponent = key.Exponent });
                return rsa.VerifyData(signed, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }

            case (int)CoseAlgorithm.EdDsa:
            {
                // .NET 10 has no Ed25519 in the BCL, so this one leans on BouncyCastle.
                Ed25519Signer verifier = new Ed25519Signer();
                verifier.Init(false, new Ed25519PublicKeyParameters(key.X, 0));
                verifier.BlockUpdate(signed, 0, signed.Length);
                return verifier.VerifySignature(signature);
            }

            default:
                throw new NotSupportedException($"Unhandled COSE algorithm {key.Algorithm}.");
        }
    }
}
