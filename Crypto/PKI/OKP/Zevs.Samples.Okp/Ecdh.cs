using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Zevs.Samples.Okp.EdCryptoWrapppers;
using JwtHeaderParameterNames = System.IdentityModel.Tokens.Jwt.JwtHeaderParameterNames;
using NamedCurves = Zevs.Samples.Okp.EdCryptoWrapppers.SecurityAlgorithmsAdditional.NamedCurves;

namespace Zevs.Samples.Okp;

/// <summary>
/// Примеры использования ECDH
/// </summary>
public class Ecdh
{
    public static TheoryData<string, string, string> Algorithms = new()
    {
        { NamedCurves.CurveX25519, SecurityAlgorithms.EcdhEs, SecurityAlgorithms.Aes128Gcm },
        { NamedCurves.CurveX448, SecurityAlgorithms.EcdhEs, SecurityAlgorithms.Aes256Gcm },
        { NamedCurves.CurveX25519, SecurityAlgorithms.EcdhEsA128kw, SecurityAlgorithms.Aes128CbcHmacSha256 },
        { NamedCurves.CurveX448, SecurityAlgorithms.EcdhEsA256kw, SecurityAlgorithms.Aes256CbcHmacSha512 }
    };

    /// <summary>
    /// Использование эллиптических кривых для реализации алгоритмов ECDH-ES
    /// </summary>
    [Theory]
    [MemberData(nameof(Algorithms))]
    public void Agreement(string crv, string alg, string enc)
    {
        var aliceCredentials = GetCredentials(crv, alg, enc);
        aliceCredentials.Key.CryptoProviderFactory.CustomCryptoProvider = new CustomCryptoProvider();
        var bobCredentials = GetCredentials(crv, alg, enc);

        var headerParameters = new JwtHeader(aliceCredentials)
        {
            { JwtHeaderParameterNames.Apu, Base64UrlEncoder.Encode("Alice") },
            { JwtHeaderParameterNames.Apv, Base64UrlEncoder.Encode("Bob") },
            { JwtHeaderParameterNames.Epk, (JsonWebKey)aliceCredentials.KeyExchangePublicKey }
        };

        var aliceData = Encoding.UTF8.GetBytes("Hello World");

        var aliceEncryptedResult = GetEncryptedMessage(aliceCredentials, bobCredentials.KeyExchangePublicKey,
            headerParameters, aliceData, out var wrappedKey);
        var bobData = GetDecryptedMessage(bobCredentials, aliceCredentials.KeyExchangePublicKey, headerParameters,
            wrappedKey, aliceEncryptedResult);

        Assert.Equal(aliceData, bobData);
    }

    private static byte[] GetDecryptedMessage(EncryptingCredentials bobCredentials, SecurityKey alicePublicKey,
        JwtHeader headerParameters, byte[]? wrappedKey, AuthenticatedEncryptionResult aliceEncryptedResult)
    {
        var key = GenerateKdf(headerParameters, (JsonWebKey)alicePublicKey, (JsonWebKey)bobCredentials.Key);

        var bobUnwrappedKey = new SymmetricSecurityKey(key);

        var bobCryptoProviderFactory = bobCredentials.CryptoProviderFactory ?? bobCredentials.Key.CryptoProviderFactory;
        if (wrappedKey != null)
        {
            var bobKeyWrapProvider =
                bobCryptoProviderFactory.CreateKeyWrapProvider(bobUnwrappedKey, GetWrapAlgorithm(headerParameters.Alg));
            bobUnwrappedKey = new SymmetricSecurityKey(bobKeyWrapProvider.UnwrapKey(wrappedKey));
        }

        var bobEncryptionProvider =
            bobCryptoProviderFactory.CreateAuthenticatedEncryptionProvider(bobUnwrappedKey, bobCredentials.Enc);

        //A.2.5.  Additional Authenticated Data https://www.rfc-editor.org/rfc/rfc7516#page-40
        var authData =
            Encoding.ASCII.GetBytes(
                Base64UrlEncoder.Encode(
                    Encoding.UTF8.GetBytes(headerParameters.SerializeToJson())));

        return bobEncryptionProvider.Decrypt(aliceEncryptedResult.Ciphertext, authData, aliceEncryptedResult.IV,
            aliceEncryptedResult.AuthenticationTag);
    }

    private static AuthenticatedEncryptionResult GetEncryptedMessage(EncryptingCredentials aliceCredentials,
        SecurityKey bobPublicKey, JwtHeader headerParameters, byte[] data, out byte[]? wrappedKey)
    {
        var key = GenerateKdf(headerParameters, (JsonWebKey)bobPublicKey, (JsonWebKey)aliceCredentials.Key);

        var aliceGeneratedSecurityKey = new SymmetricSecurityKey(key);
        wrappedKey = null;
        var aliceCryptoProviderFactory =
            aliceCredentials.CryptoProviderFactory ?? aliceCredentials.Key.CryptoProviderFactory;

        var wrapAlgorithm = GetWrapAlgorithm(headerParameters.Alg);
        if (wrapAlgorithm != null)
        {
            var aliceKeyWrapProvider = aliceCryptoProviderFactory.CreateKeyWrapProvider(aliceGeneratedSecurityKey, wrapAlgorithm);
            aliceGeneratedSecurityKey =
                new SymmetricSecurityKey(JwtTokenUtilities.GenerateKeyBytes(GetAlgorithmSize(wrapAlgorithm)));
            wrappedKey = aliceKeyWrapProvider.WrapKey(aliceGeneratedSecurityKey.Key);
        }

        var aliceEncryptionProvider =
            aliceCryptoProviderFactory.CreateAuthenticatedEncryptionProvider(aliceGeneratedSecurityKey,
                headerParameters.Enc);

        var authData =
            Encoding.ASCII.GetBytes(
                Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerParameters.SerializeToJson())));

        return aliceEncryptionProvider.Encrypt(data, authData);
    }

    private static EncryptingCredentials GetCredentials(string crv, string alg, string enc)
    {
        var edDsa = EdDsa.Create(crv);

        var ephemeralPublicKey = new JsonWebKey
        {
            Kty = SecurityAlgorithmsAdditional.EdDsaKty,
            Crv = crv,
            X = Base64UrlEncoder.Encode(edDsa.Parameters.X)
        };

        var ephemeralPrivateKey = new JsonWebKey
        {
            Kty = ephemeralPublicKey.Kty,
            Crv = ephemeralPublicKey.Crv,
            X = ephemeralPublicKey.X,
            D = Base64UrlEncoder.Encode(edDsa.Parameters.D)
        };

        return new EncryptingCredentials(ephemeralPrivateKey, alg, enc) { KeyExchangePublicKey = ephemeralPublicKey };
    }

    private static string? GetWrapAlgorithm(string alg) => alg switch
    {
        SecurityAlgorithms.EcdhEsA128kw => SecurityAlgorithms.Aes128KW,
        SecurityAlgorithms.EcdhEsA192kw => SecurityAlgorithms.Aes192KW,
        SecurityAlgorithms.EcdhEsA256kw => SecurityAlgorithms.Aes256KW,
        _ => null
    };

    private static int GetAlgorithmSize(string wrapAlg) => wrapAlg switch
    {
        SecurityAlgorithms.Aes128KW => 256,
        SecurityAlgorithms.Aes192KW => 384,
        SecurityAlgorithms.Aes256KW => 512,
        SecurityAlgorithms.Aes128CbcHmacSha256 => 256,
        SecurityAlgorithms.Aes192CbcHmacSha384 => 384,
        SecurityAlgorithms.Aes256CbcHmacSha512 => 512,
        _ => throw new NotSupportedException("Не известный алгоритм")
    };

    private static byte[] GenerateKdf(JwtHeader headerParameters, JsonWebKey publicKey, JsonWebKey privateKey)
    {
        var crv = ((JsonWebKey)headerParameters[JwtHeaderParameterNames.Epk]).Crv;

        var (x, d) = (Base64UrlEncoder.DecodeBytes(publicKey.X), Base64UrlEncoder.DecodeBytes(privateKey.D));

        (IRawAgreement agreement, AsymmetricKeyParameter bobPublic, AsymmetricKeyParameter alicePrivate, var zSize) = crv switch
        {
            NamedCurves.CurveX25519 => (
                (IRawAgreement)new X25519Agreement(),
                (AsymmetricKeyParameter)new X25519PublicKeyParameters(x),
                (AsymmetricKeyParameter)new X25519PrivateKeyParameters(d),
                32),
            NamedCurves.CurveX448 => (
                new X448Agreement(),
                new X448PublicKeyParameters(x),
                new X448PrivateKeyParameters(d),
                56),
            _ => throw new NotSupportedException()
        };

        agreement.Init(alicePrivate);

        var z = new byte[zSize];
        agreement.CalculateAgreement(bobPublic, z);

        var kdf = new ConcatenationKdfGenerator(new Sha256Digest());

        SetKeyDataLenAndEncryptionAlgorithm(headerParameters.Alg, headerParameters.Enc,
            out var algorithmId,
            out var keyDataLen);
        SetAppendBytes(algorithmId, keyDataLen,
            (string)headerParameters[JwtHeaderParameterNames.Apu],
            (string)headerParameters[JwtHeaderParameterNames.Apv],
            out var append);

        kdf.Init(new KdfParameters(z, append));
        var outArr = new byte[keyDataLen / 8];
        kdf.GenerateBytes(outArr);

        return outArr;
    }

    private static void SetKeyDataLenAndEncryptionAlgorithm(string alg, string enc, out string algorithmId, out int keyDataLen)
    {
        if ("ECDH-ES".Equals(alg, StringComparison.InvariantCulture))
        {
            algorithmId = enc;
            if ("A128GCM".Equals(enc, StringComparison.InvariantCulture))
                keyDataLen = 128;
            else if ("A192GCM".Equals(enc, StringComparison.InvariantCulture))
                keyDataLen = 192;
            else if ("A256GCM".Equals(enc, StringComparison.InvariantCulture))
                keyDataLen = 256;
            else if ("A128CBC-HS256".Equals(enc, StringComparison.InvariantCulture))
                keyDataLen = 128;
            else if ("A192CBC-HS384".Equals(enc, StringComparison.InvariantCulture))
                keyDataLen = 192;
            else if ("A256CBC-HS512".Equals(enc, StringComparison.InvariantCulture))
                keyDataLen = 256;
            else
                throw new NotSupportedException("Неизвестный алгоритм");
        }
        else
        {
            algorithmId = alg;
            if ("ECDH-ES+A128KW".Equals(alg, StringComparison.InvariantCulture))
                keyDataLen = 128;
            else if ("ECDH-ES+A192KW".Equals(alg, StringComparison.InvariantCulture))
            {
                keyDataLen = 192;
            }
            else if ("ECDH-ES+A256KW".Equals(alg, StringComparison.InvariantCulture))
                keyDataLen = 256;
            else
                throw new NotSupportedException("Неизвестный алгоритм");
        }
    }

    private static void SetAppendBytes(string algorithmId, int keyDataLen, string? apu, string? apv, out byte[] append)
    {
        var bytes1 = Encoding.ASCII.GetBytes(algorithmId);
        var numArray1 = Base64UrlEncoder.DecodeBytes(string.IsNullOrEmpty(apu) ? string.Empty : apu);
        var numArray2 = Base64UrlEncoder.DecodeBytes(string.IsNullOrEmpty(apv) ? string.Empty : apv);
        var bytes2 = BitConverter.GetBytes(bytes1.Length);
        var bytes3 = BitConverter.GetBytes(numArray1.Length);
        var bytes4 = BitConverter.GetBytes(numArray2.Length);
        var bytes5 = BitConverter.GetBytes(keyDataLen);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes2);
            Array.Reverse(bytes3);
            Array.Reverse(bytes4);
            Array.Reverse(bytes5);
        }
        append = Concat(bytes2, bytes1, bytes3, numArray1, bytes4, numArray2, bytes5);
    }

    private static byte[] Concat(params byte[][] arrays)
    {
        var length = 0;
        foreach (var array in arrays)
            length += array.Length;
        var destinationArray = new byte[length];
        var destinationIndex = 0;
        foreach (var array in arrays)
        {
            Array.Copy(array, 0, destinationArray, destinationIndex, array.Length);
            destinationIndex += array.Length;
        }
        return destinationArray;
    }
}
