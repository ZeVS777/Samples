using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.JsonWebTokens;
using JwtHeaderParameterNames = System.IdentityModel.Tokens.Jwt.JwtHeaderParameterNames;

namespace Zevs.Samples.EC;

/// <summary>
/// Примеры использования ECDH
/// </summary>
public class Ecdh
{
    public static TheoryData<string, string, string> Algorithms = new()
    {
        { JsonWebKeyECTypes.P256, SecurityAlgorithms.EcdhEsA128kw, SecurityAlgorithms.Aes128CbcHmacSha256 },
        { JsonWebKeyECTypes.P384, SecurityAlgorithms.EcdhEsA192kw, SecurityAlgorithms.Aes192CbcHmacSha384 },
        { JsonWebKeyECTypes.P521, SecurityAlgorithms.EcdhEsA256kw, SecurityAlgorithms.Aes256CbcHmacSha512 }
    };

    /// <summary>
    /// Использование эллиптических кривых для реализации алгоритмов ECDH-ES
    /// </summary>
    [Theory]
    [MemberData(nameof(Algorithms))]
    public void Agreement(string crv, string alg, string enc)
    {
        var aliceCredentials = GetCredentials(crv, alg, enc);
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
        var bobExchangeProvider = new EcdhKeyExchangeProvider(bobCredentials.Key, alicePublicKey, headerParameters.Alg,
            headerParameters.Enc);
        var bobKdf = (SymmetricSecurityKey)bobExchangeProvider.GenerateKdf(
            (string)headerParameters[JwtHeaderParameterNames.Apu],
            (string)headerParameters[JwtHeaderParameterNames.Apv]);

        var bobUnwrappedKey = bobKdf;

        var bobCryptoProviderFactory = bobCredentials.CryptoProviderFactory ?? bobCredentials.Key.CryptoProviderFactory;
        if (wrappedKey != null)
        {
            var bobKeyWrapProvider =
                bobCryptoProviderFactory.CreateKeyWrapProvider(bobKdf, GetWrapAlgorithm(headerParameters.Alg));
            bobUnwrappedKey = new SymmetricSecurityKey(bobKeyWrapProvider.UnwrapKey(wrappedKey));
        }

        var bobEncryptionProvider =
            bobCryptoProviderFactory.CreateAuthenticatedEncryptionProvider(bobUnwrappedKey, bobCredentials.Enc);

        var authData =
            Encoding.ASCII.GetBytes(
                Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerParameters.SerializeToJson())));
        return bobEncryptionProvider.Decrypt(aliceEncryptedResult.Ciphertext, authData, aliceEncryptedResult.IV,
            aliceEncryptedResult.AuthenticationTag);
    }

    private static AuthenticatedEncryptionResult GetEncryptedMessage(EncryptingCredentials aliceCredentials,
        SecurityKey bobPublicKey, JwtHeader headerParameters, byte[] data, out byte[]? wrappedKey)
    {
        var aliceExchangeProvider = new EcdhKeyExchangeProvider(aliceCredentials.Key, bobPublicKey,
            headerParameters.Alg, headerParameters.Enc);
        var aliceKdf = (SymmetricSecurityKey)aliceExchangeProvider.GenerateKdf(
            (string)headerParameters[JwtHeaderParameterNames.Apu],
            (string)headerParameters[JwtHeaderParameterNames.Apv]);

        var aliceGeneratedSecurityKey = aliceKdf;
        wrappedKey = null;
        var aliceCryptoProviderFactory =
            aliceCredentials.CryptoProviderFactory ?? aliceCredentials.Key.CryptoProviderFactory;

        var wrapAlgorithm = GetWrapAlgorithm(headerParameters.Alg);
        if (wrapAlgorithm != null)
        {
            var aliceKeyWrapProvider = aliceCryptoProviderFactory.CreateKeyWrapProvider(aliceKdf, wrapAlgorithm);
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
        using var ecPrivate = ECDiffieHellman.Create(EcDsa.GetCurve(crv));
        var ecParameters = ecPrivate.ExportParameters(true);

        var ephemeralPublicKey = new JsonWebKey
        {
            Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve,
            Crv = crv,
            X = Base64UrlEncoder.Encode(ecParameters.Q.X),
            Y = Base64UrlEncoder.Encode(ecParameters.Q.Y)
        };

        var ephemeralPrivateKey = new JsonWebKey
        {
            Kty = ephemeralPublicKey.Kty,
            Crv = ephemeralPublicKey.Crv,
            X = ephemeralPublicKey.X,
            Y = ephemeralPublicKey.Y,
            D = Base64UrlEncoder.Encode(ecParameters.D)
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
        _ => throw new NotSupportedException()
    };
}
