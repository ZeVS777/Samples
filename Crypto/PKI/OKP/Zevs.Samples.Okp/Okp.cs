using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Zevs.Samples.Okp.EdCryptoWrapppers;

namespace Zevs.Samples.Okp;

/// <summary>
/// Примеры загрузки и использования EdDsa
/// </summary>
public class Okp
{
    public static TheoryData<string> Crv = new()
    {
        "Ed25519",
        "Ed448"
    };

    private readonly byte[] _data = Encoding.UTF8.GetBytes("Криптография - круто!");

    /// <summary>
    /// Загрузка EdDsa из файлов приватного и публичного PEM ключа (Ed25519, Ed448)
    /// </summary>
    [Theory]
    [MemberData(nameof(Crv))]
    public void LoadFromPem(string crv)
    {
        var edPrivate = EdDsa.Create();
        edPrivate.ImportFromPem(File.ReadAllText($"CertFiles/private-key.{crv}.pem"));

        var edPublic = EdDsa.Create();
        edPublic.ImportFromPem(File.ReadAllText($"CertFiles/public-key.{crv}.pem"));

        SignVerify(edPublic, edPrivate, crv);
    }

    /// <summary>
    /// Загрузка EdDsa из X.509 pem файла (Ed25519, Ed448)
    /// </summary>
    [Theory]
    [MemberData(nameof(Crv))]
    public void LoadFromCertPem(string crv)
    {
        var edPrivate = EdDsa.Create();
        edPrivate.ImportFromPem(File.ReadAllText($"CertFiles/private-key.{crv}.pem"));

        var edPublic = EdDsa.Create();
        edPublic.ImportFromPem(File.ReadAllText($"CertFiles/cert.{crv}.pem"));
        SignVerify(edPublic, edPrivate, crv);
    }

    /// <summary>
    /// Загрузка EdDsa из JWK (Ed25519, Ed448)
    /// </summary>
    [Theory]
    [MemberData(nameof(Crv))]
    public void LoadFromJwk(string crv)
    {
        var privateJwkJson = GetPrivateJwk(crv);
        var privateJwk = new JsonWebKey(privateJwkJson);

        var publicJwkJson = GetPublicJwk(crv);
        var publicJwk = new JsonWebKey(publicJwkJson);

        Assert.Equal("OKP", publicJwk.Kty);
        Assert.Equal(publicJwk.Kty, privateJwk.Kty);
        Assert.Equal(publicJwk.Alg, privateJwk.Alg);

        var privateParameters = GetFromJwk(privateJwk);

        var edPrivate = EdDsa.Create(privateParameters);

        var publicParameters = GetFromJwk(publicJwk);

        var edPublic = EdDsa.Create(publicParameters);

        SignVerify(edPublic, edPrivate, privateJwk.Crv);
    }

    /// <summary>
    /// Загрузка из эфемерного сертификата (Ed25519, Ed448)
    /// </summary>
    [Theory]
    [MemberData(nameof(Crv))]
    public void LoadEphemeralX509(string crv)
    {
        var edPrivate = EdDsa.Create(crv);
        var cGenerator = new X509V3CertificateGenerator();
        cGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        cGenerator.SetSubjectDN(new X509Name("C=RU, ST=Moscow, L=Moscow, O=ZeVS"));
        cGenerator.SetIssuerDN(new X509Name("C=RU, ST=Moscow, L=Moscow, O=ZeVS"));
        cGenerator.SetNotBefore(DateTime.Now);
        cGenerator.SetNotAfter(DateTime.Now.Add(TimeSpan.FromMinutes(1)));
        cGenerator.SetPublicKey(edPrivate.Parameters.PublicKey);
        cGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
        var cert = cGenerator.Generate(new Asn1SignatureFactory(crv, edPrivate.Parameters.PrivateKey));

        var edPublic = EdDsa.Create(new EdParameters(cert.GetPublicKey(), cert.SigAlgName));
        SignVerify(edPublic, edPrivate, crv);
    }

    /// <summary>
    /// Использование CryptoProviderFactory для создания подписи и её проверки (Ed25519, Ed448)
    /// </summary>
    [Theory]
    [MemberData(nameof(Crv))]
    public void UsingCryptoProviderFactory(string crv)
    {
        var edDsa = EdDsa.Create(crv);

        SecurityKey key = new EdDsaSecurityKey(edDsa);

        var signer = key.CryptoProviderFactory.CreateForSigning(key, SecurityAlgorithmsAdditional.EdDsa);
        var verifier = key.CryptoProviderFactory.CreateForVerifying(key, SecurityAlgorithmsAdditional.EdDsa);

        var signature = signer.Sign(_data);
        Assert.True(verifier.Verify(_data, signature));
    }

    private static string GetPrivateJwk(string crv)
    {
        var edPrivate = EdDsa.Create();
        edPrivate.ImportFromPem(File.ReadAllText($"CertFiles/private-key.{crv}.pem"));
        var edParameters = edPrivate.Parameters;

        var jwk = new JsonWebKey
        {
            Kty = "OKP",
            Alg = "EdDSA",
            Crv = crv,
            Use = "sig",
            D = Base64UrlEncoder.Encode(edParameters.D)
        };

        return GetFormattedJwk(jwk);
    }

    private static string GetPublicJwk(string crv)
    {
        var edPublic = EdDsa.Create();
        edPublic.ImportFromPem(File.ReadAllText($"CertFiles/public-key.{crv}.pem"));
        var ecParameters = edPublic.Parameters;

        var jwk = new JsonWebKey
        {
            Kty = "OKP",
            Alg = "EdDSA",
            Crv = crv,
            Use = "sig",
            X = Base64UrlEncoder.Encode(ecParameters.X)
        };

        return GetFormattedJwk(jwk);
    }

    private static EdParameters GetFromJwk(JsonWebKey jwk)
    {
        Assert.Equal("OKP", jwk.Kty);
        Assert.Equal("EdDSA", jwk.Alg);

        if (jwk.D != null)
            return new EdParameters(jwk.Crv switch
            {
                SecurityAlgorithmsAdditional.NamedCurves.Curve25519 => new Ed25519PrivateKeyParameters(
                    Base64UrlEncoder.DecodeBytes(jwk.D)),
                SecurityAlgorithmsAdditional.NamedCurves.Curve448 => new Ed448PrivateKeyParameters(
                    Base64UrlEncoder.DecodeBytes(jwk.D)),
                _ => throw new NotSupportedException()
            }, jwk.Crv);


        if (jwk.X != null)
            return new EdParameters(jwk.Crv switch
            {
                SecurityAlgorithmsAdditional.NamedCurves.Curve25519 => new Ed25519PublicKeyParameters(
                    Base64UrlEncoder.DecodeBytes(jwk.X)),
                SecurityAlgorithmsAdditional.NamedCurves.Curve448 => new Ed448PublicKeyParameters(
                    Base64UrlEncoder.DecodeBytes(jwk.X)),
                _ => throw new NotSupportedException()
            }, jwk.Crv);

        throw new NotSupportedException("Необходимые параметры не указаны: D и/или X");
    }

    private static string GetFormattedJwk(JsonWebKey jwk)
    {
        var json = JsonExtensions.SerializeToJson(jwk);

        //jwk уже готов, но для простоты чтения человеком, давайте отформатируем
        var obj = JsonSerializer.Deserialize<object>(json);
        var formatted = JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = true });

        return formatted;
    }

    /// <summary>
    /// Подпись данных и её проверка
    /// </summary>
    /// <param name="edPublic">Публичный ключ, которым производится проверка подписи</param>
    /// <param name="edPrivate">Приватный ключ, которым подписываются данные</param>
    /// <param name="crv">Алгоритм, выбранный для проведения процедуры подписывания</param>
    private void SignVerify(EdDsa edPublic, EdDsa edPrivate, string crv)
    {
        Assert.Equal(crv, edPrivate.Parameters.Curve);

        var signature = edPrivate.Sign(_data);
        var result = edPublic.Verify(_data, signature);
        Assert.True(result);
    }
}
