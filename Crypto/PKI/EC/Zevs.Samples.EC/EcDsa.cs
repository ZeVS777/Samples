using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Zevs.Samples.EC;

/// <summary>
/// Примеры загрузки и использования ECDsa
/// </summary>
public class EcDsa
{
    public static TheoryData<string, string> Algorithms = new()
    {
        { "", SecurityAlgorithms.EcdsaSha256 },
        { ".secp256k1", "ES256K" }
    };

    public static TheoryData<string> EcAlgorithms = new()
    {
        SecurityAlgorithms.EcdsaSha256,
        "ES256K",
        SecurityAlgorithms.EcdsaSha384,
        SecurityAlgorithms.EcdsaSha512,
    };

    private readonly byte[] _data = Encoding.UTF8.GetBytes("Криптография - круто!");

    /// <summary>
    /// Загрузка ECDsa из файлов приватного и публичного PEM ключа (ES256, ES256K)
    /// </summary>
    [Theory]
    [MemberData(nameof(Algorithms))]
    public void LoadFromPem(string fileSuffix, string alg)
    {
        using var ecPrivate = ECDsa.Create();
        ecPrivate.ImportFromPem(File.ReadAllText($"CertFiles/private-key{fileSuffix}.pem"));

        using var ecPublic = ECDsa.Create();
        ecPublic.ImportFromPem(File.ReadAllText($"CertFiles/public-key{fileSuffix}.pem"));

        SignVerify(ecPublic, ecPrivate, alg);
    }

    /// <summary>
    /// Загрузка ECDsa из X.509 pem файла (ES256, ES256K)
    /// </summary>
    [Theory]
    [MemberData(nameof(Algorithms))]
    public void LoadFromCertPem(string fileSuffix, string alg)
    {
        using var ecPrivate = ECDsa.Create();
        ecPrivate.ImportFromPem(File.ReadAllText($"CertFiles/private-key{fileSuffix}.pem"));

        var cert = X509Certificate2.CreateFromPem(File.ReadAllText($"CertFiles/cert{fileSuffix}.pem"));
        using var ecPublic = cert.GetECDsaPublicKey();

        Assert.NotNull(ecPublic);

        SignVerify(ecPublic, ecPrivate, alg);
    }

    /// <summary>
    /// Загрузка ECDsa из X.509 pfx файла (ES256, ES256K)
    /// </summary>
    [Theory]
    [MemberData(nameof(Algorithms))]
    public void LoadFromCertPfx(string fileSuffix, string alg)
    {
        var pfx = X509Certificate.CreateFromCertFile($"CertFiles/cert{fileSuffix}.pfx");
        var cert = new X509Certificate2(pfx);

        using var ecPrivate = cert.GetECDsaPrivateKey();
        using var ecPublic = cert.GetECDsaPublicKey();
        Assert.NotNull(ecPublic);
        Assert.NotNull(ecPrivate);

        SignVerify(ecPublic, ecPrivate, alg);
    }

    /// <summary>
    /// Загрузка ECDsa из JWK (ES256, ES256K)
    /// </summary>
    [Theory]
    [MemberData(nameof(Algorithms))]
    public void LoadFromJwk(string fileSuffix, string alg)
    {
        var privateJwkJson = GetPrivateJwk(fileSuffix, alg);
        var privateJwk = new JsonWebKey(privateJwkJson);

        var publicJwkJson = GetPublicJwk(fileSuffix, alg);
        var publicJwk = new JsonWebKey(publicJwkJson);

        Assert.Equal("EC", publicJwk.Kty);
        Assert.Equal(publicJwk.Kty, privateJwk.Kty);
        Assert.Equal(publicJwk.Alg, privateJwk.Alg);

        var privateParameters = GetFromJwk(privateJwk);
        if (!string.IsNullOrEmpty(privateJwk.Crv))
            Assert.Equal(privateParameters.Curve.Oid.FriendlyName, GetCurve(privateJwk.Crv).Oid.FriendlyName);

        using var ecPrivate = ECDsa.Create(privateParameters);

        var publicParameters = GetFromJwk(publicJwk);
        if (!string.IsNullOrEmpty(publicJwk.Crv))
            Assert.Equal(privateParameters.Curve.Oid.FriendlyName, GetCurve(publicJwk.Crv).Oid.FriendlyName);

        using var ecPublic = ECDsa.Create(publicParameters);

        SignVerify(ecPublic, ecPrivate, privateJwk.Alg);
    }

    /// <summary>
    /// Загрузка из эфемерного сертификата (ES256, ES384, ES512, ES256K)
    /// </summary>
    [Theory]
    [MemberData(nameof(EcAlgorithms))]
    public void LoadEphemeralX509(string alg)
    {
        var (curve, hashingAlg) = GetAlgCurveHash(alg);

        using var ecDsa = ECDsa.Create(curve);
        var req = new CertificateRequest("C=RU, CN=ZeVS", ecDsa, hashingAlg);
        var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddMinutes(1));

        var rsaPrivate = cert.GetECDsaPrivateKey();
        var rsaPublic = cert.GetECDsaPublicKey();

        Assert.NotNull(rsaPublic);
        Assert.NotNull(rsaPrivate);

        SignVerify(rsaPublic, rsaPrivate, alg);
    }

    /// <summary>
    /// Использование CryptoProviderFactory для создания подписи и её проверки (ES256, ES384, ES512, ES256K)
    /// </summary>
    [Theory]
    [MemberData(nameof(EcAlgorithms))]
    public void UsingCryptoProviderFactory(string alg)
    {
        var (curve, _) = GetAlgCurveHash(alg);

        using var ecDsa = ECDsa.Create(curve);

        SecurityKey key = alg == "ES256K" ? new CustomEcDsaSecurityKey(ecDsa) : new ECDsaSecurityKey(ecDsa);

        var signer = key.CryptoProviderFactory.CreateForSigning(key, alg);
        var verifier = key.CryptoProviderFactory.CreateForVerifying(key, alg);

        var signature = signer.Sign(_data);
        Assert.True(verifier.Verify(_data, signature));
    }

    private static string GetPrivateJwk(string fileSuffix, string alg)
    {
        using var ecPrivate = ECDsa.Create();
        ecPrivate.ImportFromPem(File.ReadAllText($"CertFiles/private-key{fileSuffix}.pem"));
        var ecParameters = ecPrivate.ExportParameters(true);

        var jwk = new JsonWebKey
        {
            Kty = "EC",
            Alg = alg,
            Crv = GetCrv(ecParameters.Curve),
            //Если ключ будет использоваться только для подписи
            //Use = "sig",
            //Если ключ будет использоваться только для шифрования
            //Use = "enc",
            D = Base64UrlEncoder.Encode(ecParameters.D),
            X = Base64UrlEncoder.Encode(ecParameters.Q.X),
            Y = Base64UrlEncoder.Encode(ecParameters.Q.Y)
        };

        return GetFormattedJwk(jwk);
    }

    private static string GetPublicJwk(string fileSuffix, string alg)
    {
        using var ecPublic = ECDsa.Create();
        ecPublic.ImportFromPem(File.ReadAllText($"CertFiles/public-key{fileSuffix}.pem"));
        var ecParameters = ecPublic.ExportParameters(false);

        var jwk = new JsonWebKey
        {
            Kty = "EC",
            Alg = alg,
            Crv = GetCrv(ecParameters.Curve),
            //Если ключ будет использоваться только для подписи
            //Use = "sig",
            //Если ключ будет использоваться только для шифрования
            //Use = "enc",
            X = Base64UrlEncoder.Encode(ecParameters.Q.X),
            Y = Base64UrlEncoder.Encode(ecParameters.Q.Y)
        };

        return GetFormattedJwk(jwk);
    }

    private static ECParameters GetFromJwk(JsonWebKey jwk) => new()
    {
        Curve = GetAlgCurveHash(jwk.Alg).Curve,
        Q = new ECPoint
        {
            X = string.IsNullOrEmpty(jwk.X) ? null : Base64UrlEncoder.DecodeBytes(jwk.X),
            Y = string.IsNullOrEmpty(jwk.Y) ? null : Base64UrlEncoder.DecodeBytes(jwk.Y),
        },
        //Приватные параметры
        D = string.IsNullOrEmpty(jwk.D) ? null : Base64UrlEncoder.DecodeBytes(jwk.D)
    };

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
    /// <param name="ecPublic">Публичный ключ, которым производится проверка подписи</param>
    /// <param name="ecPrivate">Приватный ключ, которым подписываются данные</param>
    /// <param name="alg">Алгоритм, выбранный для проведения процедуры подписывания</param>
    private void SignVerify(ECDsa ecPublic, ECDsa ecPrivate, string alg = SecurityAlgorithms.EcdsaSha256)
    {
        var (curve, hashingAlg) = GetAlgCurveHash(alg);

        Assert.Equal(curve.Oid.FriendlyName, ecPrivate.ExportParameters(false).Curve.Oid.FriendlyName);

        var signature = ecPrivate.SignData(_data, hashingAlg);
        var result = ecPublic.VerifyData(_data, signature, hashingAlg);
        Assert.True(result);
    }

    private static string GetCrv(ECCurve curve) => curve.Oid.FriendlyName switch
    {
        nameof(ECCurve.NamedCurves.nistP256) => "P-256",
        "secP256k1" => "secp256k1",
        nameof(ECCurve.NamedCurves.nistP384) => "P-384",
        nameof(ECCurve.NamedCurves.nistP521) => "P-521",
        _ => throw new ArgumentOutOfRangeException(nameof(curve), "Не известная кривая")
    };

    private static ECCurve GetCurve(string crv) => crv switch
    {
        "P-256" => ECCurve.NamedCurves.nistP256,
        "secp256k1" => ECCurve.CreateFromFriendlyName("secP256k1"),
        "P-384" => ECCurve.NamedCurves.nistP384,
        "P-521" => ECCurve.NamedCurves.nistP521,
        _ => throw new ArgumentOutOfRangeException(nameof(crv), "Не известная кривая")
    };

    private static (ECCurve Curve, HashAlgorithmName HashAlgorithmName) GetAlgCurveHash(string alg) => alg switch
    {
        SecurityAlgorithms.EcdsaSha256 => (ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256),
        "ES256K" => (ECCurve.CreateFromFriendlyName("secP256k1"), HashAlgorithmName.SHA256),
        SecurityAlgorithms.EcdsaSha384 => (ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384),
        SecurityAlgorithms.EcdsaSha512 => (ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512),
        _ => throw new ArgumentOutOfRangeException(nameof(alg), "Не известная алгоритм")
    };
}
