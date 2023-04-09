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
    private readonly byte[] _data = Encoding.UTF8.GetBytes("Криптография - круто!");

    /// <summary>
    /// Загрузка ECDsa из файлов приватного и публичного ключа (PEM)
    /// </summary>
    [Fact]
    public void LoadFromPem()
    {
        using var ecPrivate = ECDsa.Create();
        ecPrivate.ImportFromPem(File.ReadAllText("CertFiles/private-key.pem"));

        using var ecPublic = ECDsa.Create();
        ecPublic.ImportFromPem(File.ReadAllText("CertFiles/public-key.pem"));


        SignVerify(ecPublic, ecPrivate);
    }

    /// <summary>
    /// Загрузка ECDsa из X.509 (pem)
    /// </summary>
    [Fact]
    public void LoadFromCertPem()
    {
        using var ecPrivate = ECDsa.Create();
        ecPrivate.ImportFromPem(File.ReadAllText("CertFiles/private-key.pem"));

        var cert = X509Certificate2.CreateFromPem(File.ReadAllText("CertFiles/cert.pem"));
        using var ecPublic = cert.GetECDsaPublicKey();

        Assert.NotNull(ecPublic);

        SignVerify(ecPublic, ecPrivate);
    }

    /// <summary>
    /// Загрузка ECDsa из X.509 (pfx)
    /// </summary>
    [Fact]
    public void LoadFromCertPfx()
    {
        var pfx = X509Certificate.CreateFromCertFile("CertFiles/cert.pfx");
        var cert = new X509Certificate2(pfx);

        using var ecPrivate = cert.GetECDsaPrivateKey();
        using var ecPublic = cert.GetECDsaPublicKey();
        Assert.NotNull(ecPublic);
        Assert.NotNull(ecPrivate);

        SignVerify(ecPublic, ecPrivate);
    }

    /// <summary>
    /// Загрузка ECDsa из JWK (ES256)
    /// </summary>
    [Fact]
    public void LoadFromJwk()
    {
        var privateJwkJson = GetPrivateJwk();
        var privateJwk = new JsonWebKey(privateJwkJson);

        var publicJwkJson = GetPublicJwk();
        var publicJwk = new JsonWebKey(publicJwkJson);

        Assert.Equal("EC", publicJwk.Kty);
        Assert.Equal(publicJwk.Kty, privateJwk.Kty);
        Assert.Equal(publicJwk.Alg, privateJwk.Alg);

        var privateParameters = GetFromJwk(privateJwk);
        using var ecPrivate = ECDsa.Create(privateParameters);

        var publicParameters = GetFromJwk(publicJwk);
        using var ecPublic = ECDsa.Create(publicParameters);

        SignVerify(ecPublic, ecPrivate, privateJwk.Alg);
    }

    /// <summary>
    /// Загрузка из эфемерного сертификата
    /// </summary>
    [Fact]
    public void LoadEphemeralX509()
    {
        const string alg = SecurityAlgorithms.EcdsaSha384;
        var hashingAlg = GetHashingFunc(alg);

        using var ecDsa = ECDsa.Create(GetCurve("P-384"));
        var req = new CertificateRequest("C=RU, CN=ZeVS", ecDsa, hashingAlg);
        var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddMinutes(1));

        var rsaPrivate = cert.GetECDsaPrivateKey();
        var rsaPublic = cert.GetECDsaPublicKey();

        Assert.NotNull(rsaPublic);
        Assert.NotNull(rsaPrivate);

        SignVerify(rsaPublic, rsaPrivate, alg);
    }

    /// <summary>
    /// Использование CryptoProviderFactory для создания подписи и её проверки
    /// </summary>
    [Fact]
    public void UsingCryptoProviderFactory()
    {
        const string alg = SecurityAlgorithms.EcdsaSha256;

        using var ecDsa = ECDsa.Create(GetCurve("P-256"));

        var signer = CryptoProviderFactory.Default.CreateForSigning(new ECDsaSecurityKey(ecDsa), alg);
        var verifier = CryptoProviderFactory.Default.CreateForVerifying(new ECDsaSecurityKey(ecDsa), alg);

        var signature = signer.Sign(_data);
        Assert.True(verifier.Verify(_data, signature));
    }

    private static string GetPrivateJwk()
    {
        using var ecPrivate = ECDsa.Create();
        ecPrivate.ImportFromPem(File.ReadAllText("CertFiles/private-key.pem"));
        var ecParameters = ecPrivate.ExportParameters(true);

        var jwk = new JsonWebKey
        {
            Kty = "EC",
            Alg = SecurityAlgorithms.EcdsaSha256,
            Crv = GetCurveName(ecParameters.Curve),
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

    private static string GetPublicJwk()
    {
        using var ecPublic = ECDsa.Create();
        ecPublic.ImportFromPem(File.ReadAllText("CertFiles/public-key.pem"));
        var ecParameters = ecPublic.ExportParameters(false);

        var jwk = new JsonWebKey
        {
            Kty = "EC",
            Alg = SecurityAlgorithms.EcdsaSha256,
            Crv = GetCurveName(ecParameters.Curve),
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
        Curve = GetCurve(jwk.Crv),
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
        var hashingAlg = GetHashingFunc(alg);

        var signature = ecPrivate.SignData(_data, hashingAlg);
        var result = ecPublic.VerifyData(_data, signature, hashingAlg);
        Assert.True(result);
    }

    private static HashAlgorithmName GetHashingFunc(string alg) => alg switch
    {
        SecurityAlgorithms.EcdsaSha256 => HashAlgorithmName.SHA256,
        SecurityAlgorithms.EcdsaSha384 => HashAlgorithmName.SHA384,
        SecurityAlgorithms.EcdsaSha512 => HashAlgorithmName.SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(alg), "Не известный алгоритм")
    };

    private static string GetCurveName(ECCurve curve) => curve.Oid.FriendlyName switch
    {
        nameof(ECCurve.NamedCurves.nistP256) => "P-256",
        nameof(ECCurve.NamedCurves.nistP384) => "P-384",
        nameof(ECCurve.NamedCurves.nistP521) => "P-521",
        _ => throw new ArgumentOutOfRangeException(nameof(curve), "Не известная кривая")
    };

    private static ECCurve GetCurve(string crv) => crv switch
    {
        "P-256" => ECCurve.NamedCurves.nistP256,
        "P-384" => ECCurve.NamedCurves.nistP384,
        "P-521" => ECCurve.NamedCurves.nistP521,
        _ => throw new ArgumentOutOfRangeException(nameof(crv), "Не известная кривая")
    };
}
