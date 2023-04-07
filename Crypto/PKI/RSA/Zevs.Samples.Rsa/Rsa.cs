using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Zevs.Samples.Rsa;

/// <summary>
/// Примеры загрузки и использования RSA
/// </summary>
public class Rsa
{
    private readonly byte[] _data = Encoding.UTF8.GetBytes("Криптография - круто!");

    /// <summary>
    /// Загрузка RSA из файлов приватного и публичного ключа (PEM)
    /// </summary>
    [Fact]
    public void LoadFromPem()
    {
        using var rsaPrivate = RSA.Create();
        rsaPrivate.ImportFromPem(File.ReadAllText("CertFiles/private-key.pem"));

        using var rsaPublic = RSA.Create();
        rsaPublic.ImportFromPem(File.ReadAllText("CertFiles/public-key.pem"));

        SignVerify(rsaPublic, rsaPrivate);
        EncryptingVerify(rsaPublic, rsaPrivate);
    }

    /// <summary>
    /// Загрузка RSA из X.509 (pem)
    /// </summary>
    [Fact]
    public void LoadFromCertPem()
    {
        using var rsaPrivate = RSA.Create();
        rsaPrivate.ImportFromPem(File.ReadAllText("CertFiles/private-key.pem"));

        var cert = X509Certificate2.CreateFromPem(File.ReadAllText("CertFiles/cert.pem"));
        using var rsaPublic = cert.GetRSAPublicKey();

        Assert.NotNull(rsaPublic);

        SignVerify(rsaPublic, rsaPrivate);
        EncryptingVerify(rsaPublic, rsaPrivate);
    }

    /// <summary>
    /// Загрузка RSA из X.509 (pfx)
    /// </summary>
    [Fact]
    public void LoadFromCertPfx()
    {
        var pfx = X509Certificate.CreateFromCertFile("CertFiles/cert.pfx");
        var cert = new X509Certificate2(pfx);

        using var rsaPrivate = cert.GetRSAPrivateKey();
        using var rsaPublic = cert.GetRSAPublicKey();
        Assert.NotNull(rsaPublic);
        Assert.NotNull(rsaPrivate);

        SignVerify(rsaPublic, rsaPrivate);
        EncryptingVerify(rsaPublic, rsaPrivate);
    }

    /// <summary>
    /// Загрузка RSA из JWK (HS256)
    /// </summary>
    [Fact]
    public void LoadFromJwk()
    {
        var privateJwkJson = GetPrivateJwk();
        var privateJwk = new JsonWebKey(privateJwkJson);

        var publicJwkJson = GetPublicJwk();
        var publicJwk = new JsonWebKey(publicJwkJson);

        Assert.Equal(nameof(RSA), publicJwk.Kty);
        Assert.Equal(publicJwk.Kty, privateJwk.Kty);
        Assert.Equal(publicJwk.Alg, privateJwk.Alg);

        var privateParameters = GetFromJwk(privateJwk);
        using var rsaPrivate = RSA.Create(privateParameters);

        var publicParameters = GetFromJwk(publicJwk);
        using var rsaPublic = RSA.Create(publicParameters);

        SignVerify(rsaPublic, rsaPrivate, privateJwk.Alg);
        EncryptingVerify(rsaPublic, rsaPrivate);
    }

    /// <summary>
    /// Загрузка RSA из JWK (PS256)
    /// </summary>
    [Fact]
    public void LoadPssFromJwk()
    {
        var privateJwkJson = GetPrivateJwk(SecurityAlgorithms.RsaSsaPssSha256);
        var privateJwk = new JsonWebKey(privateJwkJson);

        var publicJwkJson = GetPublicJwk(SecurityAlgorithms.RsaSsaPssSha256);
        var publicJwk = new JsonWebKey(publicJwkJson);

        Assert.Equal(nameof(RSA), publicJwk.Kty);
        Assert.Equal(publicJwk.Kty, privateJwk.Kty);
        Assert.Equal(publicJwk.Alg, privateJwk.Alg);

        var privateParameters = GetFromJwk(privateJwk);
        using var rsaPrivate = RSA.Create(privateParameters);

        var publicParameters = GetFromJwk(publicJwk);
        using var rsaPublic = RSA.Create(publicParameters);

        SignVerify(rsaPublic, rsaPrivate, privateJwk.Alg);
        EncryptingVerify(rsaPublic, rsaPrivate);
    }

    /// <summary>
    /// Загрузка из эфемерного сертификата
    /// </summary>
    [Fact]
    public void LoadEphemeralX509()
    {
        const string alg = SecurityAlgorithms.RsaSha384;
        var padding = GetPadding(alg);
        var hashingAlg = GetHashingFunc(alg);

        using var rsa = RSA.Create(3072);
        var req = new CertificateRequest("C=RU, CN=ZeVS", rsa, hashingAlg, padding);
        var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddMinutes(1));

        var rsaPrivate = cert.GetRSAPrivateKey();
        var rsaPublic = cert.GetRSAPublicKey();

        Assert.NotNull(rsaPublic);
        Assert.NotNull(rsaPrivate);

        SignVerify(rsaPublic, rsaPrivate, alg);
        EncryptingVerify(rsaPublic, rsaPrivate);
    }

    /// <summary>
    /// Использование CryptoProviderFactory для создания подписи и её проверки
    /// </summary>
    [Fact]
    public void UsingCryptoProviderFactory()
    {
        const string alg = SecurityAlgorithms.RsaSsaPssSha256;

        using var rsa = RSA.Create(3072);

        var signer = CryptoProviderFactory.Default.CreateForSigning(new RsaSecurityKey(rsa), alg);
        var verifier = CryptoProviderFactory.Default.CreateForVerifying(new RsaSecurityKey(rsa), alg);

        var signature = signer.Sign(_data);
        Assert.True(verifier.Verify(_data, signature));
    }

    /// <summary>
    /// Подпись данных и её проверка
    /// </summary>
    /// <param name="rsaPublic">Публичный ключ, которым производится проверка подписи</param>
    /// <param name="rsaPrivate">Приватный ключ, которым подписываются данные</param>
    /// <param name="alg">Алгоритм, выбранный для проведения процедуры подписывания</param>
    private void SignVerify(RSA rsaPublic, RSA rsaPrivate, string alg = SecurityAlgorithms.RsaSha256)
    {
        var padding = GetPadding(alg);
        var hashingAlg = GetHashingFunc(alg);

        var signature = rsaPrivate.SignData(_data, hashingAlg, padding);
        var result = rsaPublic.VerifyData(_data, signature, hashingAlg, padding);
        Assert.True(result);
    }

    /// <summary>
    /// Шифрование и расшифровка данных
    /// </summary>
    /// <param name="rsaPublic">Публичный ключ, которым производится шифрование</param>
    /// <param name="rsaPrivate">Приватный ключ, которым производится расшифровка</param>
    private void EncryptingVerify(RSA rsaPublic, RSA rsaPrivate)
    {
        var encryptedData = rsaPublic.Encrypt(_data, RSAEncryptionPadding.Pkcs1);
        var decrypted = rsaPrivate.Decrypt(encryptedData, RSAEncryptionPadding.Pkcs1);
        Assert.Equal(decrypted, _data);
    }

    private static HashAlgorithmName GetHashingFunc(string alg) => alg switch
    {
        SecurityAlgorithms.RsaSha256 => HashAlgorithmName.SHA256,
        SecurityAlgorithms.RsaSsaPssSha256 => HashAlgorithmName.SHA256,
        SecurityAlgorithms.RsaSha384 => HashAlgorithmName.SHA384,
        SecurityAlgorithms.RsaSsaPssSha384 => HashAlgorithmName.SHA384,
        SecurityAlgorithms.RsaSha512 => HashAlgorithmName.SHA512,
        SecurityAlgorithms.RsaSsaPssSha512 => HashAlgorithmName.SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(alg), "Не известный алгоритм")
    };

    private static RSASignaturePadding GetPadding(string alg) => alg switch
    {
        SecurityAlgorithms.RsaSha256 => RSASignaturePadding.Pkcs1,
        SecurityAlgorithms.RsaSsaPssSha256 => RSASignaturePadding.Pss,
        SecurityAlgorithms.RsaSha384 => RSASignaturePadding.Pkcs1,
        SecurityAlgorithms.RsaSsaPssSha384 => RSASignaturePadding.Pss,
        SecurityAlgorithms.RsaSha512 => RSASignaturePadding.Pkcs1,
        SecurityAlgorithms.RsaSsaPssSha512 => RSASignaturePadding.Pss,
        _ => throw new ArgumentOutOfRangeException(nameof(alg), "Не известный алгоритм")
    };

    private static string GetPrivateJwk(string alg = SecurityAlgorithms.RsaSha256)
    {
        using var rsaPrivate = RSA.Create();
        rsaPrivate.ImportFromPem(File.ReadAllText("CertFiles/private-key.pem"));
        var rsaParameters = rsaPrivate.ExportParameters(true);

        if (alg != SecurityAlgorithms.RsaSha256 && alg != SecurityAlgorithms.RsaSsaPssSha256) 
            throw new ArgumentException("Приватный ключ в PEM файле подготовлен для RSA 256 bit", nameof(alg));

        var jwk = new JsonWebKey
        {
            Kty = nameof(RSA),
            Alg = alg,
            //Если ключ будет использоваться только для подписи
            //Use = "sig",
            //Если ключ будет использоваться только для шифрования
            //Use = "enc",
            N = Base64UrlEncoder.Encode(rsaParameters.Modulus),
            E = Base64UrlEncoder.Encode(rsaParameters.Exponent),
            D = Base64UrlEncoder.Encode(rsaParameters.D),
            P = Base64UrlEncoder.Encode(rsaParameters.P),
            Q = Base64UrlEncoder.Encode(rsaParameters.Q),
            DP = Base64UrlEncoder.Encode(rsaParameters.DP),
            DQ = Base64UrlEncoder.Encode(rsaParameters.DQ),
            QI = Base64UrlEncoder.Encode(rsaParameters.InverseQ)
        };

        return GetFormattedJwk(jwk);
    }

    private static string GetPublicJwk(string alg = SecurityAlgorithms.RsaSha256)
    {
        using var rsaPublic = RSA.Create();
        rsaPublic.ImportFromPem(File.ReadAllText("CertFiles/public-key.pem"));
        var rsaParameters = rsaPublic.ExportParameters(false);

        var jwk = new JsonWebKey
        {
            Kty = nameof(RSA),
            Alg = alg,
            //Если ключ будет использоваться только для подписи
            //Use = "sig",
            //Если ключ будет использоваться только для шифрования
            //Use = "enc",
            N = Base64UrlEncoder.Encode(rsaParameters.Modulus),
            E = Base64UrlEncoder.Encode(rsaParameters.Exponent)
        };

        return GetFormattedJwk(jwk);
    }

    private static string GetFormattedJwk(JsonWebKey jwk)
    {
        var json = JsonExtensions.SerializeToJson(jwk);

        //jwk уже готов, но для простоты чтения человеком, давайте отформатируем
        var obj = JsonSerializer.Deserialize<object>(json);
        var formatted = JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = true });

        return formatted;
    }

    private static RSAParameters GetFromJwk(JsonWebKey jwk) => new()
    {
        Modulus = Base64UrlEncoder.DecodeBytes(jwk.N),
        Exponent = Base64UrlEncoder.DecodeBytes(jwk.E),
        //Приватные параметры
        D = string.IsNullOrEmpty(jwk.D) ? null : Base64UrlEncoder.DecodeBytes(jwk.D),
        P = string.IsNullOrEmpty(jwk.P) ? null : Base64UrlEncoder.DecodeBytes(jwk.P),
        Q = string.IsNullOrEmpty(jwk.Q) ? null : Base64UrlEncoder.DecodeBytes(jwk.Q),
        DP = string.IsNullOrEmpty(jwk.DP) ? null : Base64UrlEncoder.DecodeBytes(jwk.DP),
        DQ = string.IsNullOrEmpty(jwk.DQ) ? null : Base64UrlEncoder.DecodeBytes(jwk.DQ),
        InverseQ = string.IsNullOrEmpty(jwk.QI) ? null : Base64UrlEncoder.DecodeBytes(jwk.QI)
    };
}
