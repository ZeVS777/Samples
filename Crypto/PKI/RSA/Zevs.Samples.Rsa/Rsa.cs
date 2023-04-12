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
    /// Использование алгоритма
    /// </summary>
    public enum AlgorithmUsing
    {
        /// <summary>
        /// Подпись
        /// </summary>
        Signing,

        /// <summary>
        /// Шифрование
        /// </summary>
        Encryption
    }

    public static TheoryData<AlgorithmUsing, string> RsaAlgorithms = new()
    {
        { AlgorithmUsing.Signing, SecurityAlgorithms.RsaSha256 },
        { AlgorithmUsing.Signing, SecurityAlgorithms.RsaSha384 },
        { AlgorithmUsing.Signing, SecurityAlgorithms.RsaSha512 },
        { AlgorithmUsing.Signing, SecurityAlgorithms.RsaSsaPssSha256 },
        { AlgorithmUsing.Signing, SecurityAlgorithms.RsaSsaPssSha384 },
        { AlgorithmUsing.Signing, SecurityAlgorithms.RsaSsaPssSha512 },
        { AlgorithmUsing.Encryption, SecurityAlgorithms.RsaPKCS1 },
        { AlgorithmUsing.Encryption, SecurityAlgorithms.RsaOAEP },
        { AlgorithmUsing.Encryption, "RSA-OAEP-256" }
    };

    /// <summary>
    /// Загрузка RSA из файлов приватного и публичного ключа (PEM)
    /// </summary>
    [Theory]
    [MemberData(nameof(RsaAlgorithms))]
    public void LoadFromPem(AlgorithmUsing algorithmUsing, string alg)
    {
        using var rsaPrivate = RSA.Create();
        rsaPrivate.ImportFromPem(File.ReadAllText("CertFiles/private-key.pem"));

        using var rsaPublic = RSA.Create();
        rsaPublic.ImportFromPem(File.ReadAllText("CertFiles/public-key.pem"));

        if (algorithmUsing == AlgorithmUsing.Signing)
            SignVerify(rsaPublic, rsaPrivate, alg);
        else
            EncryptingVerify(rsaPublic, rsaPrivate, alg);
    }

    /// <summary>
    /// Загрузка RSA из X.509 (pem)
    /// </summary>
    [Theory]
    [MemberData(nameof(RsaAlgorithms))]
    public void LoadFromCertPem(AlgorithmUsing algorithmUsing, string alg)
    {
        using var rsaPrivate = RSA.Create();
        rsaPrivate.ImportFromPem(File.ReadAllText("CertFiles/private-key.pem"));

        var cert = X509Certificate2.CreateFromPem(File.ReadAllText("CertFiles/cert.pem"));
        using var rsaPublic = cert.GetRSAPublicKey();

        Assert.NotNull(rsaPublic);

        if (algorithmUsing == AlgorithmUsing.Signing)
            SignVerify(rsaPublic, rsaPrivate, alg);
        else
            EncryptingVerify(rsaPublic, rsaPrivate, alg);
    }

    /// <summary>
    /// Загрузка RSA из X.509 (pfx)
    /// </summary>
    [Theory]
    [MemberData(nameof(RsaAlgorithms))]
    public void LoadFromCertPfx(AlgorithmUsing algorithmUsing, string alg)
    {
        var pfx = X509Certificate.CreateFromCertFile("CertFiles/cert.pfx");
        var cert = new X509Certificate2(pfx);

        using var rsaPrivate = cert.GetRSAPrivateKey();
        using var rsaPublic = cert.GetRSAPublicKey();
        Assert.NotNull(rsaPublic);
        Assert.NotNull(rsaPrivate);

        if (algorithmUsing == AlgorithmUsing.Signing)
            SignVerify(rsaPublic, rsaPrivate, alg);
        else
            EncryptingVerify(rsaPublic, rsaPrivate, alg);
    }

    /// <summary>
    /// Загрузка RSA из JWK
    /// </summary>
    [Theory]
    [MemberData(nameof(RsaAlgorithms))]
    public void LoadFromJwk(AlgorithmUsing algorithmUsing, string alg)
    {
        var privateJwkJson = GetPrivateJwk(algorithmUsing, alg);
        var privateJwk = new JsonWebKey(privateJwkJson);

        var publicJwkJson = GetPublicJwk(algorithmUsing, alg);
        var publicJwk = new JsonWebKey(publicJwkJson);

        Assert.Equal(nameof(RSA), publicJwk.Kty);
        Assert.Equal(publicJwk.Kty, privateJwk.Kty);
        Assert.Equal(publicJwk.Alg, privateJwk.Alg);
        Assert.Equal(publicJwk.Use, privateJwk.Use);

        var privateParameters = GetFromJwk(privateJwk);
        using var rsaPrivate = RSA.Create(privateParameters);

        var publicParameters = GetFromJwk(publicJwk);
        using var rsaPublic = RSA.Create(publicParameters);

        if (publicJwk.Use == "sig")
            SignVerify(rsaPublic, rsaPrivate, publicJwk.Alg);
        else
            EncryptingVerify(rsaPublic, rsaPrivate, publicJwk.Alg);
    }

    /// <summary>
    /// Загрузка из эфемерного сертификата
    /// </summary>
    [Theory]
    [MemberData(nameof(RsaAlgorithms))]
    public void LoadEphemeralX509(AlgorithmUsing algorithmUsing, string alg)
    {
        var padding = algorithmUsing == AlgorithmUsing.Signing ? GetSignaturePadding(alg) : RSASignaturePadding.Pkcs1;
        var hashingAlg = algorithmUsing == AlgorithmUsing.Signing ? GetHashingFunc(alg) : HashAlgorithmName.SHA256;

        using var rsa = RSA.Create(3072);
        var req = new CertificateRequest("C=RU, CN=ZeVS", rsa, hashingAlg, padding);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            algorithmUsing == AlgorithmUsing.Signing ? X509KeyUsageFlags.DigitalSignature : X509KeyUsageFlags.KeyEncipherment,
            critical: true));
        var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddMinutes(1));

        var rsaPrivate = cert.GetRSAPrivateKey();
        var rsaPublic = cert.GetRSAPublicKey();

        Assert.NotNull(rsaPublic);
        Assert.NotNull(rsaPrivate);

        if (algorithmUsing == AlgorithmUsing.Signing)
            SignVerify(rsaPublic, rsaPrivate, alg);
        else
            EncryptingVerify(rsaPublic, rsaPrivate, alg);
    }

    /// <summary>
    /// Использование CryptoProviderFactory для создания подписи и её проверки
    /// </summary>
    [Theory]
    [MemberData(nameof(RsaAlgorithms))]
    public void UsingCryptoProviderFactory(AlgorithmUsing algorithmUsing, string alg)
    {
        using var rsa = RSA.Create(3072);
        var key = alg == "RSA-OAEP-256" ? new CustomRsaSecurityKey(rsa) : new RsaSecurityKey(rsa);

        if (algorithmUsing == AlgorithmUsing.Signing)
        {
            var cryptoProviderFactory = key.CryptoProviderFactory;
            var signer = cryptoProviderFactory.CreateForSigning(key, alg);
            var verifier = cryptoProviderFactory.CreateForVerifying(key, alg);
            var signature = signer.Sign(_data);
            Assert.True(verifier.Verify(_data, signature));
        }
        else
        {
            var enc = key.CryptoProviderFactory.CreateKeyWrapProvider(key, alg);
            var encrypted = enc.WrapKey(_data);
            var decrypted = enc.UnwrapKey(encrypted);

            Assert.Equal(_data, decrypted);
        }
    }

    /// <summary>
    /// Подпись данных и её проверка
    /// </summary>
    /// <param name="rsaPublic">Публичный ключ, которым производится проверка подписи</param>
    /// <param name="rsaPrivate">Приватный ключ, которым подписываются данные</param>
    /// <param name="alg">Алгоритм, выбранный для проведения процедуры подписывания</param>
    private void SignVerify(RSA rsaPublic, RSA rsaPrivate, string alg)
    {
        var padding = GetSignaturePadding(alg);
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
    /// <param name="alg">Алгоритм шифрования</param>
    private void EncryptingVerify(RSA rsaPublic, RSA rsaPrivate, string alg)
    {
        var padding = GetEncryptionPadding(alg);
        var encryptedData = rsaPublic.Encrypt(_data, padding);
        var decrypted = rsaPrivate.Decrypt(encryptedData, padding);
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

    private static RSASignaturePadding GetSignaturePadding(string alg) => alg switch
    {
        SecurityAlgorithms.RsaSha256 => RSASignaturePadding.Pkcs1,
        SecurityAlgorithms.RsaSsaPssSha256 => RSASignaturePadding.Pss,
        SecurityAlgorithms.RsaSha384 => RSASignaturePadding.Pkcs1,
        SecurityAlgorithms.RsaSsaPssSha384 => RSASignaturePadding.Pss,
        SecurityAlgorithms.RsaSha512 => RSASignaturePadding.Pkcs1,
        SecurityAlgorithms.RsaSsaPssSha512 => RSASignaturePadding.Pss,
        _ => throw new ArgumentOutOfRangeException(nameof(alg), "Не известный алгоритм")
    };

    private static RSAEncryptionPadding GetEncryptionPadding(string alg) => alg switch
    {
        SecurityAlgorithms.RsaOAEP => RSAEncryptionPadding.OaepSHA1,
        "RSA-OAEP-256" => RSAEncryptionPadding.OaepSHA256,
        SecurityAlgorithms.RsaPKCS1 => RSAEncryptionPadding.Pkcs1,
        _ => throw new ArgumentOutOfRangeException(nameof(alg), "Не известный алгоритм")
    };

    private static string GetPrivateJwk(AlgorithmUsing algorithmUsing, string alg)
    {
        using var rsaPrivate = RSA.Create();
        rsaPrivate.ImportFromPem(File.ReadAllText("CertFiles/private-key.pem"));
        var rsaParameters = rsaPrivate.ExportParameters(true);

        var jwk = new JsonWebKey
        {
            Kty = nameof(RSA),
            Alg = alg,
            Use = algorithmUsing == AlgorithmUsing.Signing ? "sig" : "enc",
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

    private static string GetPublicJwk(AlgorithmUsing algorithmUsing, string alg)
    {
        using var rsaPublic = RSA.Create();
        rsaPublic.ImportFromPem(File.ReadAllText("CertFiles/public-key.pem"));
        var rsaParameters = rsaPublic.ExportParameters(false);

        var jwk = new JsonWebKey
        {
            Kty = nameof(RSA),
            Alg = alg,
            Use = algorithmUsing == AlgorithmUsing.Signing ? "sig" : "enc",
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
