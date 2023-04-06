using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Zevs.Samples.Rsa;

public class Rsa
{
    private readonly byte[] _data = Encoding.UTF8.GetBytes("Cryptography is cool!");

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

    [Fact]
    public void LoadFromJwk()
    {
        var privateJwkJson = GetPrivateJwk();
        var privateJwk = new JsonWebKey(privateJwkJson);

        var publicJwkJson = GetPublicJwk();
        var publicJwk = new JsonWebKey(publicJwkJson);

        Assert.Equal(publicJwk.Kty, nameof(RSA));
        Assert.Equal(publicJwk.Kty, privateJwk.Kty);
        Assert.Equal(publicJwk.Alg, privateJwk.Alg);

        var privateParameters = GetFromJwk(privateJwk);
        using var rsaPrivate = RSA.Create(privateParameters);

        var publicParameters = GetFromJwk(publicJwk);
        using var rsaPublic = RSA.Create(publicParameters);

        SignVerify(rsaPublic, rsaPrivate, privateJwk.Alg);
        EncryptingVerify(rsaPublic, rsaPrivate);
    }

    [Fact]
    public void LoadPssFromJwk()
    {
        var privateJwkJson = GetPrivateJwk(SecurityAlgorithms.RsaSsaPssSha256);
        var privateJwk = new JsonWebKey(privateJwkJson);

        var publicJwkJson = GetPublicJwk(SecurityAlgorithms.RsaSsaPssSha256);
        var publicJwk = new JsonWebKey(publicJwkJson);

        Assert.Equal(publicJwk.Kty, nameof(RSA));
        Assert.Equal(publicJwk.Kty, privateJwk.Kty);
        Assert.Equal(publicJwk.Alg, privateJwk.Alg);

        var privateParameters = GetFromJwk(privateJwk);
        using var rsaPrivate = RSA.Create(privateParameters);

        var publicParameters = GetFromJwk(publicJwk);
        using var rsaPublic = RSA.Create(publicParameters);

        SignVerify(rsaPublic, rsaPrivate, privateJwk.Alg);
        EncryptingVerify(rsaPublic, rsaPrivate);
    }

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

    private void SignVerify(RSA rsaPublic, RSA rsaPrivate, string alg = SecurityAlgorithms.RsaSha256)
    {
        var padding = GetPadding(alg);
        var hashingAlg = GetHashingFunc(alg);

        var signature = rsaPrivate.SignData(_data, hashingAlg, padding);
        var result = rsaPublic.VerifyData(_data, signature, hashingAlg, padding);
        Assert.True(result);
    }

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
        using var rsaPrivate = RSA.Create();
        rsaPrivate.ImportFromPem(File.ReadAllText("CertFiles/public-key.pem"));

        var rsaParameters = rsaPrivate.ExportParameters(false);

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