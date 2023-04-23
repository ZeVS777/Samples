using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Zevs.Samples.EC;

/// <summary>
/// Самописный провайдер криптографических функций для поддержки дополнительных алгоритмов
/// </summary>
public class CustomCryptoProvider : ICryptoProvider
{
    /// <inheritdoc />
    public bool IsSupportedAlgorithm(string algorithm, params object[] args) => algorithm 
        is "ES256K" 
        or SecurityAlgorithms.Aes128Gcm
        or SecurityAlgorithms.Aes256Gcm
        or SecurityAlgorithms.Aes192Gcm;

    /// <inheritdoc />
    public object Create(string algorithm, params object[] args) => algorithm switch
    {
        "ES256K" when args[0] is CustomEcDsaSecurityKey es => new CustomSignatureProvider(es, algorithm),
        SecurityAlgorithms.Aes128Gcm or SecurityAlgorithms.Aes256Gcm or SecurityAlgorithms.Aes192Gcm when args[0] is SecurityKey key =>
            new CustomAuthenticatedEncryptionProvider(key, algorithm),
        _ => throw new NotSupportedException()
    };

    /// <inheritdoc />
    public void Release(object cryptoInstance)
    {
        if (cryptoInstance is IDisposable disposableObject)
            disposableObject.Dispose();
    }
}

/// <summary>
/// Самописный ключ безопасности с поддержкой <see cref="CustomCryptoProvider"/>
/// </summary>
public class CustomEcDsaSecurityKey : ECDsaSecurityKey
{
    /// <summary>
    /// Создать новый экземпляр <see cref="CustomEcDsaSecurityKey" />.
    /// </summary>
    /// <param name="ecdsa"><see cref="T:System.Security.Cryptography.ECDsa" /></param>
    public CustomEcDsaSecurityKey(ECDsa ecdsa) : base(ecdsa) => CryptoProviderFactory.CustomCryptoProvider = new CustomCryptoProvider();
}

/// <summary>
/// Самописный провайдер функций создания подписей и её проверки с поддержкой дополнительных алгоритмов
/// </summary>
public class CustomSignatureProvider : SignatureProvider
{
    /// <summary>
    /// Создать новый экземпляр <see cref="CustomSignatureProvider"/>
    /// </summary>
    /// <param name="key">Ключ безопасности</param>
    /// <param name="algorithm">Алгоритм, используемый при создании и проверке подписи</param>
    /// <exception cref="NotSupportedException">Алгоритм или ключ не поддерживаются</exception>
    public CustomSignatureProvider(CustomEcDsaSecurityKey key, string algorithm) : base(key, algorithm) { }

    protected override void Dispose(bool disposing) { }

    /// <summary>
    /// Создаёт подпись 'input' используя <see cref="CustomEcDsaSecurityKey" /> и алгоритм, заданный в <see cref="CustomSignatureProvider(CustomEcDsaSecurityKey,string)" />.
    /// </summary>
    /// <param name="input">Байты, которые требуется подписать.</param>
    /// <returns>Подпись input.</returns>
    public override byte[] Sign(byte[] input) => ((CustomEcDsaSecurityKey)Key).ECDsa.SignData(input, HashAlgorithmName.SHA256);

    /// <summary>
    /// Подтверждает, что подпись <paramref name="signature"/> входных данных <paramref name="input"/>, использующая
    /// <see cref="SecurityKey"/> и <see cref="SignatureProvider.Algorithm"/>, описанных в
    /// <see cref="SignatureProvider"/>, согласованы.
    /// </summary>
    /// <param name="input">Байты, которые требуется подписать.</param>
    /// <param name="signature">Подпись, которую требуется проверить.</param>
    public override bool Verify(byte[] input, byte[] signature) => 
        ((CustomEcDsaSecurityKey)Key).ECDsa.VerifyData(input, signature, HashAlgorithmName.SHA256);
}

/// <summary>
/// Самописный провайдер функций шифрования с поддержкой дополнительных алгоритмов
/// </summary>
public class CustomAuthenticatedEncryptionProvider : AuthenticatedEncryptionProvider
{
    public CustomAuthenticatedEncryptionProvider(SecurityKey key, string algorithm) : base(key, algorithm) { }

    public override AuthenticatedEncryptionResult Encrypt(byte[] plaintext, byte[] authenticatedData)
    {
        using var aesGcm = new AesGcm(((SymmetricSecurityKey)Key).Key);
        var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
        RandomNumberGenerator.Fill(nonce);
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        var cipherText = new byte[plaintext.Length];
        aesGcm.Encrypt(nonce, plaintext, cipherText, tag, authenticatedData);

        return new AuthenticatedEncryptionResult(Key, cipherText, nonce, tag);
    }
}
