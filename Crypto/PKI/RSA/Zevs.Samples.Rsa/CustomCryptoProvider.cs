using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Zevs.Samples.Rsa;

/// <summary>
/// Самописный провайдер криптографических функций для поддержки дополнительных алгоритмов
/// </summary>
public class CustomCryptoProvider : ICryptoProvider
{
    /// <inheritdoc />
    public bool IsSupportedAlgorithm(string algorithm, params object[] args) => algorithm == "RSA-OAEP-256";

    /// <inheritdoc />
    public object Create(string algorithm, params object[] args)
    {
        if (algorithm != "RSA-OAEP-256" || args[0] is not CustomRsaSecurityKey key)
            throw new NotSupportedException();

        return new CustomKeyWrapProviderProvider(key, algorithm, (bool) args[1]);
    }

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
public class CustomRsaSecurityKey : RsaSecurityKey
{
    /// <summary>
    /// Создать новый экземпляр <see cref="CustomRsaSecurityKey" />.
    /// </summary>
    /// <param name="rsa"><see cref="RSA" /></param>
    public CustomRsaSecurityKey(RSA rsa) : base(rsa) => CryptoProviderFactory.CustomCryptoProvider = new CustomCryptoProvider();
}

/// <summary>
/// Самописный провайдер функций шифрования ключей с поддержкой дополнительных алгоритмов
/// </summary>
public class CustomKeyWrapProviderProvider : RsaKeyWrapProvider
{
    /// <summary>
    /// Создать новый экземпляр <see cref="CustomKeyWrapProviderProvider"/>
    /// </summary>
    /// <param name="key">Ключ безопасности</param>
    /// <param name="algorithm">Алгоритм, используемый при создании и проверке подписи</param>
    /// <param name="willUnwrap">Whether this <see cref="T:Microsoft.IdentityModel.Tokens.RsaKeyWrapProvider" /> is required to un-wrap keys. If true, the private key is required.</param>
    public CustomKeyWrapProviderProvider(CustomRsaSecurityKey key, string algorithm, bool willUnwrap) : 
        base(key, algorithm, willUnwrap) => Key = key;

    protected override void Dispose(bool disposing)
    {
    }

    /// <inheritdoc />
    public override byte[] UnwrapKey(byte[] keyBytes) => Key.Rsa.Decrypt(keyBytes, RSAEncryptionPadding.OaepSHA256);

    /// <inheritdoc />
    public override byte[] WrapKey(byte[] keyBytes) => Key.Rsa.Encrypt(keyBytes, RSAEncryptionPadding.OaepSHA256);

    /// <inheritdoc />
    public override CustomRsaSecurityKey Key { get; }
}
