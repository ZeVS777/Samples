using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Zevs.Samples.Okp.EdCryptoWrapppers;

namespace Zevs.Samples.Okp;

/// <summary>
/// Провайдер криптографических инструментов для поддержки алгоритмов, основанных на кривых Эдвардса
/// </summary>
public class EdDsaCryptoProvider : ICryptoProvider
{
    /// <inheritdoc />
    public bool IsSupportedAlgorithm(string algorithm, params object[] args) => algorithm == SecurityAlgorithmsAdditional.EdDsa;

    /// <inheritdoc />
    public object Create(string algorithm, params object[] args)
    {
        if (!IsSupportedAlgorithm(algorithm, args) || args[0] is not EdDsaSecurityKey key) throw new NotSupportedException();

        return new EdDsaSignatureProvider(key, algorithm);
    }

    /// <inheritdoc />
    public void Release(object cryptoInstance)
    {
        if (cryptoInstance is IDisposable disposableObject)
            disposableObject.Dispose();
    }
}

/// <summary>
/// EdDsa криптографический ключ
/// </summary>
public class EdDsaSecurityKey : AsymmetricSecurityKey
{
    /// <summary>
    /// Создать экземпляр класса <see cref="EdDsaSecurityKey" />.
    /// </summary>
    /// <param name="edDsa">Криптографический ключ <see cref="EdDsa" /></param>
    public EdDsaSecurityKey(EdDsa edDsa)
    {
        EdDsa = edDsa ?? throw LogHelper.LogArgumentNullException(nameof(edDsa));
        CryptoProviderFactory.CustomCryptoProvider = new EdDsaCryptoProvider();
    }

    /// <summary>
    /// <see cref="EdDsa" /> криптографический ключ
    /// </summary>
    public EdDsa EdDsa { get; }

    /// <inheritdoc />
    public override int KeySize => throw new NotImplementedException();

    /// <inheritdoc />
    [Obsolete("HasPrivateKey method is deprecated, please use FoundPrivateKey instead.")]
    public override bool HasPrivateKey => EdDsa.Parameters.D != null;

    /// <inheritdoc />
    public override PrivateKeyStatus PrivateKeyStatus => EdDsa.Parameters.D != null ?
        PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;
}

/// <summary>
/// Провайдер сервиса создания и проверки подписи, основанный на кривых Эдвардса
/// </summary>
public class EdDsaSignatureProvider : SignatureProvider
{
    /// <summary>
    /// Создать новый экземпляр класса <see cref="EdDsaSignatureProvider"/>
    /// </summary>
    /// <param name="key">EdDsa криптографический ключ</param>
    /// <param name="algorithm">Алгоритм подписи (поддерживается только OKT) </param>
    public EdDsaSignatureProvider(EdDsaSecurityKey key, string algorithm) : base(key, algorithm) { }

    protected override void Dispose(bool disposing) { }

    /// <summary>
    /// Создание подписи
    /// </summary>
    /// <param name="input">Входной массив байт, который требуется подписать</param>
    /// <returns>Массив байт, являющийся подписью</returns>
    public override byte[] Sign(byte[] input) => ((EdDsaSecurityKey)Key).EdDsa.Sign(input);

    /// <inheritdoc />
    public override bool Verify(byte[] input, byte[] signature) => ((EdDsaSecurityKey)Key).EdDsa.Verify(input, signature);

    /// <inheritdoc />
    public override bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength)
        => ((EdDsaSecurityKey)Key).EdDsa.Verify(input, inputOffset, inputLength, signature, signatureOffset, signatureLength);
}
