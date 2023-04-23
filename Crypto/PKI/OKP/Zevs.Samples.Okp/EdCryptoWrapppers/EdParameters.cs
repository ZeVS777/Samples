using System.Runtime.Versioning;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Zevs.Samples.Okp.EdCryptoWrapppers;

/// <summary>
/// Настройки алгоритма, основанного на кривых Эдвардса
/// </summary>
[UnsupportedOSPlatform("browser")]
public struct EdParameters
{
    /// <summary>
    /// Создать экземпляр класса <see cref="EdParameters"/>
    /// </summary>
    /// <param name="parameter">Информация о приватном или публичном ключе</param>
    /// <param name="curve">Тип используемой кривой</param>
    /// <exception cref="NotSupportedException">Кривая указана неверно или алгоритмом не поддерживается</exception>
    public EdParameters(AsymmetricKeyParameter parameter, string curve)
    {
        (X, D) = (null, null);

        switch (curve)
        {
            case SecurityAlgorithmsAdditional.NamedCurves.Curve25519:
                {
                    if (parameter.IsPrivate)
                        D = ((Ed25519PrivateKeyParameters)parameter).GetEncoded();
                    else
                        X = ((Ed25519PublicKeyParameters)parameter).GetEncoded();
                    break;
                }
            case SecurityAlgorithmsAdditional.NamedCurves.Curve448:
                {
                    if (parameter.IsPrivate)
                        D = ((Ed448PrivateKeyParameters)parameter).GetEncoded();
                    else
                        X = ((Ed448PublicKeyParameters)parameter).GetEncoded();
                    break;
                }
            default: throw new NotSupportedException("Кривая указана неверно или алгоритмом не поддерживается");
        }

        Curve = curve;

        (PublicKey, PrivateKey) = parameter.IsPrivate ? ((AsymmetricKeyParameter?)null, parameter) : (parameter, null);
    }

    /// <summary>
    /// Создать экземпляр класса <see cref="EdParameters"/>
    /// </summary>
    /// <param name="keyPair">Информация о приватном и публичном ключе</param>
    /// <param name="curve">Тип используемой кривой</param>
    /// <exception cref="ArgumentNullException">Если параметры не указаны</exception>
    /// <exception cref="NotSupportedException">Кривая указана неверно или алгоритмом не поддерживается</exception>
    public EdParameters(AsymmetricCipherKeyPair keyPair, string curve)
    {
        if (keyPair == null) throw new ArgumentNullException(nameof(keyPair));

        if (string.IsNullOrWhiteSpace(curve)) throw new ArgumentNullException(nameof(curve));

        switch (curve)
        {
            case SecurityAlgorithmsAdditional.NamedCurves.Curve25519:
                D = ((Ed25519PrivateKeyParameters)keyPair.Private).GetEncoded();
                X = ((Ed25519PublicKeyParameters)keyPair.Public).GetEncoded();
                break;
            case SecurityAlgorithmsAdditional.NamedCurves.Curve448:
                D = ((Ed448PrivateKeyParameters)keyPair.Private).GetEncoded();
                X = ((Ed448PublicKeyParameters)keyPair.Public).GetEncoded();
                break;
            default:
                throw new NotSupportedException("Кривая указана неверно или алгоритмом не поддерживается");
        }

        Curve = curve;
        PublicKey = keyPair.Public;
        PrivateKey = keyPair.Private;
    }

    /// <summary>
    /// Приватное значение ключа <see langword="D" /> для алгоритма, основанного на кривых Эдвардса (EdDsa)
    /// </summary>
    public byte[]? D { get; }

    /// <summary>
    /// Публичное значение ключа <see langword="X" /> для алгоритма, основанного на кривых Эдвардса (EdDsa)
    /// </summary>
    public byte[]? X { get; }

    /// <summary>
    /// Кривая на основе которой построен алгоритм
    /// </summary>
    public string? Curve { get; }

    /// <summary>
    /// Публичный ключ
    /// </summary>
    public AsymmetricKeyParameter? PublicKey { get; }

    /// <summary>
    /// Приватный ключ
    /// </summary>
    public AsymmetricKeyParameter? PrivateKey { get; }

    /// <summary>
    /// Проверка настроек
    /// </summary>
    /// <exception cref="T:System.Security.Cryptography.CryptographicException">
    /// Параметры неверные
    /// </exception>
    public void Validate()
    {
        if (D == null && X == null) throw new CryptographicException("Не указаны ни публичный, ни приватный параметры");

        if (D != null)
            switch (Curve)
            {
                case SecurityAlgorithmsAdditional.NamedCurves.Curve25519 when D.Length != 32 && D.Length != 32 * 2:
                    throw new CryptographicException("Неверная длина ключа. Должна быть 32 байта.");
                case SecurityAlgorithmsAdditional.NamedCurves.Curve448 when D.Length != 57 && D.Length != 57 * 2:
                    throw new CryptographicException("Неверная длина ключа. Должна быть 57 байт.");
            }

        if (X != null)
            switch (Curve)
            {
                case SecurityAlgorithmsAdditional.NamedCurves.Curve25519 when X.Length != 32:
                    throw new CryptographicException("Неверная длина ключа. Должна быть 32 байта.");
                case SecurityAlgorithmsAdditional.NamedCurves.Curve448 when X.Length != 57:
                    throw new CryptographicException("Неверная длина ключа. Должна быть 57 байт.");
            }
    }
}
