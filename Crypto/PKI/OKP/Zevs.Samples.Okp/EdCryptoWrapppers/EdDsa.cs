using System.Runtime.Versioning;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using NamedCurves = Zevs.Samples.Okp.EdCryptoWrapppers.SecurityAlgorithmsAdditional.NamedCurves;

namespace Zevs.Samples.Okp.EdCryptoWrapppers;

/// <summary>
/// Класс, инкапсулирующий алгоритм, основанный на кривых Эдвардса - Edwards-curve Digital Signature Algorithm (EdDSA)
/// </summary>
[UnsupportedOSPlatform("browser")]
public class EdDsa
{
    internal EdParameters Parameters { get; private set; }

    /// <summary>
    /// Создать новый ключ EdDSA на кривой по умолчанию
    /// </summary>
    /// <returns>Новый экземпляр класса <see cref="EdDsa" /></returns>
    public static EdDsa Create() => Create(NamedCurves.Curve25519);

    /// <summary>
    /// Создать новый ключ EdDSA
    /// </summary>
    /// <param name="curve">Создать ключ, основанный на Ed25519 или Ed448 кривых</param>
    /// <returns>Новый экземпляр класса <see cref="EdDsa" /></returns>
    public static EdDsa Create(string curve)
    {
        switch (curve)
        {
            case NamedCurves.Curve25519:
                {
                    var generator = new Ed25519KeyPairGenerator();
                    generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
                    var keyPair = generator.GenerateKeyPair();

                    return new EdDsa { Parameters = new EdParameters(keyPair, curve) };
                }
            case NamedCurves.Curve448:
                {
                    var generator = new Ed448KeyPairGenerator();
                    generator.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
                    var keyPair = generator.GenerateKeyPair();

                    return new EdDsa { Parameters = new EdParameters(keyPair, curve) };
                }
            case NamedCurves.CurveX25519:
                {
                    var generator = new X25519KeyPairGenerator();
                    generator.Init(new X25519KeyGenerationParameters(new SecureRandom()));
                    var keyPair = generator.GenerateKeyPair();

                    return new EdDsa { Parameters = new EdParameters(keyPair, curve) };
                }
            case NamedCurves.CurveX448:
                {
                    var generator = new X448KeyPairGenerator();
                    generator.Init(new X448KeyGenerationParameters(new SecureRandom()));
                    var keyPair = generator.GenerateKeyPair();

                    return new EdDsa { Parameters = new EdParameters(keyPair, curve) };
                }
            default:
                throw new NotSupportedException("Кривая указана неверно или алгоритмом не поддерживается");
        }
    }

    /// <summary>
    /// Создать новый ключ EdDSA
    /// </summary>
    /// <param name="parameters">Параметры, описывающие ключ</param>
    /// <returns>Новый экземпляр класса <see cref="EdDsa" /></returns>
    public static EdDsa Create(EdParameters parameters)
    {
        parameters.Validate();
        return new EdDsa { Parameters = parameters };
    }

    /// <summary>
    /// Импортировать ключ, указанный в PEM формате, заменяя ключи на указанные в файле
    /// </summary>
    /// <param name="input">PEM текст, описывающий ключ</param>
    public void ImportFromPem(string input)
    {
        var pem = new PemReader(new StringReader(input)).ReadObject();

        if (pem is X509Certificate certificate) pem = certificate.GetPublicKey();

        Parameters = pem switch
        {
            Ed25519PrivateKeyParameters privateParameters => new EdParameters(privateParameters, NamedCurves.Curve25519),
            Ed25519PublicKeyParameters publicParameters => new EdParameters(publicParameters, NamedCurves.Curve25519),
            Ed448PrivateKeyParameters privateParameters => new EdParameters(privateParameters, NamedCurves.Curve448),
            Ed448PublicKeyParameters publicParameters => new EdParameters(publicParameters, NamedCurves.Curve448),
            X25519PrivateKeyParameters privateParameters => new EdParameters(privateParameters, NamedCurves.Curve25519),
            X25519PublicKeyParameters publicParameters => new EdParameters(publicParameters, NamedCurves.Curve25519),
            X448PrivateKeyParameters privateParameters => new EdParameters(privateParameters, NamedCurves.Curve448),
            X448PublicKeyParameters publicParameters => new EdParameters(publicParameters, NamedCurves.Curve448),
            _ => throw new NotSupportedException("Формат файла или его содержимое не соответствует ожидаемым параметрам")
        };
    }

    /// <summary>
    /// Выполнить процедуру подписания
    /// </summary>
    /// <param name="input">Входной массив байт, который требуется подписать</param>
    /// <returns>Массив байт, являющийся подписью</returns>
    /// <exception cref="ArgumentNullException">Если не указан входной параметр</exception>
    public byte[] Sign(byte[] input)
    {
        if (input == null) throw new ArgumentNullException(nameof(input));

        var signer = CreateSigner();
        signer.Init(true, CreatePrivateKeyParameter());
        signer.BlockUpdate(input, 0, input.Length);

        return signer.GenerateSignature();
    }

    /// <summary>
    /// Выполнить процедуру проверки подписи
    /// </summary>
    /// <param name="input">Входной массив байт, для которого создана подпись</param>
    /// <param name="signature">Массив байт, являющийся подписью входного массива</param>
    /// <returns>Возвращает <see langword="true"/>, если подпись верна, иначе <see langword="false"/></returns>
    /// <exception cref="ArgumentNullException">Если не указан какой-либо входной параметр</exception>
    public bool Verify(byte[] input, byte[] signature)
    {
        if (input == null) throw new ArgumentNullException(nameof(input));
        if (signature == null) throw new ArgumentNullException(nameof(signature));

        var validator = CreateSigner();
        validator.Init(false, CreatePublicKeyParameter());
        validator.BlockUpdate(input, 0, input.Length);

        return validator.VerifySignature(signature);
    }

    /// <summary>
    /// Выполнить процедуру проверки подписи
    /// </summary>
    /// <param name="input">Входной массив байт, для которого создана подпись</param>
    /// <param name="inputOffset">Сдвиг во входном массиве</param>
    /// <param name="inputLength">Длина читаемых данных во входном массиве</param>
    /// <param name="signature">Массив байт, являющийся подписью входного массива</param>
    /// <param name="signatureOffset">Сдвиг в массиве подписи</param>
    /// <param name="signatureLength">Длина читаемых данных в массиве подписи</param>
    /// <returns>Возвращает <see langword="true"/>, если подпись верна, иначе <see langword="false"/></returns>
    /// <exception cref="ArgumentNullException">Если не указан какой-либо входной параметр</exception>
    /// <exception cref="ArgumentException">Неверные параметры</exception>
    public bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength)
    {
        if (input == null) throw new ArgumentNullException(nameof(input));
        if (signature == null) throw new ArgumentNullException(nameof(signature));
        if (inputLength <= 0) throw new ArgumentException($"{nameof(inputLength)} значение должно быть больше 0");
        if (signatureLength <= 0) throw new ArgumentException($"{nameof(signatureLength)} значение должно быть больше 0");

        return Verify(input.Skip(inputOffset).Take(inputLength).ToArray(), signature.Skip(signatureOffset).Take(signatureLength).ToArray());
    }

    private ISigner CreateSigner() => Parameters.Curve switch
    {
        NamedCurves.Curve25519 => new Ed25519Signer(),
        NamedCurves.Curve448 => new Ed448Signer(Array.Empty<byte>()),
        _ => throw new NotSupportedException("Кривая указана неверно или алгоритмом не поддерживается")
    };

    private AsymmetricKeyParameter CreatePrivateKeyParameter() => Parameters.Curve switch
    {
        NamedCurves.Curve25519 => new Ed25519PrivateKeyParameters(Parameters.D, 0),
        NamedCurves.Curve448 => new Ed448PrivateKeyParameters(Parameters.D, 0),
        _ => throw new NotSupportedException("Кривая указана неверно или алгоритмом не поддерживается")
    };

    private AsymmetricKeyParameter CreatePublicKeyParameter() => Parameters.Curve switch
    {
        NamedCurves.Curve25519 => new Ed25519PublicKeyParameters(Parameters.X, 0),
        NamedCurves.Curve448 => new Ed448PublicKeyParameters(Parameters.X, 0),
        _ => throw new NotSupportedException("Кривая указана неверно или алгоритмом не поддерживается")
    };
}
