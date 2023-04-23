namespace Zevs.Samples.Okp.EdCryptoWrapppers;

/// <summary>
/// Дополнительные поддерживание алгоритмы
/// </summary>
public class SecurityAlgorithmsAdditional
{
    /// <summary>
    /// Тип ключа, описывающий использование алгоритмов, основанных на кривых Эдвардса <seealso href="https://tools.ietf.org/html/rfc8037#section-5"/>
    /// </summary>
    public const string EdDsaKty = "OKP";

    /// <summary>
    /// Алгоритм подписи, основанной на кривых Эдвардса <seealso href="https://tools.ietf.org/html/rfc8037"/>
    /// </summary>
    public const string EdDsa = "EdDSA";

    /// <summary>
    /// Известные кривые, на которым построен алгоритм
    /// </summary>
    public static class NamedCurves
    {
        /// <summary>
        /// Кривая Ed25519 для создания подписей <seealso href="https://tools.ietf.org/html/rfc8037#section-3.1"/>
        /// </summary>
        public const string Curve25519 = "Ed25519";

        /// <summary>
        /// Кривая Ed448 для создания подписей <seealso href="https://tools.ietf.org/html/rfc8037#section-3.1"/>
        /// </summary>
        public const string Curve448 = "Ed448";

        /// <summary>
        /// Кривая X25519 для алгоритма ECDH-ES <seealso href="https://tools.ietf.org/html/rfc8037#section-3.2"/>
        /// </summary>
        public const string CurveX25519 = "X25519";

        /// <summary>
        /// Кривая X448 для алгоритма ECDH-ES <seealso href="https://tools.ietf.org/html/rfc8037#section-3.2"/>
        /// </summary>
        public const string CurveX448 = "X448";
    }
}
