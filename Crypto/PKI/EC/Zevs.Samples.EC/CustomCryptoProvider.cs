using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Zevs.Samples.EC;

public class CustomCryptoProvider : ICryptoProvider
{
    public bool IsSupportedAlgorithm(string algorithm, params object[] args) => algorithm == "ES256K";

    public object Create(string algorithm, params object[] args)
    {
        if (algorithm != "ES256K" || args[0] is not CustomEcDsaSecurityKey key)
            throw new NotSupportedException();

        return new CustomSignatureProvider(key, algorithm);
    }

    public void Release(object cryptoInstance)
    {
        if (cryptoInstance is IDisposable disposableObject)
            disposableObject.Dispose();
    }
}

public class CustomEcDsaSecurityKey : AsymmetricSecurityKey
{
    public ECParameters EcParameters { get; }

    public override int KeySize => throw new NotImplementedException();

    [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus instead.")]
    public override bool HasPrivateKey => EcParameters.D is not null;

    public override PrivateKeyStatus PrivateKeyStatus =>
        EcParameters.D is not null ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;

    public CustomEcDsaSecurityKey(ECParameters ecParameters)
    {
        if (ecParameters.Curve.Oid.FriendlyName != "secP256k1")
            throw new NotSupportedException();

        EcParameters = ecParameters;
        CryptoProviderFactory.CustomCryptoProvider = new CustomCryptoProvider();
    }
}

public class CustomSignatureProvider : SignatureProvider
{
    private readonly CustomEcDsaSecurityKey _securityKey;

    public CustomSignatureProvider(SecurityKey key, string algorithm) : base(key, algorithm)
    {
        if (algorithm != "ES256K" || key is not CustomEcDsaSecurityKey securityKey)
            throw new NotSupportedException();

        _securityKey = securityKey;
    }

    protected override void Dispose(bool disposing)
    {
    }

    public override byte[] Sign(byte[] input)
    {
        using var ecDsa = ECDsa.Create(_securityKey.EcParameters);
        return ecDsa.SignData(input, HashAlgorithmName.SHA256);
    }

    public override bool Verify(byte[] input, byte[] signature)
    {
        using var ecDsa = ECDsa.Create(_securityKey.EcParameters);
        return ecDsa.VerifyData(input, signature, HashAlgorithmName.SHA256);
    }
}
