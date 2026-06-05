using System.Security.Cryptography;

namespace pqc204;

public sealed class DilithiumSdkWrapper : IDisposable
{
    private readonly MLDsa _mldsa;

    public DilithiumSdkWrapper(DilithiumSuite suite)
    {
        _mldsa = MLDsa.GenerateKey(MapSuiteToAlgorithm(suite));
    }

    private DilithiumSdkWrapper(MLDsa mldsa)
    {
        _mldsa = mldsa;
    }

    public MLDsaAlgorithm Algorithm => _mldsa.Algorithm;

    public byte[] ExportPublicKey() => _mldsa.ExportSubjectPublicKeyInfo();

    public byte[] ExportPrivateKey() => _mldsa.ExportPkcs8PrivateKey();

    public string ExportPublicKeyPem() => _mldsa.ExportSubjectPublicKeyInfoPem();

    public string ExportPrivateKeyPem() => _mldsa.ExportPkcs8PrivateKeyPem();

    public string ExportEncryptedPrivateKeyPem(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        var pbeParameters = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc,
            HashAlgorithmName.SHA256,
            iterationCount: 100_000);
        return _mldsa.ExportEncryptedPkcs8PrivateKeyPem(password, pbeParameters);
    }

    public string ExportEncryptedPrivateKeyPem(ReadOnlySpan<char> password)
    {
        var pbeParameters = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc,
            HashAlgorithmName.SHA256,
            iterationCount: 100_000);
        return _mldsa.ExportEncryptedPkcs8PrivateKeyPem(password, pbeParameters);
    }

    public byte[] SignData(byte[] data) => _mldsa.SignData(data);

    public bool VerifyData(byte[] data, byte[] signature) => _mldsa.VerifyData(data, signature);

    public static DilithiumSdkWrapper ImportPublicKey(byte[] publicKey)
    {
        var mldsa = MLDsa.ImportSubjectPublicKeyInfo(publicKey);
        return new DilithiumSdkWrapper(mldsa);
    }

    public static DilithiumSdkWrapper ImportPrivateKey(byte[] privateKey)
    {
        var mldsa = MLDsa.ImportPkcs8PrivateKey(privateKey);
        return new DilithiumSdkWrapper(mldsa);
    }

    public static DilithiumSdkWrapper ImportPublicKeyPem(string pemKey)
    {
        ArgumentNullException.ThrowIfNull(pemKey);
        var mldsa = MLDsa.ImportFromPem(pemKey);
        return new DilithiumSdkWrapper(mldsa);
    }

    public static DilithiumSdkWrapper ImportPrivateKeyPem(string pemKey)
    {
        ArgumentNullException.ThrowIfNull(pemKey);
        var mldsa = MLDsa.ImportFromPem(pemKey);
        return new DilithiumSdkWrapper(mldsa);
    }

    public static DilithiumSdkWrapper ImportEncryptedPrivateKeyPem(string pemKey, string password)
    {
        ArgumentNullException.ThrowIfNull(pemKey);
        ArgumentNullException.ThrowIfNull(password);
        var mldsa = MLDsa.ImportFromEncryptedPem(pemKey, password);
        return new DilithiumSdkWrapper(mldsa);
    }

    public static DilithiumSdkWrapper ImportEncryptedPrivateKeyPem(ReadOnlySpan<char> pemKey, ReadOnlySpan<char> password)
    {
        var mldsa = MLDsa.ImportFromEncryptedPem(pemKey, password);
        return new DilithiumSdkWrapper(mldsa);
    }

    public static bool IsSupported => MLDsa.IsSupported;

    // Raw FIPS-204 key export/import for interoperability with FIPS-native implementations
    // (HSMs, legacy toolchains, other language runtimes)
    
    /// <summary>
    /// Exports the raw FIPS-204 private key (full expanded key material).
    /// SECURITY WARNING: This exposes unencrypted private key material.
    /// Use ExportRawFips204PrivateKeyEncrypted for production scenarios.
    /// </summary>
    public byte[] ExportRawFips204PrivateKey() => FipsInterop.ExportRawFips204PrivateKey(_mldsa);

    /// <summary>
    /// Exports the raw FIPS-204 private key encrypted with a password.
    /// This is the RECOMMENDED method for exporting raw private keys.
    /// </summary>
    public byte[] ExportRawFips204PrivateKeyEncrypted(string password) => 
        FipsInterop.ExportRawFips204PrivateKeyEncrypted(_mldsa, password);

    /// <summary>
    /// Exports the raw FIPS-204 private key encrypted with a password.
    /// This is the RECOMMENDED method for exporting raw private keys.
    /// </summary>
    public byte[] ExportRawFips204PrivateKeyEncrypted(ReadOnlySpan<char> password) => 
        FipsInterop.ExportRawFips204PrivateKeyEncrypted(_mldsa, password);

    /// <summary>
    /// Exports the raw FIPS-204 public key (uncompressed FIPS-204 format).
    /// </summary>
    public byte[] ExportRawFips204PublicKey() => FipsInterop.ExportRawFips204PublicKey(_mldsa);

    /// <summary>
    /// Imports a raw FIPS-204 private key (full expanded key material).
    /// SECURITY WARNING: Ensure the input key is securely sourced and handled.
    /// </summary>
    public static DilithiumSdkWrapper ImportRawFips204PrivateKey(byte[] rawPrivateKey, DilithiumSuite suite)
    {
        var algorithm = MapSuiteToAlgorithm(suite);
        var mldsa = FipsInterop.ImportRawFips204PrivateKey(rawPrivateKey, algorithm);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports a raw FIPS-204 private key (full expanded key material).
    /// SECURITY WARNING: Ensure the input key is securely sourced and handled.
    /// </summary>
    public static DilithiumSdkWrapper ImportRawFips204PrivateKey(ReadOnlySpan<byte> rawPrivateKey, DilithiumSuite suite)
    {
        var algorithm = MapSuiteToAlgorithm(suite);
        var mldsa = FipsInterop.ImportRawFips204PrivateKey(rawPrivateKey, algorithm);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports an encrypted raw FIPS-204 private key.
    /// </summary>
    public static DilithiumSdkWrapper ImportRawFips204PrivateKeyEncrypted(byte[] encryptedBlob, string password, DilithiumSuite suite)
    {
        var algorithm = MapSuiteToAlgorithm(suite);
        var mldsa = FipsInterop.ImportRawFips204PrivateKeyEncrypted(encryptedBlob, password, algorithm);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports an encrypted raw FIPS-204 private key.
    /// </summary>
    public static DilithiumSdkWrapper ImportRawFips204PrivateKeyEncrypted(ReadOnlySpan<byte> encryptedBlob, ReadOnlySpan<char> password, DilithiumSuite suite)
    {
        var algorithm = MapSuiteToAlgorithm(suite);
        var mldsa = FipsInterop.ImportRawFips204PrivateKeyEncrypted(encryptedBlob, password, algorithm);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports a raw FIPS-204 public key (uncompressed FIPS-204 format).
    /// </summary>
    public static DilithiumSdkWrapper ImportRawFips204PublicKey(byte[] rawPublicKey, DilithiumSuite suite)
    {
        var algorithm = MapSuiteToAlgorithm(suite);
        var mldsa = FipsInterop.ImportRawFips204PublicKey(rawPublicKey, algorithm);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports a raw FIPS-204 public key (uncompressed FIPS-204 format).
    /// </summary>
    public static DilithiumSdkWrapper ImportRawFips204PublicKey(ReadOnlySpan<byte> rawPublicKey, DilithiumSuite suite)
    {
        var algorithm = MapSuiteToAlgorithm(suite);
        var mldsa = FipsInterop.ImportRawFips204PublicKey(rawPublicKey, algorithm);
        return new DilithiumSdkWrapper(mldsa);
    }

    public void Dispose() => _mldsa.Dispose();

    private static MLDsaAlgorithm MapSuiteToAlgorithm(DilithiumSuite suite) => suite switch
    {
        DilithiumSuite.MlDsa44 => MLDsaAlgorithm.MLDsa44,
        DilithiumSuite.MlDsa65 => MLDsaAlgorithm.MLDsa65,
        DilithiumSuite.MlDsa87 => MLDsaAlgorithm.MLDsa87,
        _ => throw new ArgumentOutOfRangeException(nameof(suite))
    };
}
