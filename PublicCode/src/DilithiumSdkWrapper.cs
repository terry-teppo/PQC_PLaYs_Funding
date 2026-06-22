using System.Security.Cryptography;

namespace pqc204;

/// <summary>
/// High-level wrapper around the .NET ML‑DSA (Dilithium) provider.
/// This class exposes a controlled, interop‑safe API surface for
/// post‑quantum signing, verification, and key management without
/// exposing internal cryptographic state or implementation details.
/// </summary>
/// <remarks>
/// [INTEROP]  
/// This behaves like a managed wrapper over a native C library: callers
/// interact only with this façade, while the underlying ML‑DSA engine
/// remains hidden behind framework interfaces.
///
/// [SECURITY]  
/// - No direct access to private key internals  
/// - All import/export flows are explicit and controlled  
/// - Fail‑fast behavior for invalid or unsafe inputs  
/// - No mutation of underlying provider state outside wrapper control  
///
/// [COMMENTARY]  
/// This type is the corridor‑safe entry point for Dilithium operations.
/// It is designed to be embedded in higher‑level systems that must not
/// depend on the concrete cryptographic implementation.
/// </remarks>
public sealed class DilithiumSdkWrapper : IDisposable
{
    // [COMMENTARY] Underlying ML‑DSA provider instance.
    // This object contains key material and cryptographic logic.
    // It is intentionally hidden behind this wrapper boundary.
    private readonly MLDsa _mldsa;

    /// <summary>
    /// Creates a new Dilithium keypair using the specified suite.
    /// </summary>
    /// <param name="suite">Dilithium security level (44, 65, or 87).</param>
    /// <remarks>
    /// [DESCENT]  
    /// This constructor performs the "birth" of a new Dilithium identity:
    /// 1. Maps the requested suite to a concrete ML‑DSA algorithm  
    /// 2. Generates a fresh keypair inside the provider boundary  
    ///
    /// [SECURITY]  
    /// No key material leaves the provider unless explicitly exported
    /// via the export methods on this wrapper.
    /// </remarks>
    public DilithiumSdkWrapper(DilithiumSuite suite)
    {
        _mldsa = MLDsa.GenerateKey(MapSuiteToAlgorithm(suite));
    }

    /// <summary>
    /// Internal constructor used exclusively for import pathways.
    /// </summary>
    /// <param name="mldsa">An already‑initialized ML‑DSA provider instance.</param>
    /// <remarks>
    /// [INTEROP]  
    /// This constructor is intentionally private to ensure that all
    /// externally sourced key material passes through controlled import
    /// functions (PEM, PKCS#8, or raw FIPS‑204).
    ///
    /// [SECURITY]  
    /// Prevents arbitrary injection of provider instances from outside
    /// the wrapper, preserving the integrity of the abstraction boundary.
    /// </remarks>
    private DilithiumSdkWrapper(MLDsa mldsa)
    {
        _mldsa = mldsa;
    }

    /// <summary>
    /// Gets the ML‑DSA algorithm associated with this instance.
    /// </summary>
    /// <remarks>
    /// [COMMENTARY]  
    /// Exposes only the algorithm identity (e.g., MLDsa44, MLDsa65, MLDsa87),
    /// never the key material itself. Useful for diagnostics and suite
    /// verification in corridor‑level code.
    /// </remarks>
    public MLDsaAlgorithm Algorithm => _mldsa.Algorithm;

    /// <summary>
    /// Exports the public key in DER SubjectPublicKeyInfo format.
    /// </summary>
    /// <returns>Byte array containing the public key in SPKI DER encoding.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Suitable for storage, transport, or interop with other systems
    /// that understand standard X.509 SubjectPublicKeyInfo structures.
    ///
    /// [SECURITY]  
    /// Public key material only; safe to share with untrusted parties.
    /// </remarks>
    public byte[] ExportPublicKey() => _mldsa.ExportSubjectPublicKeyInfo();

    /// <summary>
    /// Exports the private key in PKCS#8 DER format.
    /// </summary>
    /// <returns>Byte array containing the private key in PKCS#8 DER encoding.</returns>
    /// <remarks>
    /// [SECURITY]  
    /// This exports unencrypted private key material. It should be handled
    /// with extreme care and protected at rest and in transit. Prefer
    /// encrypted export mechanisms where possible.
    /// </remarks>
    public byte[] ExportPrivateKey() => _mldsa.ExportPkcs8PrivateKey();

    /// <summary>
    /// Exports the public key in PEM format.
    /// </summary>
    /// <returns>String containing the public key in PEM encoding.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// PEM is convenient for configuration files, text‑based storage, and
    /// interoperability with tools that expect ASCII armored keys.
    /// </remarks>
    public string ExportPublicKeyPem() => _mldsa.ExportSubjectPublicKeyInfoPem();

    /// <summary>
    /// Exports the private key in PKCS#8 PEM format.
    /// </summary>
    /// <returns>String containing the private key in PEM encoding.</returns>
    /// <remarks>
    /// [SECURITY]  
    /// This is an unencrypted private key in PEM form. Treat it as highly
    /// sensitive. For production scenarios, prefer the encrypted export
    /// methods provided by this wrapper.
    /// </remarks>
    public string ExportPrivateKeyPem() => _mldsa.ExportPkcs8PrivateKeyPem();

    /// <summary>
    /// Exports the private key in encrypted PKCS#8 PEM format using a password.
    /// </summary>
    /// <param name="password">Password used to derive the encryption key.</param>
    /// <returns>String containing the encrypted private key in PEM encoding.</returns>
    /// <remarks>
    /// [SECURITY]  
    /// Uses PBES2 with AES‑256‑CBC and SHA‑256, with 100,000 iterations.
    /// This is the recommended way to export private keys for storage
    /// outside the process boundary.
    ///
    /// [COMMENTARY]  
    /// This method encapsulates both the PBE configuration and the export
    /// operation, so corridor callers do not need to reason about low‑level
    /// cryptographic parameters.
    /// </remarks>
    public string ExportEncryptedPrivateKeyPem(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        var pbeParameters = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc,
            HashAlgorithmName.SHA256,
            iterationCount: 100_000);
        return _mldsa.ExportEncryptedPkcs8PrivateKeyPem(password, pbeParameters);
    }

    /// <summary>
    /// Exports the private key in encrypted PKCS#8 PEM format using a password span.
    /// </summary>
    /// <param name="password">Password span used to derive the encryption key.</param>
    /// <returns>String containing the encrypted private key in PEM encoding.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Span‑based overload for callers that manage sensitive password data
    /// without allocating intermediate strings.
    ///
    /// [SECURITY]  
    /// Same cryptographic parameters as the string‑based overload.
    /// </remarks>
    public string ExportEncryptedPrivateKeyPem(ReadOnlySpan<char> password)
    {
        var pbeParameters = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc,
            HashAlgorithmName.SHA256,
            iterationCount: 100_000);
        return _mldsa.ExportEncryptedPkcs8PrivateKeyPem(password, pbeParameters);
    }

    /// <summary>
    /// Signs the specified data using the current Dilithium private key.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <returns>Signature bytes produced by the ML‑DSA provider.</returns>
    /// <remarks>
    /// [INVOCATION]  
    /// Corridor‑level signing primitive. The data is passed to the provider,
    /// and the resulting signature is returned. The private key never leaves
    /// the provider boundary.
    ///
    /// [SECURITY]  
    /// Callers are responsible for choosing appropriate message formats and
    /// canonicalization strategies before signing.
    /// </remarks>
    public byte[] SignData(byte[] data) => _mldsa.SignData(data);

    /// <summary>
    /// Verifies a signature over the specified data using the current public key.
    /// </summary>
    /// <param name="data">The original data that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
    /// <remarks>
    /// [INVOCATION]  
    /// Corridor‑level verification primitive. This method delegates to the
    /// provider's verification logic and returns a simple boolean result.
    ///
    /// [SECURITY]  
    /// A <c>false</c> result indicates either tampering or mismatch between
    /// the data, signature, and key. It is not treated as an exceptional
    /// condition.
    /// </remarks>
    public bool VerifyData(byte[] data, byte[] signature) => _mldsa.VerifyData(data, signature);

    /// <summary>
    /// Imports a public key from DER SubjectPublicKeyInfo format.
    /// </summary>
    /// <param name="publicKey">Byte array containing the public key in SPKI DER encoding.</param>
    /// <returns>A new <see cref="DilithiumSdkWrapper"/> instance bound to the imported public key.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Use this when you have a standard SPKI public key and need a wrapper
    /// instance for verification operations.
    ///
    /// [SECURITY]  
    /// Public key only; safe to construct from untrusted sources, though
    /// callers should still validate provenance as appropriate.
    /// </remarks>
    public static DilithiumSdkWrapper ImportPublicKey(byte[] publicKey)
    {
        var mldsa = MLDsa.ImportSubjectPublicKeyInfo(publicKey);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports a private key from PKCS#8 DER format.
    /// </summary>
    /// <param name="privateKey">Byte array containing the private key in PKCS#8 DER encoding.</param>
    /// <returns>A new <see cref="DilithiumSdkWrapper"/> instance bound to the imported keypair.</returns>
    /// <remarks>
    /// [SECURITY]  
    /// This expects unencrypted private key material. Callers must ensure
    /// that the source is trusted and that the data is handled securely.
    /// </remarks>
    public static DilithiumSdkWrapper ImportPrivateKey(byte[] privateKey)
    {
        var mldsa = MLDsa.ImportPkcs8PrivateKey(privateKey);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports a public or private key from PEM format.
    /// </summary>
    /// <param name="pemKey">PEM‑encoded key material.</param>
    /// <returns>A new <see cref="DilithiumSdkWrapper"/> instance bound to the imported key.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// This method delegates to the provider's PEM import logic, which can
    /// handle both public and private keys depending on the PEM content.
    ///
    /// [SECURITY]  
    /// If the PEM contains private key material, treat the source as highly
    /// sensitive and trusted.
    /// </remarks>
    public static DilithiumSdkWrapper ImportPublicKeyPem(string pemKey)
    {
        ArgumentNullException.ThrowIfNull(pemKey);
        var mldsa = MLDsa.ImportFromPem(pemKey);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports a private key from PEM format.
    /// </summary>
    /// <param name="pemKey">PEM‑encoded private key material.</param>
    /// <returns>A new <see cref="DilithiumSdkWrapper"/> instance bound to the imported keypair.</returns>
    /// <remarks>
    /// [SECURITY]  
    /// Assumes the PEM contains private key material. Callers must ensure
    /// secure handling and trusted provenance.
    /// </remarks>
    public static DilithiumSdkWrapper ImportPrivateKeyPem(string pemKey)
    {
        ArgumentNullException.ThrowIfNull(pemKey);
        var mldsa = MLDsa.ImportFromPem(pemKey);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports an encrypted private key from PEM format using a password.
    /// </summary>
    /// <param name="pemKey">PEM‑encoded encrypted private key.</param>
    /// <param name="password">Password used to decrypt the key.</param>
    /// <returns>A new <see cref="DilithiumSdkWrapper"/> instance bound to the decrypted keypair.</returns>
    /// <remarks>
    /// [SECURITY]  
    /// This is the preferred way to import private keys that have been
    /// stored or transported in encrypted form. The password must be
    /// supplied by a secure channel or secret management system.
    /// </remarks>
    public static DilithiumSdkWrapper ImportEncryptedPrivateKeyPem(string pemKey, string password)
    {
        ArgumentNullException.ThrowIfNull(pemKey);
        ArgumentNullException.ThrowIfNull(password);
        var mldsa = MLDsa.ImportFromEncryptedPem(pemKey, password);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports an encrypted private key from PEM format using spans.
    /// </summary>
    /// <param name="pemKey">PEM‑encoded encrypted private key.</param>
    /// <param name="password">Password used to decrypt the key.</param>
    /// <returns>A new <see cref="DilithiumSdkWrapper"/> instance bound to the decrypted keypair.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Span‑based overload for callers that manage sensitive data without
    /// allocating intermediate strings.
    /// </remarks>
    public static DilithiumSdkWrapper ImportEncryptedPrivateKeyPem(ReadOnlySpan<char> pemKey, ReadOnlySpan<char> password)
    {
        var mldsa = MLDsa.ImportFromEncryptedPem(pemKey, password);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Gets a value indicating whether the underlying ML‑DSA provider is supported on this platform.
    /// </summary>
    /// <remarks>
    /// [COMMENTARY]  
    /// Use this to gate feature availability at runtime. If this is <c>false</c>,
    /// the platform/runtime does not support the required Dilithium primitives.
    /// </remarks>
    public static bool IsSupported => MLDsa.IsSupported;

    // ---------------------------------------------------------------------
    // Raw FIPS‑204 key export/import for interoperability with FIPS‑native
    // implementations (HSMs, legacy toolchains, other language runtimes).
    // ---------------------------------------------------------------------

    /// <summary>
    /// Exports the raw FIPS‑204 private key (full expanded key material).
    /// </summary>
    /// <returns>Byte array containing the raw FIPS‑204 private key.</returns>
    /// <remarks>
    /// [SECURITY]  
    /// This exposes unencrypted private key material in FIPS‑204 native form.
    /// It should only be used for interoperability with trusted FIPS‑native
    /// components (e.g., HSMs) and must be protected rigorously.
    ///
    /// [INTEROP]  
    /// Intended for scenarios where a FIPS‑native implementation expects
    /// raw key material rather than PKCS#8 or PEM.
    /// </remarks>
    public byte[] ExportRawFips204PrivateKey() => FipsInterop.ExportRawFips204PrivateKey(_mldsa);

    /// <summary>
    /// Exports the raw FIPS‑204 private key encrypted with a password.
    /// </summary>
    /// <param name="password">Password used to encrypt the raw key blob.</param>
    /// <returns>Byte array containing the encrypted raw FIPS‑204 private key.</returns>
    /// <remarks>
    /// [SECURITY]  
    /// This is the recommended method for exporting raw private keys for
    /// interoperability. The resulting blob must still be handled as
    /// sensitive material, but is safer than plaintext raw export.
    /// </remarks>
    public byte[] ExportRawFips204PrivateKeyEncrypted(string password) =>
        FipsInterop.ExportRawFips204PrivateKeyEncrypted(_mldsa, password);

    /// <summary>
    /// Exports the raw FIPS‑204 private key encrypted with a password span.
    /// </summary>
    /// <param name="password">Password span used to encrypt the raw key blob.</param>
    /// <returns>Byte array containing the encrypted raw FIPS‑204 private key.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Span‑based overload for environments that avoid string allocation
    /// for sensitive password material.
    /// </remarks>
    public byte[] ExportRawFips204PrivateKeyEncrypted(ReadOnlySpan<char> password) =>
        FipsInterop.ExportRawFips204PrivateKeyEncrypted(_mldsa, password);

    /// <summary>
    /// Exports the raw FIPS‑204 public key (uncompressed FIPS‑204 format).
    /// </summary>
    /// <returns>Byte array containing the raw FIPS‑204 public key.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Use this when interoperating with FIPS‑native implementations that
    /// expect public keys in their native uncompressed format rather than
    /// SPKI or PEM.
    /// </remarks>
    public byte[] ExportRawFips204PublicKey() => FipsInterop.ExportRawFips204PublicKey(_mldsa);

    /// <summary>
    /// Imports a raw FIPS‑204 private key (full expanded key material).
    /// </summary>
    /// <param name="rawPrivateKey">Raw FIPS‑204 private key bytes.</param>
    /// <param name="suite">Dilithium suite corresponding to the key.</param>
    /// <returns>A new <see cref="DilithiumSdkWrapper"/> instance bound to the imported key.</returns>
    /// <remarks>
        /// [SECURITY]  
    /// Callers must ensure the raw key is securely sourced and handled.
    ///
    /// [INTEROP]  
    /// This is intended for integration with FIPS‑native key management
    /// systems that operate on raw key material.
    /// </remarks>
    public static DilithiumSdkWrapper ImportRawFips204PrivateKey(byte[] rawPrivateKey, DilithiumSuite suite)
    {
        var algorithm = MapSuiteToAlgorithm(suite);
        var mldsa = FipsInterop.ImportRawFips204PrivateKey(rawPrivateKey, algorithm);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports a raw FIPS‑204 private key (full expanded key material) from a span.
    /// </summary>
    /// <param name="rawPrivateKey">Raw FIPS‑204 private key bytes.</param>
    /// <param name="suite">Dilithium suite corresponding to the key.</param>
    /// <returns>A new <see cref="DilithiumSdkWrapper"/> instance bound to the imported key.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Span‑based overload for callers that manage key material in spans
    /// rather than arrays.
    /// </remarks>
    public static DilithiumSdkWrapper ImportRawFips204PrivateKey(ReadOnlySpan<byte> rawPrivateKey, DilithiumSuite suite)
    {
        var algorithm = MapSuiteToAlgorithm(suite);
        var mldsa = FipsInterop.ImportRawFips204PrivateKey(rawPrivateKey, algorithm);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports an encrypted raw FIPS‑204 private key.
    /// </summary>
    /// <param name="encryptedBlob">Encrypted raw FIPS‑204 private key blob.</param>
    /// <param name="password">Password used to decrypt the blob.</param>
    /// <param name="suite">Dilithium suite corresponding to the key.</param>
    /// <returns>A new <see cref="DilithiumSdkWrapper"/> instance bound to the imported key.</returns>
    /// <remarks>
    /// [SECURITY]  
    /// This is the preferred way to ingest raw FIPS‑204 private keys from
    /// external systems, as it keeps the key encrypted at rest and in transit.
    /// </remarks>
    public static DilithiumSdkWrapper ImportRawFips204PrivateKeyEncrypted(byte[] encryptedBlob, string password, DilithiumSuite suite)
    {
        var algorithm = MapSuiteToAlgorithm(suite);
        var mldsa = FipsInterop.ImportRawFips204PrivateKeyEncrypted(encryptedBlob, password, algorithm);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports an encrypted raw FIPS‑204 private key from spans.
    /// </summary>
    /// <param name="encryptedBlob">Encrypted raw FIPS‑204 private key blob.</param>
    /// <param name="password">Password used to decrypt the blob.</param>
    /// <param name="suite">Dilithium suite corresponding to the key.</param>
    /// <returns>A new <see cref="DilithiumSdkWrapper"/> instance bound to the imported key.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Span‑based overload for environments that operate on spans for both
    /// key blobs and passwords.
    /// </remarks>
    public static DilithiumSdkWrapper ImportRawFips204PrivateKeyEncrypted(ReadOnlySpan<byte> encryptedBlob, ReadOnlySpan<char> password, DilithiumSuite suite)
    {
        var algorithm = MapSuiteToAlgorithm(suite);
        var mldsa = FipsInterop.ImportRawFips204PrivateKeyEncrypted(encryptedBlob, password, algorithm);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports a raw FIPS‑204 public key (uncompressed FIPS‑204 format).
    /// </summary>
    /// <param name="rawPublicKey">Raw FIPS‑204 public key bytes.</param>
    /// <param name="suite">Dilithium suite corresponding to the key.</param>
    /// <returns>A new <see cref="DilithiumSdkWrapper"/> instance bound to the imported public key.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Use this when interoperating with FIPS‑native systems that emit
    /// public keys in their native raw format.
    /// </remarks>
    public static DilithiumSdkWrapper ImportRawFips204PublicKey(byte[] rawPublicKey, DilithiumSuite suite)
    {
        var algorithm = MapSuiteToAlgorithm(suite);
        var mldsa = FipsInterop.ImportRawFips204PublicKey(rawPublicKey, algorithm);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Imports a raw FIPS‑204 public key (uncompressed FIPS‑204 format) from a span.
    /// </summary>
    /// <param name="rawPublicKey">Raw FIPS‑204 public key bytes.</param>
    /// <param name="suite">Dilithium suite corresponding to the key.</param>
    /// <returns>A new <see cref="DilithiumSdkWrapper"/> instance bound to the imported public key.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Span‑based overload for callers that manage public key material in spans.
    /// </remarks>
    public static DilithiumSdkWrapper ImportRawFips204PublicKey(ReadOnlySpan<byte> rawPublicKey, DilithiumSuite suite)
    {
        var algorithm = MapSuiteToAlgorithm(suite);
        var mldsa = FipsInterop.ImportRawFips204PublicKey(rawPublicKey, algorithm);
        return new DilithiumSdkWrapper(mldsa);
    }

    /// <summary>
    /// Releases resources associated with the underlying ML‑DSA provider.
    /// </summary>
    /// <remarks>
    /// [DESCENT]  
    /// This marks the end of the lifecycle for this wrapper instance.
    /// After disposal, no further operations should be performed.
    ///
    /// [SECURITY]  
    /// Disposing may trigger zeroization or release of sensitive resources
    /// in the underlying provider, depending on its implementation.
    /// </remarks>
    public void Dispose() => _mldsa.Dispose();

    /// <summary>
    /// Maps a <see cref="DilithiumSuite"/> value to the corresponding <see cref="MLDsaAlgorithm"/>.
    /// </summary>
    /// <param name="suite">The Dilithium suite to map.</param>
    /// <returns>The corresponding <see cref="MLDsaAlgorithm"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown if the suite value is not recognized.
    /// </exception>
    /// <remarks>
    /// [COMMENTARY]  
    /// Centralized mapping between high‑level suite identifiers and the
    /// concrete algorithms exposed by the underlying provider. This keeps
    /// corridor‑level code independent of provider‑specific enums.
    /// </remarks>
    private static MLDsaAlgorithm MapSuiteToAlgorithm(DilithiumSuite suite) => suite switch
    {
        DilithiumSuite.MlDsa44 => MLDsaAlgorithm.MLDsa44,
        DilithiumSuite.MlDsa65 => MLDsaAlgorithm.MLDsa65,
        DilithiumSuite.MlDsa87 => MLDsaAlgorithm.MLDsa87,
        _ => throw new ArgumentOutOfRangeException(nameof(suite))
    };
}
