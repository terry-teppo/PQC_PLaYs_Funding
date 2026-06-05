using System.Security.Cryptography;

namespace pqc204;

/// <summary>
/// Provides metadata about ML-DSA algorithm parameters as defined in FIPS 204.
/// </summary>
public static class MLDsaAlgorithmMetadata
{
    /// <summary>
    /// Gets the raw public key size in bytes for the specified ML-DSA algorithm (FIPS 204 format).
    /// This is the uncompressed FIPS-204 public key size used by raw export/import operations.
    /// </summary>
    /// <param name="algorithm">The ML-DSA algorithm.</param>
    /// <returns>The raw public key size in bytes.</returns>
    public static int GetPublicKeySize(MLDsaAlgorithm algorithm)
    {
        if (algorithm == MLDsaAlgorithm.MLDsa44) return 1312;
        if (algorithm == MLDsaAlgorithm.MLDsa65) return 1952;
        if (algorithm == MLDsaAlgorithm.MLDsa87) return 2592;
        
        throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unknown ML-DSA algorithm");
    }

    /// <summary>
    /// Gets the raw FIPS-204 public key size in bytes.
    /// Alias for GetPublicKeySize for clarity in raw key interop scenarios.
    /// </summary>
    /// <param name="algorithm">The ML-DSA algorithm.</param>
    /// <returns>The raw FIPS-204 public key size in bytes (1312/1952/2592).</returns>
    public static int GetRawFips204PublicKeySize(MLDsaAlgorithm algorithm) => GetPublicKeySize(algorithm);

    /// <summary>
    /// Gets the SubjectPublicKeyInfo (X.509 SPKI) encoded public key size in bytes.
    /// This includes ASN.1 encoding overhead (~22 bytes).
    /// </summary>
    /// <param name="algorithm">The ML-DSA algorithm.</param>
    /// <returns>The SPKI-encoded public key size in bytes.</returns>
    public static int GetSpkiPublicKeySize(MLDsaAlgorithm algorithm)
    {
        if (algorithm == MLDsaAlgorithm.MLDsa44) return 1334;
        if (algorithm == MLDsaAlgorithm.MLDsa65) return 1974;
        if (algorithm == MLDsaAlgorithm.MLDsa87) return 2614;
        
        throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unknown ML-DSA algorithm");
    }

    /// <summary>
    /// Gets the raw private key size in bytes for the specified ML-DSA algorithm (FIPS 204 format).
    /// This is the full expanded private key size used by raw export/import operations.
    /// </summary>
    /// <param name="algorithm">The ML-DSA algorithm.</param>
    /// <returns>The raw private key size in bytes.</returns>
    public static int GetPrivateKeySize(MLDsaAlgorithm algorithm)
    {
        if (algorithm == MLDsaAlgorithm.MLDsa44) return 2560;
        if (algorithm == MLDsaAlgorithm.MLDsa65) return 4032;
        if (algorithm == MLDsaAlgorithm.MLDsa87) return 4896;
        
        throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unknown ML-DSA algorithm");
    }

    /// <summary>
    /// Gets the raw FIPS-204 private key size in bytes (full expanded key).
    /// Alias for GetPrivateKeySize for clarity in raw key interop scenarios.
    /// </summary>
    /// <param name="algorithm">The ML-DSA algorithm.</param>
    /// <returns>The raw FIPS-204 private key size in bytes (2560/4032/4896).</returns>
    public static int GetRawFips204PrivateKeySize(MLDsaAlgorithm algorithm) => GetPrivateKeySize(algorithm);

    /// <summary>
    /// Gets the PKCS#8 PrivateKeyInfo encoded private key size in bytes.
    /// Note: .NET's PKCS#8 format uses a compressed representation storing only the seed.
    /// </summary>
    /// <param name="algorithm">The ML-DSA algorithm.</param>
    /// <returns>The PKCS#8-encoded private key size in bytes (constant 54 bytes for all algorithms).</returns>
    public static int GetPkcs8PrivateKeySize(MLDsaAlgorithm algorithm)
    {
        // PKCS#8 format stores the private seed, not the full expanded key
        // This results in a constant size regardless of algorithm
        if (algorithm == MLDsaAlgorithm.MLDsa44) return 54;
        if (algorithm == MLDsaAlgorithm.MLDsa65) return 54;
        if (algorithm == MLDsaAlgorithm.MLDsa87) return 54;
        
        throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unknown ML-DSA algorithm");
    }

    /// <summary>
    /// Gets the signature size in bytes for the specified ML-DSA algorithm.
    /// </summary>
    /// <param name="algorithm">The ML-DSA algorithm.</param>
    /// <returns>The signature size in bytes.</returns>
    public static int GetSignatureSize(MLDsaAlgorithm algorithm)
    {
        if (algorithm == MLDsaAlgorithm.MLDsa44) return 2420;
        if (algorithm == MLDsaAlgorithm.MLDsa65) return 3309;
        if (algorithm == MLDsaAlgorithm.MLDsa87) return 4627;
        
        throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unknown ML-DSA algorithm");
    }

    /// <summary>
    /// Gets the NIST security level for the specified ML-DSA algorithm.
    /// </summary>
    /// <param name="algorithm">The ML-DSA algorithm.</param>
    /// <returns>The NIST security level (2, 3, or 5).</returns>
    public static int GetSecurityLevel(MLDsaAlgorithm algorithm)
    {
        if (algorithm == MLDsaAlgorithm.MLDsa44) return 2;
        if (algorithm == MLDsaAlgorithm.MLDsa65) return 3;
        if (algorithm == MLDsaAlgorithm.MLDsa87) return 5;
        
        throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unknown ML-DSA algorithm");
    }
}
