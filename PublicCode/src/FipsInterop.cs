using System.Formats.Asn1;
using System.Security.Cryptography;

namespace pqc204;

/// <summary>
/// Provides raw FIPS‑204 key format export/import for interoperability with
/// FIPS‑native implementations (HSMs, legacy toolchains, other language runtimes).
/// </summary>
/// <remarks>
/// [INTEROP]  
/// This static helper is a focused interop layer that translates between the
/// managed ML‑DSA provider and a raw FIPS‑204 native key representation used by
/// external systems. It is intentionally minimal: its responsibility is to
/// serialize/deserialize raw key blobs and to provide a secure, encrypted
/// export/import pathway for raw private keys.
///
/// [SECURITY]  
/// - Raw private key export exposes full expanded key material (large blobs).
/// - Prefer encrypted export methods for production use.
/// - All functions validate inputs and zeroize sensitive buffers where possible.
/// - Caller must ensure secure handling of returned blobs and supplied passwords.
///
/// [COMMENTARY]  
/// Treat this type as the corridor between managed provider and FIPS‑native
/// ecosystems. It mirrors the semantics of a C interop shim: explicit, minimal,
/// and security‑aware.
/// </remarks>
public static class FipsInterop
{
    // Sizes and constants used by the encrypted export/import format.
    private const int AesGcmNonceSize = 12;
    private const int AesGcmTagSize = 16;
    private const int Pbkdf2SaltSize = 32;
    private const int Pbkdf2Iterations = 600_000;
    private const int VersionSize = 1;
    private const byte CurrentVersion = 1;

    /// <summary>
    /// Exports the raw FIPS‑204 private key (full expanded key material).
    /// </summary>
    /// <param name="mldsa">The ML‑DSA instance.</param>
    /// <returns>
    /// Raw FIPS‑204 private key bytes (2560/4032/4896 bytes depending on algorithm).
    /// </returns>
    /// <remarks>
    /// [SECURITY]  
    /// This returns unencrypted private key material. Use only for trusted,
    /// short‑lived interoperability scenarios. Prefer
    /// <see cref="ExportRawFips204PrivateKeyEncrypted(MLDsa,string)"/> for
    /// production exports.
    /// </remarks>
    public static byte[] ExportRawFips204PrivateKey(MLDsa mldsa)
    {
        ArgumentNullException.ThrowIfNull(mldsa);
        return mldsa.ExportMLDsaPrivateKey();
    }

    /// <summary>
    /// Exports the raw FIPS‑204 private key encrypted with a password using AES‑256‑GCM and PBKDF2‑SHA256.
    /// </summary>
    /// <param name="mldsa">The ML‑DSA instance.</param>
    /// <param name="password">Password for encryption (minimum 12 characters recommended).</param>
    /// <returns>
    /// Encrypted blob containing: [1‑byte version][32‑byte salt][12‑byte nonce][16‑byte tag][encrypted raw private key].
    /// </returns>
    /// <remarks>
    /// [SECURITY]  
    /// This is the RECOMMENDED method for exporting raw private keys for
    /// interoperability. The format includes a version byte, PBKDF2 salt,
    /// AES‑GCM nonce and tag, followed by the ciphertext. The password is
    /// used to derive a 32‑byte AES key via PBKDF2(SHA‑256).
    /// </remarks>
    public static byte[] ExportRawFips204PrivateKeyEncrypted(MLDsa mldsa, string password)
    {
        ArgumentNullException.ThrowIfNull(mldsa);
        ArgumentNullException.ThrowIfNull(password);
        return ExportRawFips204PrivateKeyEncrypted(mldsa, password.AsSpan());
    }

    /// <summary>
    /// Exports the raw FIPS‑204 private key encrypted with a password using AES‑256‑GCM and PBKDF2‑SHA256.
    /// Span overload to avoid allocating intermediate password strings.
    /// </summary>
    /// <param name="mldsa">The ML‑DSA instance.</param>
    /// <param name="password">Password for encryption (minimum 12 characters recommended).</param>
    /// <returns>
    /// Encrypted blob containing: [1‑byte version][32‑byte salt][12‑byte nonce][16‑byte tag][encrypted raw private key].
    /// </returns>
    /// <remarks>
    /// [INTEROP]  
    /// Uses UTF‑8 encoding of the password span and PBKDF2 to derive the AES key.
    /// Sensitive buffers (raw private key, derived key, ciphertext) are zeroized
    /// where feasible to reduce exposure in managed memory.
    /// </remarks>
    public static byte[] ExportRawFips204PrivateKeyEncrypted(MLDsa mldsa, ReadOnlySpan<char> password)
    {
        ArgumentNullException.ThrowIfNull(mldsa);

        byte[] rawPrivateKey = mldsa.ExportMLDsaPrivateKey();
        try
        {
            byte[] salt = RandomNumberGenerator.GetBytes(Pbkdf2SaltSize);
            byte[] nonce = RandomNumberGenerator.GetBytes(AesGcmNonceSize);

            // Encode password into UTF‑8 bytes on the stack when possible.
            Span<byte> passwordBytes = stackalloc byte[password.Length * 3];
            int passwordBytesWritten = System.Text.Encoding.UTF8.GetBytes(password, passwordBytes);

            // Derive AES‑256 key using PBKDF2(SHA‑256)
            using var keyDerivation = new Rfc2898DeriveBytes(
                passwordBytes[..passwordBytesWritten].ToArray(),
                salt,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256);
            byte[] key = keyDerivation.GetBytes(32);

            try
            {
                using var aesGcm = new AesGcm(key, AesGcmTagSize);
                byte[] ciphertext = new byte[rawPrivateKey.Length];
                byte[] tag = new byte[AesGcmTagSize];

                // Use algorithm name as additional authenticated data (AAD)
                byte[] aad = System.Text.Encoding.UTF8.GetBytes(mldsa.Algorithm.Name);

                aesGcm.Encrypt(nonce, rawPrivateKey, ciphertext, tag, aad);

                byte[] result = new byte[VersionSize + Pbkdf2SaltSize + AesGcmNonceSize + AesGcmTagSize + ciphertext.Length];
                result[0] = CurrentVersion;
                Buffer.BlockCopy(salt, 0, result, VersionSize, Pbkdf2SaltSize);
                Buffer.BlockCopy(nonce, 0, result, VersionSize + Pbkdf2SaltSize, AesGcmNonceSize);
                Buffer.BlockCopy(tag, 0, result, VersionSize + Pbkdf2SaltSize + AesGcmNonceSize, AesGcmTagSize);
                Buffer.BlockCopy(ciphertext, 0, result, VersionSize + Pbkdf2SaltSize + AesGcmNonceSize + AesGcmTagSize, ciphertext.Length);

                // Zeroize ephemeral ciphertext buffer before returning
                CryptographicOperations.ZeroMemory(ciphertext);
                return result;
            }
            finally
            {
                // Zeroize derived key material
                CryptographicOperations.ZeroMemory(key);
            }
        }
        finally
        {
            // Zeroize raw private key material
            CryptographicOperations.ZeroMemory(rawPrivateKey);
        }
    }

    /// <summary>
    /// Exports the raw FIPS‑204 public key (uncompressed FIPS‑204 format).
    /// </summary>
    /// <param name="mldsa">The ML‑DSA instance.</param>
    /// <returns>Raw FIPS‑204 public key bytes (1312/1952/2592 bytes depending on algorithm).</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Public key export in native FIPS‑204 format is useful when integrating
    /// with systems that expect uncompressed native public keys rather than SPKI/PEM.
    /// </remarks>
    public static byte[] ExportRawFips204PublicKey(MLDsa mldsa)
    {
        ArgumentNullException.ThrowIfNull(mldsa);
        return mldsa.ExportMLDsaPublicKey();
    }

    /// <summary>
    /// Imports a raw FIPS‑204 private key (full expanded key material).
    /// </summary>
    /// <param name="rawPrivateKey">Raw FIPS‑204 private key bytes (2560/4032/4896 bytes depending on algorithm).</param>
    /// <param name="algorithm">The ML‑DSA algorithm corresponding to the key.</param>
    /// <returns>ML‑DSA instance initialized with the private key.</returns>
    /// <remarks>
    /// [SECURITY]  
    /// Ensure the input key is securely sourced and handled. The input buffer
    /// is zeroized after import to reduce the lifetime of sensitive material
    /// in managed memory.
    /// </remarks>
    public static MLDsa ImportRawFips204PrivateKey(byte[] rawPrivateKey, MLDsaAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(rawPrivateKey);
        try
        {
            return MLDsa.ImportMLDsaPrivateKey(algorithm, rawPrivateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawPrivateKey);
        }
    }

    /// <summary>
    /// Imports a raw FIPS‑204 private key (full expanded key material) from a span.
    /// </summary>
    /// <param name="rawPrivateKey">Raw FIPS‑204 private key bytes (2560/4032/4896 bytes depending on algorithm).</param>
    /// <param name="algorithm">The ML‑DSA algorithm corresponding to the key.</param>
    /// <returns>ML‑DSA instance initialized with the private key.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Span overload avoids array allocation when callers already manage
    /// key material in spans. Caller remains responsible for zeroizing the
    /// source span if necessary.
    /// </remarks>
    public static MLDsa ImportRawFips204PrivateKey(ReadOnlySpan<byte> rawPrivateKey, MLDsaAlgorithm algorithm)
    {
        return MLDsa.ImportMLDsaPrivateKey(algorithm, rawPrivateKey);
    }

    /// <summary>
    /// Imports an encrypted raw FIPS‑204 private key that was exported with ExportRawFips204PrivateKeyEncrypted.
    /// </summary>
    /// <param name="encryptedBlob">Encrypted blob containing: [1‑byte version][32‑byte salt][12‑byte nonce][16‑byte tag][encrypted raw private key].</param>
    /// <param name="password">Password used for encryption.</param>
    /// <param name="algorithm">The ML‑DSA algorithm corresponding to the key.</param>
    /// <returns>ML‑DSA instance initialized with the decrypted private key.</returns>
    /// <remarks>
    /// [SECURITY]  
    /// Validates blob structure and version. Uses PBKDF2(SHA‑256) to derive
    /// the AES key and AES‑GCM for authenticated decryption. Zeroizes derived
    /// key material on exit. Throws <see cref="CryptographicException"/> on
    /// authentication failure or malformed input.
    /// </remarks>
    public static MLDsa ImportRawFips204PrivateKeyEncrypted(byte[] encryptedBlob, string password, MLDsaAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(encryptedBlob);
        ArgumentNullException.ThrowIfNull(password);
        return ImportRawFips204PrivateKeyEncrypted(encryptedBlob.AsSpan(), password.AsSpan(), algorithm);
    }

    /// <summary>
    /// Imports an encrypted raw FIPS‑204 private key that was exported with ExportRawFips204PrivateKeyEncrypted.
    /// Span overload to avoid intermediate allocations for password and blob.
    /// </summary>
    /// <param name="encryptedBlob">Encrypted blob containing: [1‑byte version][32‑byte salt][12‑byte nonce][16‑byte tag][encrypted raw private key].</param>
    /// <param name="password">Password used for encryption.</param>
    /// <param name="algorithm">The ML‑DSA algorithm corresponding to the key.</param>
    /// <returns>ML‑DSA instance initialized with the decrypted private key.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Performs strict size checks based on expected raw private key size for
    /// the provided algorithm. Uses algorithm name as AAD to bind ciphertext
    /// to the expected algorithm identity.
    /// </remarks>
    public static MLDsa ImportRawFips204PrivateKeyEncrypted(ReadOnlySpan<byte> encryptedBlob, ReadOnlySpan<char> password, MLDsaAlgorithm algorithm)
    {
        int expectedRawSize = MLDsaAlgorithmMetadata.GetPrivateKeySize(algorithm);
        int minBlobSize = VersionSize + Pbkdf2SaltSize + AesGcmNonceSize + AesGcmTagSize + expectedRawSize;

        if (encryptedBlob.Length < minBlobSize)
        {
            throw new CryptographicException($"Encrypted blob is too small. Expected at least {minBlobSize} bytes, got {encryptedBlob.Length}");
        }

        byte version = encryptedBlob[0];
        if (version != CurrentVersion)
        {
            throw new CryptographicException($"Unsupported encrypted blob version: {version}. Expected version {CurrentVersion}");
        }

        ReadOnlySpan<byte> salt = encryptedBlob.Slice(VersionSize, Pbkdf2SaltSize);
        ReadOnlySpan<byte> nonce = encryptedBlob.Slice(VersionSize + Pbkdf2SaltSize, AesGcmNonceSize);
        ReadOnlySpan<byte> tag = encryptedBlob.Slice(VersionSize + Pbkdf2SaltSize + AesGcmNonceSize, AesGcmTagSize);
        ReadOnlySpan<byte> ciphertext = encryptedBlob.Slice(VersionSize + Pbkdf2SaltSize + AesGcmNonceSize + AesGcmTagSize);

        // Encode password into UTF‑8 bytes on the stack when possible.
        Span<byte> passwordBytes = stackalloc byte[password.Length * 3];
        int passwordBytesWritten = System.Text.Encoding.UTF8.GetBytes(password, passwordBytes);

        using var keyDerivation = new Rfc2898DeriveBytes(
            passwordBytes[..passwordBytesWritten].ToArray(),
            salt.ToArray(),
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256);
        byte[] key = keyDerivation.GetBytes(32);

        try
        {
            using var aesGcm = new AesGcm(key, AesGcmTagSize);
            byte[] plaintext = new byte[ciphertext.Length];

            try
            {
                // Use algorithm name as additional authenticated data
                byte[] aad = System.Text.Encoding.UTF8.GetBytes(algorithm.Name);

                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                return MLDsa.ImportMLDsaPrivateKey(algorithm, plaintext);
            }
            catch (CryptographicException)
            {
                // Zeroize plaintext on authentication failure before rethrowing
                CryptographicOperations.ZeroMemory(plaintext);
                throw;
            }
        }
        finally
        {
            // Zeroize derived key material
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Imports a raw FIPS‑204 public key (uncompressed FIPS‑204 format).
    /// </summary>
    /// <param name="rawPublicKey">Raw FIPS‑204 public key bytes (1312/1952/2592 bytes depending on algorithm).</param>
    /// <param name="algorithm">The ML‑DSA algorithm corresponding to the key.</param>
    /// <returns>ML‑DSA instance initialized with the public key.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Public key import is straightforward: the provided raw bytes are passed
    /// to the provider import routine. Caller should validate provenance if needed.
    /// </remarks>
    public static MLDsa ImportRawFips204PublicKey(byte[] rawPublicKey, MLDsaAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(rawPublicKey);
        return MLDsa.ImportMLDsaPublicKey(algorithm, rawPublicKey);
    }

    /// <summary>
    /// Imports a raw FIPS‑204 public key (uncompressed FIPS‑204 format) from a span.
    /// </summary>
    /// <param name="rawPublicKey">Raw FIPS‑204 public key bytes (1312/1952/2592 bytes depending on algorithm).</param>
    /// <param name="algorithm">The ML‑DSA algorithm corresponding to the key.</param>
    /// <returns>ML‑DSA instance initialized with the public key.</returns>
    /// <remarks>
    /// [INTEROP]  
    /// Span overload avoids array allocation when callers already manage
    /// public key material in spans.
    /// </remarks>
    public static MLDsa ImportRawFips204PublicKey(ReadOnlySpan<byte> rawPublicKey, MLDsaAlgorithm algorithm)
    {
        return MLDsa.ImportMLDsaPublicKey(algorithm, rawPublicKey);
    }
}
