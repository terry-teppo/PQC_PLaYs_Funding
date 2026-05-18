using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace PQC_PLaYs_Funding.PublicCode
{
    /// <summary>
    /// Managed wrapper for the native CRYSTALS-Dilithium (ML-DSA) library.
    /// Provides methods for key generation, signing, and signature verification.
    /// </summary>
    public static class DilithiumSdkWrapper
    {
#if WINDOWS
        private const string NativeLibrary = "dilithium.dll";
#elif LINUX
        private const string NativeLibrary = "libdilithium.so";
#elif OSX
        private const string NativeLibrary = "libdilithium.dylib";
#else
        private const string NativeLibrary = "dilithium";
#endif

        // Update these constants to match the selected Dilithium parameter set.
        public const int PublicKeySize = 1312;   // Dilithium2
        public const int PrivateKeySize = 2528;  // Dilithium2
        public const int SignatureMaxSize = 2420;

        #region Native Methods

        [DllImport(NativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        private static extern int dilithium_generate_keypair(
            byte[] publicKey,
            byte[] privateKey);

        [DllImport(NativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        private static extern int dilithium_sign(
            byte[] signature,
            out int signatureLength,
            byte[] message,
            int messageLength,
            byte[] privateKey);

        [DllImport(NativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        private static extern int dilithium_verify(
            byte[] signature,
            int signatureLength,
            byte[] message,
            int messageLength,
            byte[] publicKey);

        #endregion

        #region Public API

        /// <summary>
        /// Generates a new Dilithium key pair.
        /// </summary>
        /// <returns>A tuple containing the public key and private key.</returns>
        /// <exception cref="CryptographicException">Thrown if key generation fails.</exception>
        public static (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
        {
            byte[] publicKey = new byte[PublicKeySize];
            byte[] privateKey = new byte[PrivateKeySize];

            int result = dilithium_generate_keypair(publicKey, privateKey);
            if (result != 0)
            {
                SecureZero(privateKey);
                throw new CryptographicException($"Dilithium key generation failed with code {result}.");
            }

            return (publicKey, privateKey);
        }

        /// <summary>
        /// Signs a message using the provided private key.
        /// </summary>
        /// <param name="message">The message to sign.</param>
        /// <param name="privateKey">The Dilithium private key.</param>
        /// <returns>The signature bytes.</returns>
        /// <exception cref="ArgumentNullException">Thrown if any argument is null.</exception>
        /// <exception cref="ArgumentException">Thrown if the private key length is invalid.</exception>
        /// <exception cref="CryptographicException">Thrown if signing fails.</exception>
        public static byte[] Sign(byte[] message, byte[] privateKey)
        {
            ValidateNotNull(message, nameof(message));
            ValidateNotNull(privateKey, nameof(privateKey));
            ValidateLength(privateKey, PrivateKeySize, nameof(privateKey));

            byte[] signature = new byte[SignatureMaxSize];

            int result = dilithium_sign(
                signature,
                out int signatureLength,
                message,
                message.Length,
                privateKey);

            if (result != 0)
                throw new CryptographicException($"Dilithium signing failed with code {result}.");

            if (signatureLength <= 0 || signatureLength > SignatureMaxSize)
                throw new CryptographicException("Native library returned an invalid signature length.");

            byte[] finalSignature = new byte[signatureLength];
            Buffer.BlockCopy(signature, 0, finalSignature, 0, signatureLength);

            SecureZero(signature);

            return finalSignature;
        }

        /// <summary>
        /// Verifies a Dilithium signature.
        /// </summary>
        /// <param name="message">The original message.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKey">The public key.</param>
        /// <returns>True if the signature is valid; otherwise false.</returns>
        public static bool Verify(byte[] message, byte[] signature, byte[] publicKey)
        {
            ValidateNotNull(message, nameof(message));
            ValidateNotNull(signature, nameof(signature));
            ValidateNotNull(publicKey, nameof(publicKey));
            ValidateLength(publicKey, PublicKeySize, nameof(publicKey));

            int result = dilithium_verify(
                signature,
                signature.Length,
                message,
                message.Length,
                publicKey);

            return result == 0;
        }

        /// <summary>
        /// Converts binary data to a Base64 string.
        /// </summary>
        public static string ToBase64(byte[] data)
        {
            ValidateNotNull(data, nameof(data));
            return Convert.ToBase64String(data);
        }

        /// <summary>
        /// Converts a Base64 string to binary data.
        /// </summary>
        public static byte[] FromBase64(string base64)
        {
            if (string.IsNullOrWhiteSpace(base64))
                throw new ArgumentException("Base64 string cannot be null or empty.", nameof(base64));

            return Convert.FromBase64String(base64);
        }

        /// <summary>
        /// Securely wipes a private key from memory.
        /// Call this when you no longer need the key.
        /// </summary>
        public static void ClearPrivateKey(byte[] privateKey)
        {
            if (privateKey != null)
                SecureZero(privateKey);
        }

        #endregion

        #region Validation Helpers

        private static void ValidateNotNull(byte[] value, string paramName)
        {
            if (value is null)
                throw new ArgumentNullException(paramName);
        }

        private static void ValidateLength(byte[] value, int expectedLength, string paramName)
        {
            if (value.Length != expectedLength)
            {
                throw new ArgumentException(
                    $"{paramName} must be exactly {expectedLength} bytes.",
                    paramName);
            }
        }

        #endregion

        #region Security Helpers

        private static void SecureZero(byte[] buffer)
        {
            if (buffer != null)
                CryptographicOperations.ZeroMemory(buffer);
        }

        #endregion
    }
}
