# FipsInterop README

A compact, production‑ready README for **FipsInterop.cs** — a helper that provides raw FIPS‑204 (ML‑DSA / Dilithium) key export/import and password‑protected raw key blobs for interoperability with FIPS‑native implementations (HSMs, other runtimes, toolchains). This README documents the exact behavior, formats, and recommended usage of the code in `FipsInterop.cs`.

- ![Hysteresis Flow Diagram 📈 Key Flow Characteristics: 🔄 Bidirectional ...](https://ts3.mm.bing.net/th?id=OIP.hbRVJEQJhEih0F7Xj56CmwHaLl&pid=15.1&o=7&rm=3)
    
- ![API Key Authentication Best Practices - Zuplo](https://ts3.mm.bing.net/th?id=OIP.rrbqmfRSbsjv0sv2SeZCegHaD_&pid=15.1&o=7&rm=3)
    
- ![Enterprise Architecture Diagram | Boardmix](https://ts1.mm.bing.net/th?id=OIP.CyFxwh65bPOqn2SLqMCmAgHaFd&pid=15.1&o=7&rm=3)
    
- ![Screen Process Flow Diagram](https://ts4.mm.bing.net/th?id=OIP.YsFul6HICcTifYped9NaRgHaFb&pid=15.1&o=7&rm=3)
    

## Overview

**FipsInterop** exposes safe, explicit helpers to:

- Export raw FIPS‑204 private and public keys.
    
- Export raw private keys **encrypted** with PBKDF2‑SHA256 + AES‑256‑GCM.
    
- Import raw private and public keys, including decryption of the encrypted raw private key format.
    
- Zeroize sensitive buffers where appropriate to reduce in‑memory exposure.
    

This utility is intended for **interoperability** (moving raw key material between implementations) and **not** as a general-purpose key storage API. Prefer standard PKCS#8 PEM or platform key stores for routine key management.

## Features and Formats

**Key operations implemented**

- `ExportRawFips204PrivateKey(MLDsa mldsa)` — returns the full expanded private key bytes.
    
- `ExportRawFips204PublicKey(MLDsa mldsa)` — returns the uncompressed FIPS‑204 public key bytes.
    
- `ExportRawFips204PrivateKeyEncrypted(MLDsa mldsa, string password)` — returns an encrypted blob using PBKDF2‑SHA256 and AES‑256‑GCM.
    
- `ImportRawFips204PrivateKey(byte[] rawPrivateKey, MLDsaAlgorithm algorithm)` and span overloads — imports raw private key material and zeroizes the input buffer where applicable.
    
- `ImportRawFips204PrivateKeyEncrypted(byte[] encryptedBlob, string password, MLDsaAlgorithm algorithm)` — decrypts the blob and imports the private key.
    
- `ImportRawFips204PublicKey(byte[] rawPublicKey, MLDsaAlgorithm algorithm)` and span overloads — imports raw public key material.
    

**Encrypted blob layout**

The encrypted raw private key blob produced by `ExportRawFips204PrivateKeyEncrypted` has the exact byte layout:

- **[1 byte]** version (currently `0x01`)
    
- **[32 bytes]** PBKDF2 salt
    
- **[12 bytes]** AES‑GCM nonce
    
- **[16 bytes]** AES‑GCM tag
    
- **[variable]** ciphertext (AES‑GCM of the raw private key)
    

The implementation uses **PBKDF2 (Rfc2898DeriveBytes)** with **SHA‑256**, **600,000 iterations**, a **32‑byte salt**, and derives a 32‑byte key for **AES‑256‑GCM**. The algorithm name is used as AAD for AES‑GCM to bind the ciphertext to the expected ML‑DSA algorithm.

## API Reference (signatures and behavior)

> All methods throw `ArgumentNullException` for null inputs where applicable and `CryptographicException` for malformed or unsupported blobs.

### Export

csharp

```csharp
public static byte[] ExportRawFips204PrivateKey(MLDsa mldsa)
public static byte[] ExportRawFips204PublicKey(MLDsa mldsa)
public static byte[] ExportRawFips204PrivateKeyEncrypted(MLDsa mldsa, string password)
public static byte[] ExportRawFips204PrivateKeyEncrypted(MLDsa mldsa, ReadOnlySpan<char> password)
```

- **Behavior**: `ExportRawFips204PrivateKey` returns the full expanded private key (size depends on suite).
    
- **Encrypted export**: Produces the versioned blob described above. Passwords are UTF‑8 encoded; temporary buffers are zeroized where possible.
    

### Import

csharp

```csharp
public static MLDsa ImportRawFips204PrivateKey(byte[] rawPrivateKey, MLDsaAlgorithm algorithm)
public static MLDsa ImportRawFips204PrivateKey(ReadOnlySpan<byte> rawPrivateKey, MLDsaAlgorithm algorithm)
public static MLDsa ImportRawFips204PrivateKeyEncrypted(byte[] encryptedBlob, string password, MLDsaAlgorithm algorithm)
public static MLDsa ImportRawFips204PrivateKeyEncrypted(ReadOnlySpan<byte> encryptedBlob, ReadOnlySpan<char> password, MLDsaAlgorithm algorithm)
public static MLDsa ImportRawFips204PublicKey(byte[] rawPublicKey, MLDsaAlgorithm algorithm)
public static MLDsa ImportRawFips204PublicKey(ReadOnlySpan<byte> rawPublicKey, MLDsaAlgorithm algorithm)
```

- **Behavior**: Import methods call the platform `MLDsa.ImportMLDsaPrivateKey` / `ImportMLDsaPublicKey`. Encrypted import validates version, derives the AES key with the same PBKDF2 parameters, verifies AES‑GCM tag, and returns an `MLDsa` instance initialized with the decrypted private key. Input buffers are zeroized when the implementation can do so. Errors on invalid blobs or authentication failures raise `CryptographicException`.
    

## Usage Examples

### Export encrypted raw private key

csharp

```csharp
using var mldsa = new MLDsa(DilithiumSuite.Dilithium3); // example
byte[] encrypted = FipsInterop.ExportRawFips204PrivateKeyEncrypted(mldsa, "strong-password-123!");
// store encrypted blob safely
```

### Import encrypted raw private key

csharp

```
MLDsa algInstance = FipsInterop.ImportRawFips204PrivateKeyEncrypted(encryptedBlob, "strong-password-123!", MLDsaAlgorithm.Dilithium3);
```

### Import raw public key

csharp

```csharp
MLDsa pub = FipsInterop.ImportRawFips204PublicKey(rawPublicKeyBytes, MLDsaAlgorithm.Dilithium2);
```

## Security Guidance

- **Do not export raw private keys unless absolutely necessary.** Raw private keys expose the full expanded secret material (thousands of bytes). Prefer PKCS#8 PEM or platform key stores.
    
- **Use the encrypted export** (`ExportRawFips204PrivateKeyEncrypted`) for any transport or at‑rest storage of raw private keys. The implementation’s PBKDF2 iteration count is high (600,000) to slow brute‑force attacks.
    
- **Choose strong passwords** (minimum 12 characters recommended) and protect them with secure secret management.
    
- **Zeroize sensitive buffers** and call `Dispose` on `MLDsa` instances when finished. The helper zeroizes some buffers internally, but callers must still follow best practices.
    

- ![Network Security Editable Diagram | EdrawMax Template](https://ts3.mm.bing.net/th?id=OIP.3OXOlKyQIGEtPuxL4LZVRQHaF_&pid=15.1&o=7&rm=3)
    
- ![Free Network Diagram Templates, Editable and Downloadable](https://ts4.mm.bing.net/th?id=OIP.TQwS2TtlUonSZzGJYo297AHaFV&pid=15.1&o=7&rm=3)
    
- ![Network Security Diagram | EdrawMax Templates](https://ts2.mm.bing.net/th?id=OIP.QLqRwrfaLeCmfnJNWfCJhgHaET&pid=15.1&o=7&rm=3)
    
- ![How to Create a Security Architecture Tutorial](https://ts3.mm.bing.net/th?id=OIP.PtCM_Q-bavMVYR0cRIUsjwHaEK&pid=15.1&o=7&rm=3)
    

## License and Attribution

This file is part of the **PQC_PLaYs_Funding** repository. Refer to the repository root for license terms. The README reflects the implementation and formats defined in `FipsInterop.cs`.


## Precise findings (line‑level summary)

### ✅ Good things already present

- **Span overloads for password and key inputs** are implemented (e.g., `ExportRawFips204PrivateKeyEncrypted(MLDsa, ReadOnlySpan<char>)` and `ImportRawFips204PrivateKeyEncrypted(ReadOnlySpan<byte>, ReadOnlySpan<char>, MLDsaAlgorithm)`).
    
- **Stackalloc** is used to encode the password to UTF‑8 into a `Span<byte>` before deriving the key.
    
- **PBKDF2 (Rfc2898DeriveBytes)** with **SHA‑256** and **600,000 iterations** is used.
    
- **AES‑GCM** is used for AEAD with a 12‑byte nonce and 16‑byte tag; the algorithm name is used as AAD.
    
- **Some zeroization** calls exist (`CryptographicOperations.ZeroMemory`) for `rawPrivateKey` and for derived `key` in `finally` blocks.
    

### ⚠️ Issues and gaps to fix

1. **Temporary arrays are allocated and not pooled**
    
    - The code calls `.ToArray()` on the UTF‑8 password span to feed `Rfc2898DeriveBytes`, and `Rfc2898DeriveBytes.GetBytes(32)` returns a `byte[] key`. The code zeroes `key` in `finally`, but it does **not** use `ArrayPool` for large buffers (ciphertext, plaintext, key), so GC allocations are high and zeroization semantics are less explicit.
        
2. **Plaintext not zeroed after successful import**
    
    - In `ImportRawFips204PrivateKeyEncrypted`, after successful `aesGcm.Decrypt(...)` the code calls `MLDsa.ImportMLDsaPrivateKey(algorithm, plaintext)` and **returns** the `MLDsa` instance without zeroing the `plaintext` buffer afterwards. The `plaintext` array therefore remains in managed memory until GC. The code only zeroes `plaintext` in the `catch` branch.
        
3. **Export path allocates ciphertext and tag arrays**
    
    - `ExportRawFips204PrivateKeyEncrypted` creates `ciphertext` and `tag` as `new byte[...]` and returns a `result` array assembled with `Buffer.BlockCopy`. While `ciphertext` is zeroed before return, these allocations could be replaced with pooled buffers to reduce GC pressure.
        
4. `ImportRawFips204PrivateKey(ReadOnlySpan<byte>)` **does not zero input**
    
    - The span overload returns `MLDsa.ImportMLDsaPrivateKey(algorithm, rawPrivateKey)` directly. A `ReadOnlySpan<byte>` cannot be zeroed by the callee, so callers must be careful. The byte[] overload does zero the input in a `finally`. This is correct behavior but should be documented clearly.
        
5. **Password handling still allocates a temporary array**
    
    - The code encodes the password into a stackalloc buffer, then calls `.ToArray()` to pass into `Rfc2898DeriveBytes`. That `.ToArray()` creates a managed array that is not explicitly zeroed. The derived key is zeroed, but the intermediate password byte array is not.
        
6. **No use of** `CryptographicOperations.FixedTimeEquals` **where applicable**
    
    - The code relies on `AesGcm.Decrypt` to authenticate; that is fine for tag verification. For any manual tag or version checks, prefer fixed‑time comparisons. (The file does version check with a single byte — that’s fine; just avoid secret comparisons elsewhere.)
