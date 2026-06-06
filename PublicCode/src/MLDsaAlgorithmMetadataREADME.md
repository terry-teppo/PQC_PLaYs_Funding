# MLDsaAlgorithmMetadata README

This README documents **MLDsaAlgorithmMetadata.cs**, a small utility that exposes constant metadata for ML‑DSA (Dilithium) algorithm parameters used across the project. It provides raw FIPS‑204 key sizes, SPKI and PKCS#8 encoded sizes, signature sizes, and NIST security levels for each supported ML‑DSA algorithm.

### Purpose

- Provide **single‑source constants** for sizes and security levels used by raw key export/import, PEM/PKCS#8 handling, and signature buffers.
    
- Avoid magic numbers scattered through the codebase by centralizing algorithm metadata.
    

### Public API Summary

- **GetPublicKeySize(MLDsaAlgorithm algorithm)** — raw FIPS‑204 public key size in bytes.
    
- **GetRawFips204PublicKeySize(MLDsaAlgorithm algorithm)** — alias for `GetPublicKeySize`.
    
- **GetSpkiPublicKeySize(MLDsaAlgorithm algorithm)** — SubjectPublicKeyInfo (X.509 SPKI) encoded public key size in bytes.
    
- **GetPrivateKeySize(MLDsaAlgorithm algorithm)** — raw FIPS‑204 private key size (full expanded private key) in bytes.
    
- **GetRawFips204PrivateKeySize(MLDsaAlgorithm algorithm)** — alias for `GetPrivateKeySize`.
    
- **GetPkcs8PrivateKeySize(MLDsaAlgorithm algorithm)** — PKCS#8 PrivateKeyInfo encoded private key size in bytes (compressed seed representation).
    
- **GetSignatureSize(MLDsaAlgorithm algorithm)** — signature size in bytes.
    
- **GetSecurityLevel(MLDsaAlgorithm algorithm)** — NIST security level (2, 3, or 5).
    

### Algorithm Sizes and Security Levels

|**Algorithm**|**Raw Public Key bytes**|**Raw Private Key bytes**|**SPKI Public Key bytes**|**Signature bytes**|**NIST Level**|
|---|---|---|---|---|---|
|**MLDsa44**|1312|2560|1334|2420|2|
|**MLDsa65**|1952|4032|1974|3309|3|
|**MLDsa87**|2592|4896|2614|4627|5|

- **PKCS#8 PrivateKeyInfo size**: **54 bytes** for all supported algorithms (PKCS#8 stores the private seed rather than the full expanded key).
    

### Usage Notes

- Use `GetRawFips204PublicKeySize` and `GetRawFips204PrivateKeySize` when allocating buffers for raw export/import to ensure correct lengths for each algorithm.
    
- Use `GetSpkiPublicKeySize` when working with X.509/SPKI encoded public keys (the SPKI size includes ASN.1 overhead).
    
- Use `GetPkcs8PrivateKeySize` when estimating PKCS#8 storage or transmission sizes; note that PKCS#8 is a compact representation and does **not** contain the full expanded private key.
    
- Use `GetSignatureSize` to size signature buffers and to validate incoming signature lengths before verification.
    

### Error Handling

All methods throw `ArgumentOutOfRangeException` for unknown or unsupported `MLDsaAlgorithm` values. Callers should validate algorithm selection before relying on returned sizes.

### License

This file is part of the **PQC_PLaYs_Funding** repository. See the repository root for license terms.
