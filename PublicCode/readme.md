
# DilithiumSdkWrapper

**DilithiumSdkWrapper** is a focused, clean-room .NET 10 wrapper around the platform ML-DSA (Dilithium) post-quantum signature primitives.

This single file demonstrates a safe, idiomatic, production-ready approach to working with Dilithium keys and signatures in .NET 10 while providing interoperability with FIPS 204 raw formats and standard PEM/PKCS#8 containers.

Use this module as a standalone interoperability helper or as a public proof point of the engineering quality behind the larger PoWChain project.

---

## Key Capabilities

- **Create and use Dilithium keys** via the .NET 10 ML-DSA API surface.
- **Sign and verify** data using post-quantum signatures.
- **Export and import** keys in multiple formats:
    - PEM (SubjectPublicKeyInfo / PKCS#8)
    - Encrypted PKCS#8 (password-protected)
    - Raw FIPS 204 key formats for interoperability with other PQC tooling
- **Span-friendly overloads** for high-performance scenarios.
- **Explicit security warnings** for operations that expose raw private key material.

---

## Why Publish This File?

- **Safe to share** — Cryptographic interoperability helpers are useful to the community and do not reveal private protocol logic.
- **Proof of competence** — Demonstrates correct use of the GA .NET 10 PQC APIs and careful handling of sensitive key material.
- **Reproducible** — The wrapper is self-contained and can be used as a building block or reference implementation.

---

## Example Usage

The examples below show typical usage patterns. Adapt names and parameters to match the exact API surface in the file.

### Create a Key Pair and Sign Data

```
using System;using System.Text;// Create a new Dilithium key pair (ML-DSA)using var key = DilithiumSdkWrapper.GenerateKeyPair();// Sign some databyte[] message = Encoding.UTF8.GetBytes("hello world");byte[] signature = DilithiumSdkWrapper.SignData(key, message);// Verify the signaturebool ok = DilithiumSdkWrapper.VerifyData(    key.PublicKey,    message,    signature);Console.WriteLine(ok ? "Signature valid" : "Signature invalid");
```

### Export and Import PEM

```
// Export to PEMstring publicPem = DilithiumSdkWrapper.ExportPublicKeyToPem(key);string privatePem = DilithiumSdkWrapper.ExportPrivateKeyToPem(key);// Import from PEMusing var imported = DilithiumSdkWrapper.ImportFromPem(privatePem);
```

### Encrypted PKCS#8 Export and Import

```
string password = "correct horse battery staple";byte[] encryptedPkcs8 =    DilithiumSdkWrapper.ExportEncryptedPkcs8(key, password);// Later, import with passwordusing var importedKey =    DilithiumSdkWrapper.ImportEncryptedPkcs8(        encryptedPkcs8,        password);
```

### Raw FIPS 204 Interoperability

```
// Export raw FIPS 204 private key bytesbyte[] rawPrivate =    DilithiumSdkWrapper.ExportRawFips204PrivateKey(key);// Import raw FIPS 204 private key bytesusing var keyFromRaw =    DilithiumSdkWrapper.ImportRawFips204PrivateKey(rawPrivate);
```

---

## Security Notes

- **Do not** publish or store unencrypted private key material.
- Use **encrypted PKCS#8** exports for persistent storage.
- Treat all raw byte arrays containing private keys as sensitive memory and zero them when no longer needed.
- This wrapper intentionally avoids unsafe code and custom cryptographic primitives.
- All cryptographic operations rely exclusively on the platform `System.Security.Cryptography` APIs.

---

## Tests and Validation

Add a small unit test suite that covers:

- Key generation, signing, and verification round trips
- PEM export/import round trips
- Encrypted PKCS#8 export/import round trips
- Raw FIPS 204 export/import round trips

A minimal `dotnet test` project makes the wrapper easier to adopt and increases confidence for downstream users.

---

## Contributing

This file is published as a safe, standalone module. Contributions are welcome.

- Open small, focused pull requests (tests, documentation, or minor API ergonomics).
- Avoid changes that reveal private protocol logic from the main PoWChain project.
- Report security issues privately (see below).

---

## Security and Responsible Disclosure

If you discover a security vulnerability, **do not** open a public issue.

Contact the project lead directly with:

- A reproducible report
- Impact assessment
- Suggested mitigations (if available)

Maintainers will acknowledge the report and coordinate remediation and disclosure.

---

## Contact

- **Project Lead:** Terry
- **Repository:** `pqcplaysfunding/PublicCode/DilithiumSdkWrapper.cs`
- **Funding and sponsorship:** See the `pqcplaysfunding` funding hub.
