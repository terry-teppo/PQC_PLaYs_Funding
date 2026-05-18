**DilithiumSdkWrapper**

**DilithiumSdkWrapper** is a focused, clean‑room .NET 10 wrapper around the platform MLDsa post‑quantum signature primitives. This single file demonstrates a safe, idiomatic, production‑ready approach to working with Dilithium keys and signatures in .NET 10 while providing interoperability with FIPS‑204 raw formats and standard PEM/PKCS#8 containers.

Use this module as a standalone interoperability helper or as a public proof point of the engineering quality behind the larger PoWChain project.

**Key Capabilities**

- **Create and use Dilithium keys** via the .NET 10 MLDsa API surface.
- **Sign and verify** data using PQC signatures.
- **Export and import** keys in multiple formats:

- PEM (SubjectPublicKeyInfo / PKCS#8)
- Encrypted PKCS#8 (password protected)
- Raw FIPS‑204 key formats for interoperability with other PQC tooling

- **Span‑friendly** overloads for high performance scenarios.
- **Explicit security warnings** for operations that expose raw private key material.

**Why publish this file**

- **Safe to share**: cryptographic interoperability helpers are useful to the community and do not reveal private protocol logic.
- **Proof of competence**: shows correct use of GA .NET 10 PQC APIs and careful handling of key material.
- **Reproducible**: the wrapper is self‑contained and can be used as a building block or reference implementation.

**Example Usage**

The examples below show typical usage patterns. Adapt names and parameters to match the exact API surface in the file.

**Create a key pair and sign data**

csharp

using System;

using System.Text;

// Create a new Dilithium key pair (MLDsa)

using var key = DilithiumSdkWrapper.GenerateKeyPair();

// Sign some data

byte[] message = Encoding.UTF8.GetBytes("hello world");

byte[] signature = DilithiumSdkWrapper.SignData(key, message);

// Verify the signature

bool ok = DilithiumSdkWrapper.VerifyData(key.PublicKey, message, signature);

Console.WriteLine(ok ? "Signature valid" : "Signature invalid");

**Export and import PEM**

csharp

// Export to PEM

string publicPem = DilithiumSdkWrapper.ExportPublicKeyToPem(key);

string privatePem = DilithiumSdkWrapper.ExportPrivateKeyToPem(key);

// Import from PEM

var imported = DilithiumSdkWrapper.ImportFromPem(privatePem);

**Encrypted PKCS#8 export and import**

csharp

string password = "correct horse battery staple";

byte[] encryptedPkcs8 = DilithiumSdkWrapper.ExportEncryptedPkcs8(key, password);

// Later, import with password

var importedKey = DilithiumSdkWrapper.ImportEncryptedPkcs8(encryptedPkcs8, password);

**Raw FIPS 204 interoperability**

csharp

// Export raw FIPS-204 private key bytes

byte[] rawPrivate = DilithiumSdkWrapper.ExportRawFips204PrivateKey(key);

// Import raw FIPS-204 private key bytes

var keyFromRaw = DilithiumSdkWrapper.ImportRawFips204PrivateKey(rawPrivate);

**Security Notes**

- **Do not** publish or store unencrypted private key material. The wrapper includes explicit warnings where raw private key bytes are exposed.
- Use **encrypted PKCS#8** exports for any persistent storage of private keys.
- Treat all raw byte arrays containing private keys as sensitive memory; zero them when no longer needed.
- This wrapper intentionally avoids unsafe code and custom cryptographic primitives — it relies on the platform System.Security.Cryptography primitives.

**Tests and Validation**

- Add a small unit test suite that covers:

- Key generation, sign, verify round trips
- PEM export/import round trips
- Encrypted PKCS#8 export/import round trips
- Raw FIPS‑204 export/import round trips

A minimal dotnet test project makes the wrapper easier to adopt and increases confidence for downstream users.
