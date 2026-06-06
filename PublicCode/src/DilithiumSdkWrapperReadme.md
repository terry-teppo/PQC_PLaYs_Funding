
# **DilithiumSdkWrapper — .NET 10 Wrapper for FIPS‑204 ML‑DSA (Dilithium)**

A lightweight, high‑level .NET 10 wrapper around the platform‑native **ML‑DSA (Dilithium)** implementation provided by **System.Security.Cryptography**. This wrapper simplifies key generation, signing, verification, PEM import/export, encrypted PKCS#8 handling, and FIPS‑204 raw key operations.

- ![Emerging Post Quantum Cryptography and the Importance of PUF based Root ...](https://ts4.mm.bing.net/th?id=OIP.4SJo6rIdkzX5btWxw7IFeAHaDT&pid=15.1&o=7&rm=3)
    
- ![#cryptography #postquantumsecurity #kyber #dilithium #digitalsignatures ...](https://ts3.mm.bing.net/th?id=OIP.7nPvH4uS0o6xqSXx6hfNvwHaG8&pid=15.1&o=7&rm=3)
    
- ![What Is Post-Quantum Cryptography (PQC)? A Complete Guide - Palo Alto ...](https://ts1.mm.bing.net/th?id=OIP.0pDQnw8IX-LgcTUTAD0uvAHaFv&pid=15.1&o=7&rm=3)
    
- ![Syrga2: Post-Quantum Hash-Based Signature Scheme](https://ts3.mm.bing.net/th?id=OIP.ffUbsrx9H2J_4WmaGFFjgAHaDF&pid=15.1&o=7&rm=3)
    

## **Features**

- High‑level API over `MLDsa` (FIPS‑204 Dilithium)
    
- Key generation for all supported suites (Dilithium2/3/5)
    
- Sign and verify data using byte arrays or spans
    
- Export/import keys in:
    
    - **PEM (PKCS#8)**
        
    - **Encrypted PKCS#8 (PBES2)**
        
    - **Raw FIPS‑204 key formats**
        
- Span‑based APIs for zero‑allocation workflows
    
- Safe disposal of underlying cryptographic resources
    
- Suite‑aware import logic
    

# **API Overview**

## **Construction**

```csharp
var wrapper = new DilithiumSdkWrapper(DilithiumSuite.Dilithium3);
```

### **Constructor**

```csharp
public DilithiumSdkWrapper(DilithiumSuite suite)
```

Creates a new ML‑DSA keypair using the specified suite.

## **Properties**

### **Algorithm**

```csharp
public MLDsaAlgorithm Algorithm { get; }
```

Returns the underlying algorithm instance.

### **IsSupported**

```csharp
public static bool IsSupported { get; }
```

Indicates whether ML‑DSA is supported on the current platform.

# **Signing & Verification**

### **Sign data**

```csharp
public byte[] SignData(byte[] data)
public byte[] SignData(ReadOnlySpan<byte> data)
```

### **Verify signature**

```csharp
public bool VerifyData(byte[] data, byte[] signature)
public bool VerifyData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
```

# **PEM Export / Import**

## **Export public key (PEM)**

```csharp
public string ExportPublicKeyPem()
```

## **Export private key (unencrypted PKCS#8 PEM)**

```csharp
public string ExportPrivateKeyPem()
```

## **Import public key (PEM)**

```csharp
public void ImportPublicKeyPem(string pem)
```

## **Import private key (unencrypted PKCS#8 PEM)**

```csharp
public void ImportPrivateKeyPem(string pem)
```

# **Encrypted PKCS#8 Private Keys**

## **Export encrypted private key**

```csharp
public string ExportEncryptedPrivateKeyPem(ReadOnlySpan<char> password)
```

## **Import encrypted private key**

```csharp
public void ImportEncryptedPrivateKeyPem(string pem, ReadOnlySpan<char> password)
```

# **Raw FIPS‑204 Key Support**

These APIs allow direct access to the raw ML‑DSA key material as defined in FIPS‑204.

## **Export raw private key**

```csharp
public byte[] ExportRawFips204PrivateKey()
```

## **Export raw private key (encrypted)**

```csharp
public byte[] ExportRawFips204PrivateKeyEncrypted(ReadOnlySpan<char> password)
```

## **Export raw public key**

```csharp
public byte[] ExportRawFips204PublicKey()
```

# **Import Raw FIPS‑204 Keys**

## **Import raw private key**

```csharp
public void ImportRawFips204PrivateKey(ReadOnlySpan<byte> key, DilithiumSuite suite)
```

## **Import raw private key (encrypted)**

```csharp
public void ImportRawFips204PrivateKeyEncrypted(
    ReadOnlySpan<byte> encryptedKey,
    ReadOnlySpan<char> password,
    DilithiumSuite suite)
```

## **Import raw public key**

```csharp
public void ImportRawFips204PublicKey(ReadOnlySpan<byte> key, DilithiumSuite suite)
```

# **Disposal**

The wrapper owns an internal `MLDsa` instance and must be disposed:

```csharp
public void Dispose()
```

Usage:

```csharp
using var wrapper = new DilithiumSdkWrapper(DilithiumSuite.Dilithium2);
```

# **Example Usage**

## **Generate keys, sign, verify**

csharp

```
using var dil = new DilithiumSdkWrapper(DilithiumSuite.Dilithium3);

var data = Encoding.UTF8.GetBytes("hello world");
var sig = dil.SignData(data);

bool ok = dil.VerifyData(data, sig);
Console.WriteLine($"Signature valid: {ok}");
```

## **Export & import PEM keys**

```csharp

using var dil = new DilithiumSdkWrapper(DilithiumSuite.Dilithium2);

string pubPem = dil.ExportPublicKeyPem();
string privPem = dil.ExportPrivateKeyPem();

var dil2 = new DilithiumSdkWrapper(DilithiumSuite.Dilithium2);
dil2.ImportPublicKeyPem(pubPem);
dil2.ImportPrivateKeyPem(privPem);
```

## **Encrypted PKCS#8**

```csharp
string encryptedPem = dil.ExportEncryptedPrivateKeyPem("mypassword");

var dil3 = new DilithiumSdkWrapper(DilithiumSuite.Dilithium3);
dil3.ImportEncryptedPrivateKeyPem(encryptedPem, "mypassword");
```

## **Raw FIPS‑204 keys**

```csharp
byte[] rawPriv = dil.ExportRawFips204PrivateKey();
byte[] rawPub  = dil.ExportRawFips204PublicKey();

var dil4 = new DilithiumSdkWrapper(DilithiumSuite.Dilithium3);
dil4.ImportRawFips204PrivateKey(rawPriv, DilithiumSuite.Dilithium3);
dil4.ImportRawFips204PublicKey(rawPub, DilithiumSuite.Dilithium3);
```

# **Security Notes**

- Private keys should be stored encrypted whenever possible.
    
- Avoid keeping raw key material in memory longer than necessary.
    
- Always dispose the wrapper to release sensitive resources.
    
- Never transmit private keys over insecure channels.
