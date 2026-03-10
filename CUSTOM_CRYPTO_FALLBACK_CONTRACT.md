CUSTOM CRYPTO FALLBACK IMPLEMENTATION CONTRACT
================================================

The following details are based on analysis of the Wilson codebase.

## 1. ICryptoProvider.Create() CONTRACT

When CustomCryptoProvider.Create() is called for a signature provider:

### Call Chain:
CreateForVerifying() → CreateSignatureProvider() → CustomCryptoProvider.Create()

### EXACT ARGS PASSED TO Create() for Signature Providers:

Location: CryptoProviderFactory.cs, CreateSignatureProvider method

Parameters passed (3 args, in order):
  1. algorithm (string) - The signing algorithm (e.g., "ML-DSA-44")
  2. key (SecurityKey) - The SecurityKey being used
  3. willCreateSignatures (bool) - True for CreateForSigning, False for CreateForVerifying

EXACT CODE:
  signatureProvider = CustomCryptoProvider.Create(algorithm, key, willCreateSignatures) as SignatureProvider;

### IsSupportedAlgorithm() CONTRACT:

Parameters passed (3 args, in order):
  1. algorithm (string) - The signing algorithm
  2. key (SecurityKey) - The SecurityKey being used
  3. willCreateSignatures (bool) - True for signing, False for verifying

EXACT CODE:
  if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm, key, willCreateSignatures))

---

## 2. SIGNATURE PROVIDER BASE CLASS CONTRACT

File: SignatureProvider.cs

### Constructor Signature:

protected SignatureProvider(SecurityKey key, string algorithm)
  - Parameters:
    * key: The SecurityKey that will be used (required, not null)
    * algorithm: The signature algorithm (required, not null or empty)
  - Initializes reference count to 1

### REQUIRED: Abstract Methods to Implement:

1. public abstract byte[] Sign(byte[] input)
   - Must sign the input bytes
   - Returns the signature bytes

2. public abstract bool Verify(byte[] input, byte[] signature)
   - Must verify that signature matches input
   - Returns true if signature is valid, false otherwise
   - Parameters:
     * input: UTF-8 bytes of "header.payload" from JWT
     * signature: Raw decoded bytes from JWT signature segment

3. protected abstract void Dispose(bool disposing)
   - Clean up any resources

### OPTIONAL: Virtual Methods with Default Behavior:

1. public virtual byte[] Sign(byte[] input, int offset, int count)
   - Override to sign a region of bytes
   - Default throws NotImplementedException

2. public virtual bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength)
   - Override to verify a region of bytes
   - Default throws NotImplementedException

3. public virtual bool Sign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten) [NET6_0_OR_GREATER]
   - Override for span-based signing

### Properties:

1. public string Algorithm { get; } - Read-only algorithm name
2. public SecurityKey Key { get; } - Read-only security key
3. public bool WillCreateSignatures { get; protected set; } - Set in constructor
4. public string Context { get; set; } - User context
5. public CryptoProviderCache CryptoProviderCache { get; set; } - Associated cache

### Dispose Pattern:

public void Dispose()
  - Calls Dispose(true) and GC.SuppressFinalize(this)

protected abstract void Dispose(bool disposing)
  - Implement cleanup here
  - Called from Dispose() when disposing=true
  - Called from finalizer when disposing=false

### Internal Reference Counting (for factory):

These are managed by the factory, not the custom provider:
  - AddRef(): Called by cache
  - Release(): Called by factory
  - RefCount: Read-only
  - IsCached: Set by factory

---

## 3. FACTORY'S HANDLING OF Create() RETURN VALUE

File: CryptoProviderFactory.cs, CreateSignatureProvider method

### Processing Steps:

1. Your Create() method returns an object
2. Factory casts to SignatureProvider:
   signatureProvider = CustomCryptoProvider.Create(algorithm, key, willCreateSignatures) as SignatureProvider;

3. Factory validates the cast:
   if (signatureProvider == null)
       throw new InvalidOperationException (IDX10646)

4. NO post-creation property setting:
   - Factory does NOT set any properties on the returned SignatureProvider
   - Your constructor must set ALL required properties
   - Specifically: WillCreateSignatures MUST be set in constructor

5. Return directly:
   return signatureProvider;

### Caching Behavior:

For custom providers: NO automatic caching or reference counting by factory
  - Factory will NOT call AddRef() on custom providers
  - Factory will NOT cache custom providers
  - Factory calls Release() when done, YOU handle cleanup

---

## 4. ICryptoProvider.Release() CONTRACT

File: CryptoProviderFactory.cs, ReleaseSignatureProvider method

### When Called:

After JWT signature validation completes, factory calls:
  CustomCryptoProvider.Release(signatureProvider)

### Your Cleanup Responsibility:

When Release() is called with a SignatureProvider object:

1. Do NOT automatically call Dispose() 
   - Factory will dispose non-cached providers
   - If you're caching/pooling, manage disposal yourself

2. If implementing caching:
   - Increment/decrement reference counts in Create()/Release()
   - Only dispose when refcount reaches 0 and cache is full

3. Example from test implementation:
   public void Release(object cryptoObject)
   {
       if (cryptoObject as ICustomObject != null)
           return;
       
       if (cryptoObject is IDisposable disposableObject)
           disposableObject.Dispose();
   }

---

## 5. KEY DATA FLOW FOR VERIFICATION

File: JwtSecurityTokenHandler.cs, ValidateSignatureAndIssuerSecurityKey method

### Byte Creation:

  byte[] encodedBytes = Encoding.UTF8.GetBytes(jwtToken.RawHeader + "." + jwtToken.RawPayload);
  byte[] signatureBytes = Base64UrlEncoder.DecodeBytes(jwtToken.RawSignature);

### Input Parameter (encodedBytes):

- Type: byte[]
- Content: UTF-8 encoded bytes of "RawHeader.RawPayload"
- Example: UTF-8 bytes of "eyJ...base64url...eyJ...base64url..."
- NOT decoded - kept as ASCII/UTF-8 characters
- This is the exact message that was signed

### Signature Parameter (signatureBytes):

- Type: byte[]
- Content: Raw binary bytes from Base64UrlEncoder.DecodeBytes(jwtToken.RawSignature)
- NOT base64url encoded - fully decoded to binary

### Transformations Applied:

1. Input: UTF-8 encoding ONLY
   - No decoding of base64url
   - No hashing
   - Raw "header.payload" as UTF-8 bytes

2. Signature: Base64UrlEncoder.DecodeBytes() ONLY
   - Converts "signature_part" from base64url string to raw binary
   - No hashing

---

## 6. ML-DSA SECURITY KEY - ACCESSING RAW PUBLIC KEY

File: MlDsaSecurityKey.cs

### Direct Public Access:

public MLDsa MLDsa { get; private set; }

### Get Public Key Bytes:

  byte[] publicKeyBytes = ((MlDsaSecurityKey)key).MLDsa.ExportMLDsaPublicKey();

- Method: MLDsa.ExportMLDsaPublicKey()
- Returns: Raw public key bytes (pure ML-DSA public key material)
- Available on any MlDsaSecurityKey instance
- Safe to call, no exceptions

### Get Private Key (for signing only):

  byte[] privateSeed = ((MlDsaSecurityKey)key).MLDsa.ExportMLDsaPrivateSeed();

- Method: MLDsa.ExportMLDsaPrivateSeed()
- Returns: Raw seed bytes for private key
- Throws CryptographicException if no private key
- Only call when WillCreateSignatures=true

### Via JsonWebKey Alternative:

If you have JsonWebKey instead of MlDsaSecurityKey:

1. Option A - Direct property access:
   byte[] pubKeyBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.Pub);

2. Option B - Convert to MlDsaSecurityKey:
   if (JsonWebKeyConverter.TryConvertToSecurityKey(jsonWebKey, out SecurityKey securityKey))
   {
       if (securityKey is MlDsaSecurityKey mlDsaKey)
       {
           byte[] pubKeyBytes = mlDsaKey.MLDsa.ExportMLDsaPublicKey();
       }
   }

### Key Sizes:

From MlDsaSecurityKey.KeySize property:
  int keySize = MLDsa.Algorithm.PublicKeySizeInBytes * 8;

Standard sizes:
  - ML-DSA-44: 10496 bits (1312 bytes)
  - ML-DSA-65: 15616 bits (1952 bytes)
  - ML-DSA-87: 20736 bits (2592 bytes)

---

## 7. EXISTING CUSTOM CRYPTO PROVIDER EXAMPLES

File: test/Microsoft.IdentityModel.Tokens.Tests/CustomCryptoProviders.cs

### Reference Implementation 1: Minimal Custom Provider

class CustomSignatureProvider : SignatureProvider
{
    public CustomSignatureProvider(SecurityKey key, string algorithm, bool willCreateSignatures)
        : base(key, algorithm)
    {
        WillCreateSignatures = willCreateSignatures;
    }

    public override byte[] Sign(byte[] input)
    {
        // Your signing implementation
        return new byte[64];
    }

    public override bool Verify(byte[] input, byte[] signature)
    {
        // Your verification implementation
        return true;
    }

    protected override void Dispose(bool disposing)
    {
        // Cleanup code
    }
}

### Reference Implementation 2: ICryptoProvider Implementation

class CustomCryptoProvider : ICryptoProvider
{
    public List<string> SupportedAlgorithms { get; } = new List<string>();
    public SignatureProvider SignatureProvider { get; set; }

    public bool IsSupportedAlgorithm(string algorithm, params object[] args)
    {
        foreach (var alg in SupportedAlgorithms)
        {
            if (alg.Equals(algorithm, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public object Create(string algorithm, params object[] args)
    {
        // args[0] = algorithm (string)
        // args[1] = key (SecurityKey)
        // args[2] = willCreateSignatures (bool)
        
        if (IsSupportedAlgorithm(algorithm, args))
        {
            return SignatureProvider;
        }
        return null;
    }

    public void Release(object cryptoInstance)
    {
        if (cryptoInstance is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}

### Usage in Custom Factory:

class CustomCryptoProviderFactory : CryptoProviderFactory
{
    public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
    {
        if (CustomCryptoProvider != null && 
            CustomCryptoProvider.IsSupportedAlgorithm(algorithm, key, willCreateSignatures: false))
        {
            return CustomCryptoProvider.Create(algorithm, key, false) as SignatureProvider;
        }
        
        // Fall back to default factory behavior
        return base.CreateForVerifying(key, algorithm);
    }
}

---

## ML-DSA CUSTOM FALLBACK IMPLEMENTATION CHECKLIST

✓ Create ICryptoProvider implementation:

  public bool IsSupportedAlgorithm(string algorithm, params object[] args)
  {
      // args[0] = algorithm (string)
      // args[1] = key (SecurityKey)
      // args[2] = willCreateSignatures (bool)
      
      if (args.Length >= 3 && args[1] is MlDsaSecurityKey)
      {
          bool willCreateSignatures = (bool)args[2];
          return algorithm == SecurityAlgorithms.MlDsa44 
              && !willCreateSignatures;  // For fallback: verification only
      }
      return false;
  }

  public object Create(string algorithm, params object[] args)
  {
      // args[0] = algorithm (string)
      // args[1] = key (SecurityKey)
      // args[2] = willCreateSignatures (bool)
      
      var key = (MlDsaSecurityKey)args[1];
      bool willCreateSignatures = (bool)args[2];
      
      return new SymCryptMlDsaSignatureProvider(key, algorithm, willCreateSignatures);
  }

  public void Release(object cryptoInstance)
  {
      (cryptoInstance as IDisposable)?.Dispose();
  }

✓ Create SignatureProvider subclass:

  class SymCryptMlDsaSignatureProvider : SignatureProvider
  {
      private readonly MLDsa _mlDsa;
      private readonly byte[] _publicKeyBytes;

      public SymCryptMlDsaSignatureProvider(MlDsaSecurityKey key, string algorithm, bool willCreateSignatures)
          : base(key, algorithm)
      {
          WillCreateSignatures = willCreateSignatures;
          _mlDsa = key.MLDsa;
          
          if (!willCreateSignatures)
          {
              _publicKeyBytes = _mlDsa.ExportMLDsaPublicKey();
          }
      }

      public override byte[] Sign(byte[] input)
      {
          // Not implemented for fallback (verification only)
          throw new NotSupportedException();
      }

      public override bool Verify(byte[] input, byte[] signature)
      {
          // Call SymCrypt native verification with:
          // - input: UTF-8 bytes of "header.payload"
          // - signature: Raw decoded bytes
          // - _publicKeyBytes: Raw ML-DSA public key
          
          try
          {
              return SymCryptMlDsaVerify(_publicKeyBytes, input, signature);
          }
          catch (CryptographicException)
          {
              return false;
          }
      }

      protected override void Dispose(bool disposing)
      {
          if (disposing)
          {
              // Clear any sensitive data
              if (_publicKeyBytes != null)
              {
                  System.Security.Cryptography.CryptographicOperations.ZeroMemory(_publicKeyBytes);
              }
          }
      }
  }

✓ Key points for SymCrypt integration:
  - Use _mlDsa.ExportMLDsaPublicKey() for verification
  - Input bytes are UTF-8 encoded "header.payload" - pass as-is
  - Signature bytes are raw decoded bytes - pass as-is
  - Return false on any CryptographicException (invalid signature)
  - WillCreateSignatures=false means don't implement Sign()
  - Call Base64UrlEncoder.DecodeBytes() only if working with raw JWT strings

