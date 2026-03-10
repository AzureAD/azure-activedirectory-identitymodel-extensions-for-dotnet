# Microsoft.IdentityModel.Tokens.Pqc.Composite

> ⚠️ **Experimental** — This package tracks an evolving IETF draft and its API may change
> between versions. Usage produces compiler warning `MSIDENT2001`.

Composite ML-DSA signature support for [Microsoft.IdentityModel](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet),
implementing **`draft-ietf-jose-pq-composite-sigs-01`** (JOSE Post-Quantum Composite Signatures).

Composite signatures pair a post-quantum algorithm (ML-DSA) with a traditional algorithm
(ECDSA or EdDSA), producing a single combined signature. This provides quantum resistance
while maintaining backward-verifiable security through the traditional component.

## Quick Start

```csharp
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Pqc.Composite;
using System.Security.Cryptography;

// 1. Register the composite crypto provider (one-time, typically at startup)
#pragma warning disable MSIDENT2001 // Experimental API
CryptoProviderFactory.Default.CustomCryptoProvider = new CompositeMLDsaCryptoProvider();

// 2. Generate a composite key
using var compositeKey = CompositeMLDsaSecurityKey.Create(
    CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256);

// 3. Sign a JWT
var handler = new JsonWebTokenHandler();
var descriptor = new SecurityTokenDescriptor
{
    Issuer = "https://example.com",
    Audience = "https://api.example.com",
    SigningCredentials = new SigningCredentials(
        compositeKey,
        CompositeMLDsaAlgorithms.MlDsa44Es256)
};

string token = handler.CreateToken(descriptor);

// 4. Validate the token
var result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
{
    ValidIssuer = "https://example.com",
    ValidAudience = "https://api.example.com",
    IssuerSigningKey = compositeKey,
    CryptoProviderFactory = CryptoProviderFactory.Default
});
#pragma warning restore MSIDENT2001
```

## Supported Algorithms

Per `draft-ietf-jose-pq-composite-sigs-01`, six composite algorithms are defined:

| JOSE `alg` value | ML-DSA | Traditional | .NET Status |
|---|---|---|---|
| `ML-DSA-44-ES256` | ML-DSA-44 | ECDSA P-256 | ✅ Supported |
| `ML-DSA-65-ES256` | ML-DSA-65 | ECDSA P-256 | ✅ Supported |
| `ML-DSA-87-ES384` | ML-DSA-87 | ECDSA P-384 | ✅ Supported |
| `ML-DSA-44-Ed25519` | ML-DSA-44 | Ed25519 | ⏳ Pending .NET support |
| `ML-DSA-65-Ed25519` | ML-DSA-65 | Ed25519 | ⏳ Pending .NET support |
| `ML-DSA-87-Ed448` | ML-DSA-87 | Ed448 | ⏳ Pending .NET support |

The three ECDSA-based algorithms are fully functional. The three EdDSA-based algorithms
are defined as constants but will throw `PlatformNotSupportedException` until .NET adds
runtime support for Ed25519/Ed448 composite variants.

## CryptoProvider Chaining

Wilson's `CryptoProviderFactory.CustomCryptoProvider` is a **single slot**. If your
application already uses a custom `ICryptoProvider`, you need to chain them:

```csharp
public class ChainedCryptoProvider : ICryptoProvider
{
    private readonly ICryptoProvider[] _providers;

    public ChainedCryptoProvider(params ICryptoProvider[] providers)
        => _providers = providers;

    public bool IsSupportedAlgorithm(string algorithm, params object[] args)
        => _providers.Any(p => p.IsSupportedAlgorithm(algorithm, args));

    public object Create(string algorithm, params object[] args)
        => _providers.First(p => p.IsSupportedAlgorithm(algorithm, args))
                     .Create(algorithm, args);

    public void Release(object cryptoInstance)
    {
        foreach (var p in _providers)
            p.Release(cryptoInstance);
    }
}

// Usage
CryptoProviderFactory.Default.CustomCryptoProvider = new ChainedCryptoProvider(
    new CompositeMLDsaCryptoProvider(),
    existingProvider);
```

## JWK Format

Composite keys use `kty: "AKP"` (Algorithm Key Pair) per the JOSE draft:

```json
{
    "kty": "AKP",
    "alg": "ML-DSA-44-ES256",
    "pub": "<base64url-encoded SPKI public key>",
    "priv": "<base64url-encoded PKCS#8 private key>"
}
```

Use `CompositeMLDsaJwkSerializer` to convert between `CompositeMLDsaSecurityKey` and `JsonWebKey`.

## Package Lifecycle

This package follows a three-phase lifecycle aligned with the IETF standardisation process:

### Phase 1 — Experimental (current)
- Tracks `draft-ietf-jose-pq-composite-sigs` as it evolves through working group drafts
- API may change between package versions to match draft revisions
- Marked with `[Experimental("MSIDENT2001")]` — produces a compiler warning
- Suitable for prototyping, testing, and early integration work

### Phase 2 — Stable Preview
- Begins when the IETF draft enters Working Group Last Call (~mid 2027)
- API stabilises; breaking changes become exceptional
- `[Experimental]` attribute may be replaced with `[Preview]` or similar

### Phase 3 — Graduation
- When the RFC is published (~mid-to-late 2028), composite types will be folded into
  `Microsoft.IdentityModel.Tokens` alongside existing key types
- This package will be deprecated with guidance to migrate to the core library types
- The external package approach ensures Wilson's stable API is never at risk during spec evolution

## Important Notes

### .NET Combiner Divergence

This implementation delegates to .NET's `System.Security.Cryptography.CompositeMLDsa` class,
which follows the **LAMPS** composite signatures specification (`draft-ietf-lamps-pq-composite-sigs`).
The JOSE draft specifies a slightly different combiner that base64url-encodes the message
representation (M') before signing, while the LAMPS combiner uses binary encoding.

**Impact:** Signatures produced by this package may not be interoperable with other JOSE
composite signature implementations until .NET's `CompositeMLDsa` aligns with the JOSE-specific
combiner. This is acceptable for the experimental phase — as .NET evolves to support the JOSE
combiner variant, this package will benefit automatically with no code changes required.

### Known Limitation: `JsonWebTokenHandler.CreateToken` on .NET 6+

On .NET 6 and later, `JsonWebTokenHandler.CreateToken` uses a span-based signing path that
pre-allocates a buffer sized by an internal `SupportedAlgorithms` registry. Since composite
algorithms are not registered in this internal registry, the buffer size defaults to zero,
which causes the signing operation to silently produce an unsigned token.

**Workaround:** Use `CompositeMLDsaSignatureProvider` directly to sign tokens, or construct
the JWT manually. Token **validation** via `ValidateTokenAsync` works correctly because it
uses the extensible `ICryptoProvider` path. This limitation will be resolved when composite
algorithms are graduated into the core library.

### X.509 Certificate Support

X.509 composite ML-DSA certificate support is not included in this initial release. It will
be added once composite certificate tooling matures and the LAMPS composite certificate
specification stabilises.

## Draft Revision History

| Package Version | IETF Draft | Notes |
|---|---|---|
| 0.1.x | `draft-ietf-jose-pq-composite-sigs-01` | Initial experimental release |

## Related Specifications

- [draft-ietf-jose-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/) — JOSE Composite Signatures
- [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) — X.509/CMS Composite Signatures
- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final) — Module-Lattice-Based Digital Signature Standard

## License

This project is licensed under the MIT License — see the [LICENSE](../../LICENSE.txt) file for details.
