# `JwtSecurityTokenHandler` → `JsonWebTokenHandler` feature-parity audit

**Status:** `JwtSecurityTokenHandler` is marked `[Obsolete]` as of IdentityModel 9.x.
`Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler` is the replacement.

This document is the *engineering* audit: what exists on each handler, where parity is complete,
where behavior differs, and where there is a genuine gap. Customer-facing "how do I change my
code" instructions live in [JwtSecurityTokenHandler-migration-guide.md](JwtSecurityTokenHandler-migration-guide.md).

| | `JwtSecurityTokenHandler` | `JsonWebTokenHandler` |
|---|---|---|
| Package | `System.IdentityModel.Tokens.Jwt` | `Microsoft.IdentityModel.JsonWebTokens` |
| Base type | `SecurityTokenHandler` (→ `TokenHandler`) | `TokenHandler` |
| Token type | `JwtSecurityToken` | `JsonWebToken` |
| Namespace | `System.IdentityModel.Tokens.Jwt` | `Microsoft.IdentityModel.JsonWebTokens` |

> **⚠️ Follow-up required in 9.x — separate PR**
>
> `Microsoft.IdentityModel.Protocols.OpenIdConnect` still exposes two **shipped public API**
> members typed against the legacy token type:
>
> - `OpenIdConnectProtocolValidationContext.ValidatedIdToken` → `JwtSecurityToken`
> - `IdTokenValidator.Invoke(JwtSecurityToken idToken, ...)`
>
> These force `JwtSecurityToken` on callers who never used the obsolete handler, and they block
> `OpenIdConnectProtocolValidator.ValidateUserInfoResponse` from moving to `JsonWebTokenHandler`
> (currently `#pragma`-suppressed).
>
> **Retyping them is a breaking change and should land in 9.x while the window is open — but as
> its own reviewed PR, not folded into this deprecation.** Rationale and options: [§8.1](#81-why-the-openidconnect-public-api-was-left-alone-in-this-change).

---

## 1. Summary

Parity is **complete for token creation and token validation semantics**. The differences fall
into four buckets:

1. **Different shape, same capability** — sync/`ClaimsPrincipal` APIs replaced by
   `ValidateTokenAsync` / `TokenValidationResult`; `virtual Validate*` overrides replaced by
   `TokenValidationParameters` delegates.
2. **Different defaults** — inbound claim-type mapping is **on** by default on
   `JwtSecurityTokenHandler` and **off** by default on `JsonWebTokenHandler`. This is the single
   highest-impact difference for customers.
3. **Deliberately dropped** — outbound claim-type mapping, outbound algorithm mapping, the
   inbound claim filter, and `actort` **writing**. These were legacy WIF-compat behaviors.
4. **Real gaps** — the `SecurityTokenHandler` XML surface (`WriteToken(XmlWriter, …)`,
   `ReadToken(XmlReader, …)`, `CanWriteToken`, `TokenType`) is not available, because
   `JsonWebTokenHandler` does not derive from `SecurityTokenHandler`. This only affects
   WS-Federation / WS-Trust style hosts that embed a JWT inside XML.

Nothing in bucket 4 blocks the mainstream OIDC / OAuth2 bearer-token scenarios.

---

## 2. Reading tokens

| Capability | `JwtSecurityTokenHandler` | `JsonWebTokenHandler` | Parity |
|---|---|---|---|
| `CanReadToken(string)` | `override` | `virtual` | ✅ |
| Read to concrete type | `ReadJwtToken(string) → JwtSecurityToken` | `ReadJsonWebToken(string) → JsonWebToken` | ✅ |
| Read from `ReadOnlyMemory<char>` | ❌ | `ReadJsonWebToken(ReadOnlyMemory<char>)` | ➕ only on new handler |
| `ReadToken(string) → SecurityToken` | ✅ | ✅ | ✅ |
| `ReadToken(XmlReader, TokenValidationParameters)` | ✅ | ❌ | ⚠️ gap (XML hosts only) |
| `MaximumTokenSizeInBytes` | ✅ (from `TokenHandler`) | ✅ (from `TokenHandler`) | ✅ |
| Header/payload access | `JwtSecurityToken.Header` / `.Payload` (`IDictionary`-derived) | `JsonWebToken.TryGetHeaderValue<T>` / `TryGetPayloadValue<T>` / `GetPayloadValue<T>` | ⚠️ different shape |
| Replace header without re-parsing payload | ❌ | `ReplaceTokenHeader(JsonWebToken, string)` | ➕ |

`JsonWebToken` parses lazily over the encoded token and does not materialize a
`Dictionary<string, object>` for the header/payload — that is the primary source of its
allocation win, and the reason the `Header`/`Payload` dictionaries have no direct equivalent.

## 3. Creating tokens

| Capability | `JwtSecurityTokenHandler` | `JsonWebTokenHandler` | Parity |
|---|---|---|---|
| Create from `SecurityTokenDescriptor` | `CreateToken(…) → SecurityToken`, `CreateJwtSecurityToken(…) → JwtSecurityToken`, `CreateEncodedJwt(…) → string` | `CreateToken(SecurityTokenDescriptor) → string` | ✅ (returns the compact serialization directly) |
| Create from discrete args (issuer/audience/subject/…) | `CreateJwtSecurityToken(issuer, audience, subject, notBefore, expires, issuedAt, signingCredentials, encryptingCredentials, claimCollection)` | ❌ — use `SecurityTokenDescriptor` | ⚠️ different shape |
| Create from a raw JSON payload string | ❌ | `CreateToken(string payload, …)` (11 overloads) | ➕ |
| Signing | ✅ | ✅ | ✅ |
| Encryption (JWE) | ✅ | ✅ | ✅ |
| Compression (`zip`) | ✅ | ✅ | ✅ |
| Additional header claims (outer + inner) | ✅ | ✅ | ✅ |
| Encrypt an already-signed JWS | ❌ (internal only) | `EncryptToken(innerJwt, …)` (4 overloads) | ➕ |
| `SetDefaultTimesOnTokenCreation` / `TokenLifetimeInMinutes` | ✅ | ✅ | ✅ |
| Outbound claim-type mapping (`OutboundClaimTypeMap`) | ✅ | ❌ **by design** | ⚠️ behavior change |
| Outbound algorithm mapping (`OutboundAlgorithmMap`) | ✅ | ❌ **by design** | ⚠️ behavior change |
| `CreateActorValue(ClaimsIdentity)` → `actort` | ✅ | ❌ — writes `act` instead | ⚠️ behavior change |

### 3.1 Outbound claim-type mapping (removed)

`JwtSecurityTokenHandler.CreateToken` runs every `Claim.Type` through `OutboundClaimTypeMap`,
which shortens the long WIF/WS-* URIs (for example
`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier` → `nameid`) before
writing. `JsonWebTokenHandler` writes `Claim.Type` **verbatim**.

**Impact:** if you build a `ClaimsIdentity` out of `System.Security.Claims.ClaimTypes.*`
constants and hand it to `SecurityTokenDescriptor.Subject`, the emitted JWT will contain the long
URIs as payload member names instead of the short registered names. Producers must switch to
`JwtRegisteredClaimNames.*` (or pre-map).

### 3.2 Outbound algorithm mapping (removed)

`OutboundAlgorithmMap` translated the XML-DSig/XML-Enc algorithm URIs
(`SecurityAlgorithms.RsaSha256Signature`, `…HmacSha256Signature`, `…EcdsaSha256Signature`, …)
into the JOSE `alg` short names (`RS256`, `HS256`, `ES256`, …). `JsonWebTokenHandler` writes the
algorithm from `SigningCredentials.Algorithm` as-is.

**Impact:** `SigningCredentials` constructed with a `*Signature` URI constant will produce a
non-standard `alg` header. Producers must use the JOSE names (`SecurityAlgorithms.RsaSha256`
etc.).

### 3.3 Actor: `actort` vs `act`

`JwtSecurityTokenHandler` serializes `ClaimsIdentity.Actor` as the legacy **`actort`** claim — an
unsigned nested JWT carried as a string. `JsonWebTokenHandler` writes the RFC 8693 **`act`**
claim (a JSON object) and never writes `actort`.

On the **read** side `JsonWebTokenHandler` accepts both: `act` wins whenever present, and
`actort` is still expanded into `ClaimsIdentity.Actor` for back-compat. So a
`JwtSecurityTokenHandler`-produced token is still read correctly; only newly *issued* tokens
change shape. Depth is bounded by the process-wide
`JsonWebTokenHandler.MaxActorChainLength` (default `1`).

Full design notes: [`src/Microsoft.IdentityModel.JsonWebTokens/ActorClaim.md`](../src/Microsoft.IdentityModel.JsonWebTokens/ActorClaim.md).

## 4. Validating tokens

| Capability | `JwtSecurityTokenHandler` | `JsonWebTokenHandler` | Parity |
|---|---|---|---|
| Async validation | `ValidateTokenAsync(string, TVP) → TokenValidationResult` | `ValidateTokenAsync(string, TVP)`, `ValidateTokenAsync(SecurityToken, TVP)`, plus `CancellationToken` overloads | ✅ (new handler is richer) |
| Sync validation | `ValidateToken(string, TVP, out SecurityToken) → ClaimsPrincipal` | `ValidateToken(string, TVP) → TokenValidationResult` — **already `[Obsolete]`** | ⚠️ prefer async |
| Signature validation (JWS) | ✅ | ✅ | ✅ |
| Decryption (JWE), incl. nested | ✅ | ✅ | ✅ |
| `ValidateSignatureLast` | ✅ | ✅ | ✅ |
| Issuer / audience / lifetime / replay / algorithm / type / signing-key validation | ✅ | ✅ (shared `Microsoft.IdentityModel.Tokens.Validators`) | ✅ |
| `BaseConfiguration` / `ConfigurationManager` (last-known-good, `*UsingConfiguration` delegates) | ✅ | ✅ | ✅ |
| `DecryptToken(token, TVP)` | ✅ | ✅ | ✅ |
| `DecryptTokenWithConfigurationAsync` | ❌ | ✅ | ➕ |
| Telemetry (`ITelemetryClient`) | ✅ | ✅ | ✅ |

**Both handlers execute the same validators.** `JsonWebTokenHandler` calls the shared
`Microsoft.IdentityModel.Tokens.Validators` helpers, which is exactly what
`JwtSecurityTokenHandler` does. There is no validation rule that one enforces and the other does
not.

### 4.1 Extensibility model

This is the largest *structural* difference. `JwtSecurityTokenHandler` exposes overridable
methods; `JsonWebTokenHandler` expects you to plug delegates into `TokenValidationParameters`.

| `JwtSecurityTokenHandler` override | `JsonWebTokenHandler` replacement |
|---|---|
| `ValidateIssuer(string, JwtSecurityToken, TVP)` | `TokenValidationParameters.IssuerValidator` / `IssuerValidatorUsingConfiguration` |
| `ValidateAudience(IEnumerable<string>, JwtSecurityToken, TVP)` | `TokenValidationParameters.AudienceValidator` |
| `ValidateLifetime(DateTime?, DateTime?, JwtSecurityToken, TVP)` | `TokenValidationParameters.LifetimeValidator` |
| `ValidateTokenReplay(DateTime?, string, TVP)` | `TokenValidationParameters.TokenReplayValidator` / `TokenReplayCache` |
| `ValidateIssuerSecurityKey(SecurityKey, JwtSecurityToken, TVP)` | `TokenValidationParameters.IssuerSigningKeyValidator` / `IssuerSigningKeyValidatorUsingConfiguration` |
| `ValidateSignature(string, TVP)` | `TokenValidationParameters.SignatureValidator` / `SignatureValidatorUsingConfiguration` |
| `ResolveIssuerSigningKey(string, JwtSecurityToken, TVP)` | `TokenValidationParameters.IssuerSigningKeyResolver` / `IssuerSigningKeyResolverUsingConfiguration` |
| `ResolveTokenDecryptionKey(string, JwtSecurityToken, TVP)` | `protected virtual ResolveTokenDecryptionKey(string, JsonWebToken, TVP)` **or** `TokenValidationParameters.TokenDecryptionKeyResolver` |
| `CreateClaimsIdentity(JwtSecurityToken, string, TVP)` | `protected virtual CreateClaimsIdentity(JsonWebToken, TVP[, string issuer])` |
| `ValidateTokenPayload(JwtSecurityToken, TVP)` | no direct equivalent — the individual validator delegates above |
| `DecryptToken(JwtSecurityToken, TVP)` | `DecryptToken(JsonWebToken, TVP)` |

The delegate model is what the rest of the stack (ASP.NET Core `JwtBearer`,
Microsoft.Identity.Web, MISE) already configures, so most callers own nothing here.

## 5. Claim mapping and `ClaimsIdentity` construction

| Capability | `JwtSecurityTokenHandler` | `JsonWebTokenHandler` | Parity |
|---|---|---|---|
| `MapInboundClaims` | ✅ — **default `true`** | ✅ — **default `false`** | ⚠️ **default changed** |
| `DefaultMapInboundClaims` (static) | `true` | `false` | ⚠️ |
| `InboundClaimTypeMap` / `DefaultInboundClaimTypeMap` | ✅ | ✅ (same `ClaimTypeMapping` table) | ✅ |
| `ShortClaimTypeProperty` | ✅ | ✅ | ✅ |
| `OutboundClaimTypeMap` / `DefaultOutboundClaimTypeMap` | ✅ | ❌ | ⚠️ removed (see §3.1) |
| `InboundClaimFilter` / `DefaultInboundClaimFilter` | ✅ | ❌ | ⚠️ removed |
| `JsonClaimTypeProperty` | ✅ | ❌ | ⚠️ removed |
| `ClaimsIdentity` type produced | via `TokenValidationParameters.CreateClaimsIdentity` | via `TokenValidationParameters.CreateClaimsIdentity` (`CaseSensitiveClaimsIdentity` by default) | ✅ |
| Nested-actor identity | from `actort` only | from `act` (bare identity) or `actort` (mapped identity) | ⚠️ see `ActorClaim.md` §4 |

**The `MapInboundClaims` default flip is the change most likely to break customer code.** With
`JwtSecurityTokenHandler`, `sub` surfaces as
`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier` and `roles` surfaces as
`http://schemas.microsoft.com/ws/2008/06/identity/claims/role`. With `JsonWebTokenHandler`, they
surface as `sub` and `roles`. Anything reading claims by the long URI, or relying on
`ClaimsPrincipal.IsInRole` / `.Identity.Name` picking up the default WIF claim types, changes
behavior. See the migration guide, §"Claim types".

`InboundClaimFilter` removal means claims that `JwtSecurityTokenHandler` silently dropped now
appear on the resulting `ClaimsIdentity`. The shipped default filter is empty, so this only
affects callers who populated it.

## 6. `SecurityTokenHandler` / XML surface — the real gap

`JsonWebTokenHandler` derives from `TokenHandler`, not `SecurityTokenHandler`. These members have
no replacement:

| Member | Notes |
|---|---|
| `WriteToken(XmlWriter, SecurityToken)` | WS-Federation / WS-Trust RSTR embedding |
| `ReadToken(XmlReader, TokenValidationParameters)` | ditto |
| `CanWriteToken` | always `true` for the JWT handler |
| `TokenType` | `JsonWebTokenHandler.TokenType` exists as a plain (non-`override`) property |
| `WriteToken(SecurityToken) → string` | replaced by `CreateToken(SecurityTokenDescriptor) → string`; there is no "serialize an existing `SecurityToken`" API |
| Registration in a `SecurityTokenHandlerCollection` | `JsonWebTokenHandler` cannot be added to a `SecurityTokenHandlerCollection` |

**Who is affected:** hosts that hand a `SecurityTokenHandler` to WCF / WS-Federation / WS-Trust
plumbing, or that call `WriteToken(SecurityToken)` on a `JwtSecurityToken` they built by hand.
Standard HTTP bearer-token validation is unaffected.

**Mitigation:** keep `System.IdentityModel.Tokens.Jwt` referenced for the XML plumbing only, and
use `JwtSecurityTokenConverter.Convert(JsonWebToken)` to bridge — that type is **not** obsolete
and is retained as a migration aid.

## 7. In-repo consumers

| Consumer | Status |
|---|---|
| `Microsoft.IdentityModel.Protocols.OpenIdConnect` — `OpenIdConnectProtocolValidator.ValidateUserInfoResponse` | Still uses `JwtSecurityTokenHandler` behind a local `#pragma warning disable CS0618`. This cannot be migrated in isolation: the package's **shipped public API** binds it to the legacy type — `OpenIdConnectProtocolValidationContext.ValidatedIdToken` is typed `JwtSecurityToken`, and `IdTokenValidator.Invoke` takes a `JwtSecurityToken` parameter. `ValidateUserInfoResponse` compares the `sub` it reads against `ValidatedIdToken.Payload.Sub`, so switching the handler requires a breaking public API change to `Microsoft.IdentityModel.Protocols.OpenIdConnect`. Tracked separately. |
| `Microsoft.IdentityModel.Protocols.SignedHttpRequest` | Uses `JsonWebTokenHandler`. ✅ |
| `Microsoft.IdentityModel.Tokens.Saml` / `.Xml` / `.WsFederation` | Do not use `JwtSecurityTokenHandler`. ✅ |
| Test projects and `Microsoft.IdentityModel.Benchmarks` | Suppress `CS0618` at the project level; they intentionally keep exercising the obsolete handler so its behavior stays pinned while it ships. |

## 8. Recommendation

- Ship the `[Obsolete]` warning (not an error) in 9.x.
- Keep `JwtSecurityToken`, `JwtPayload`, `JwtHeader`, `JwtSecurityTokenConverter`,
  `JwtRegisteredClaimNames` and `JwtHeaderParameterNames` **non-obsolete** — they are needed both
  by callers stuck on the XML surface and by the converter bridge.
- Do **not** close the gaps in §6 on `JsonWebTokenHandler`; the XML surface is intentionally out
  of scope for the new handler.
- **Retype the `Microsoft.IdentityModel.Protocols.OpenIdConnect` public API off `JwtSecurityToken`
  in 9.x, as a separate PR** (see §8.1), and migrate `OpenIdConnectProtocolValidator` to
  `JsonWebTokenHandler` as part of it.

### 8.1 Why the OpenIdConnect public API was left alone in this change

`Microsoft.IdentityModel.Protocols.OpenIdConnect` exposes two shipped members typed against the
legacy token type (`PublicAPI.Shipped.txt` lines 421 and 490):

```
OpenIdConnectProtocolValidationContext.ValidatedIdToken.get -> System.IdentityModel.Tokens.Jwt.JwtSecurityToken
IdTokenValidator.Invoke(System.IdentityModel.Tokens.Jwt.JwtSecurityToken idToken, ...) -> void
```

These were deliberately **not** changed as part of the obsoletion, because:

1. **`JwtSecurityToken` is not obsolete — only `JwtSecurityTokenHandler` is.** These members
   therefore produce no `CS0618` warning for any caller. There is no compile-time forcing
   function, so leaving them costs customers nothing today.
2. **Retyping is a breaking change to a second package** and needs a design decision that is out
   of scope for a deprecation pass: widen to `SecurityToken`, move to `JsonWebToken`, or add
   parallel members and obsolete the old ones. Each ripples into `IdTokenValidator`, the
   protocol-validation logic, and their tests.
3. Per `agents.md`, a change of this magnitude warrants a design proposal rather than being
   folded into an unrelated PR.

If 9.x is the intended breaking-change window, this is the natural time to do it — but as its own
tracked, reviewed change. Until then the `#pragma` in `ValidateUserInfoResponse` is the correct
holding position.
