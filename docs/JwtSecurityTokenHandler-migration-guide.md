# Migrating from `JwtSecurityTokenHandler` to `JsonWebTokenHandler`

`System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler` is **obsolete** as of Microsoft
IdentityModel 9.x. Use
`Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler` instead.

```
warning CS0618: 'JwtSecurityTokenHandler' is deprecated and will be removed in a future release.
Use 'Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler' instead.
```

`JwtSecurityTokenHandler` still works and still ships — the attribute produces a **warning**, not
an error. This guide tells you what to change and **what changes underneath you when you do**.

For the full API-by-API comparison, see
[JwtSecurityTokenHandler-JsonWebTokenHandler-parity.md](JwtSecurityTokenHandler-JsonWebTokenHandler-parity.md).

---

## Contents

1. [Do I have to do anything?](#1-do-i-have-to-do-anything)
2. [Packages and namespaces](#2-packages-and-namespaces)
3. [Validating tokens](#3-validating-tokens)
4. [Claim types — read this one](#4-claim-types--read-this-one)
5. [Creating tokens](#5-creating-tokens)
6. [Reading tokens without validating](#6-reading-tokens-without-validating)
7. [Customization: overrides → delegates](#7-customization-overrides--delegates)
8. [The actor (`act` / `actort`) claim](#8-the-actor-act--actort-claim)
9. [What has no replacement](#9-what-has-no-replacement)
10. [Suppressing the warning while you migrate](#10-suppressing-the-warning-while-you-migrate)
11. [Cheat sheet](#11-cheat-sheet)

---

## 1. Do I have to do anything?

**If you use ASP.NET Core `AddJwtBearer`, Microsoft.Identity.Web, or MISE:** probably not.
Those stacks already default to `JsonWebTokenHandler`. Your work is to check §4 (claim types) and
remove any leftover `JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear()` style
configuration.

**If you `new` up a handler yourself** to validate or issue tokens: follow §3 and §5.

**If you feed a `SecurityTokenHandler` into WS-Federation / WS-Trust / WCF plumbing:** see §9 —
this is the one scenario with no direct replacement.

## 2. Packages and namespaces

| | Old | New |
|---|---|---|
| Package | `System.IdentityModel.Tokens.Jwt` | `Microsoft.IdentityModel.JsonWebTokens` |
| Namespace | `System.IdentityModel.Tokens.Jwt` | `Microsoft.IdentityModel.JsonWebTokens` |
| Handler | `JwtSecurityTokenHandler` | `JsonWebTokenHandler` |
| Token | `JwtSecurityToken` | `JsonWebToken` |

`System.IdentityModel.Tokens.Jwt` already depends on `Microsoft.IdentityModel.JsonWebTokens`, so
the new types are available without adding a package reference. Once you have migrated fully you
can drop the `System.IdentityModel.Tokens.Jwt` reference.

`JwtRegisteredClaimNames`, `JwtHeaderParameterNames`, `JwtConstants` and `JsonClaimValueTypes`
exist in **both** namespaces with the same values, so a `using` swap is usually enough.

## 3. Validating tokens

`JsonWebTokenHandler` is async-first and returns a `TokenValidationResult` instead of throwing.

### Before

```csharp
var handler = new JwtSecurityTokenHandler();
try
{
    ClaimsPrincipal principal = handler.ValidateToken(
        token,
        validationParameters,
        out SecurityToken validatedToken);

    var jwt = (JwtSecurityToken)validatedToken;
    // ...
}
catch (SecurityTokenException ex)
{
    // ...
}
```

### After

```csharp
var handler = new JsonWebTokenHandler();

TokenValidationResult result = await handler.ValidateTokenAsync(token, validationParameters);

if (!result.IsValid)
{
    // result.Exception is the exception JwtSecurityTokenHandler would have thrown.
    // It is *not* thrown for you — inspect it, log it, and translate it yourself.
    throw result.Exception;
}

ClaimsPrincipal principal = new ClaimsPrincipal(result.ClaimsIdentity);
var jwt = (JsonWebToken)result.SecurityToken;
```

Key points:

- **Failures do not throw.** `ValidateTokenAsync` returns `IsValid == false` with
  `result.Exception` populated. Any `catch (SecurityTokenExpiredException)`-style code must move
  to an `if (!result.IsValid)` branch and type-test `result.Exception`.
- `result.ClaimsIdentity`, `result.SecurityToken`, `result.Issuer`, `result.Claims` and
  `result.TokenType` carry everything the old `out SecurityToken` + `ClaimsPrincipal` did.
- `result.TokenOnFailedValidation` gives you the parsed token even when validation failed
  (useful for logging `kid` / `iss` on failures).
- Overloads taking a `CancellationToken` and an already-parsed `SecurityToken` are available.
- `JsonWebTokenHandler.ValidateToken(string, TokenValidationParameters)` (the synchronous one) is
  itself already `[Obsolete]`. Do not migrate onto it.

Your `TokenValidationParameters` object carries over **unchanged**.

## 4. Claim types — read this one

This is the difference that most often changes behavior silently.

| | `JwtSecurityTokenHandler` | `JsonWebTokenHandler` |
|---|---|---|
| `MapInboundClaims` default | **`true`** | **`false`** |

With mapping **on** (old default), inbound JWT claim names are rewritten to the long WIF/WS-\*
URIs:

| JWT claim | Mapped `Claim.Type` (old default) | `Claim.Type` (new default) |
|---|---|---|
| `sub` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier` | `sub` |
| `email` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | `email` |
| `name` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` | `name` |
| `roles` | `http://schemas.microsoft.com/ws/2008/06/identity/claims/role` | `roles` |
| `unique_name` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` | `unique_name` |

Because `TokenValidationParameters.NameClaimType` and `RoleClaimType` default to the long
`ClaimTypes.Name` / `ClaimTypes.Role` URIs, switching handlers can make
`ClaimsPrincipal.Identity.Name` return `null` and `ClaimsPrincipal.IsInRole(...)` return `false`
even though the token is identical.

### Option A — keep the short, standard claim names (recommended)

Point `NameClaimType` / `RoleClaimType` at the JWT names and read claims by their JWT names:

```csharp
var validationParameters = new TokenValidationParameters
{
    // ...
    NameClaimType = "name",   // or JwtRegisteredClaimNames.Name / "preferred_username"
    RoleClaimType = "roles",
};

var handler = new JsonWebTokenHandler(); // MapInboundClaims is false by default
```

```csharp
// before: principal.FindFirst(ClaimTypes.NameIdentifier)
// after:
string sub = result.ClaimsIdentity.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
```

### Option B — preserve the old behavior exactly

```csharp
var handler = new JsonWebTokenHandler
{
    MapInboundClaims = true,   // uses the same DefaultInboundClaimTypeMap table
};
```

or, process-wide, before any handler is constructed:

```csharp
JsonWebTokenHandler.DefaultMapInboundClaims = true;
```

Note that `MapInboundClaims = true` only restores **inbound** mapping. Outbound mapping and the
inbound claim filter are gone (see §5 and below).

### `InboundClaimFilter` has no replacement

`JwtSecurityTokenHandler.InboundClaimFilter` silently dropped listed claim types while building
the `ClaimsIdentity`. `JsonWebTokenHandler` has no filter — every claim in the token reaches the
identity. If you populated the filter, drop the claims yourself after validation:

```csharp
var identity = result.ClaimsIdentity;
foreach (var claim in identity.FindAll(c => filtered.Contains(c.Type)).ToList())
    identity.RemoveClaim(claim);
```

### `JsonClaimTypeProperty` has no replacement

The `Claim.Properties[JwtSecurityTokenHandler.JsonClaimTypeProperty]` marker for JSON-typed
claims is not produced. Use `JsonWebToken.TryGetPayloadValue<T>("claim")` to read structured
claim values with their real CLR type instead of round-tripping through `Claim.Value` strings.

## 5. Creating tokens

`JsonWebTokenHandler.CreateToken` returns the **compact serialization directly** — there is no
intermediate token object to write out.

### Before

```csharp
var handler = new JwtSecurityTokenHandler();
var descriptor = new SecurityTokenDescriptor
{
    Issuer = "https://issuer.example",
    Audience = "api://resource",
    Subject = new ClaimsIdentity(new[] { new Claim("sub", "user-1") }),
    Expires = DateTime.UtcNow.AddHours(1),
    SigningCredentials = signingCredentials,
};

SecurityToken token = handler.CreateToken(descriptor);
string jwt = handler.WriteToken(token);
```

### After

```csharp
var handler = new JsonWebTokenHandler();
var descriptor = new SecurityTokenDescriptor
{
    Issuer = "https://issuer.example",
    Audience = "api://resource",
    Subject = new ClaimsIdentity(new[] { new Claim("sub", "user-1") }),
    Expires = DateTime.UtcNow.AddHours(1),
    SigningCredentials = signingCredentials,
};

string jwt = handler.CreateToken(descriptor);
```

`CreateEncodedJwt(...)`, `CreateJwtSecurityToken(...)` and the `(issuer, audience, subject,
notBefore, expires, issuedAt, signingCredentials, encryptingCredentials)` overloads all collapse
into `SecurityTokenDescriptor` + `CreateToken`. Encryption, compression (`zip`), and
`AdditionalHeaderClaims` / `AdditionalInnerHeaderClaims` all work the same way through the
descriptor.

If you already hold the payload as JSON, there is a faster path that skips `ClaimsIdentity`
entirely:

```csharp
string jwt = handler.CreateToken(payloadJson, signingCredentials);
```

### 5.1 Use JWT claim names, not `ClaimTypes.*` URIs

`JwtSecurityTokenHandler` ran outbound claims through `OutboundClaimTypeMap`, converting
`ClaimTypes.NameIdentifier` and friends into short JWT names. **`JsonWebTokenHandler` writes
`Claim.Type` verbatim.**

```csharp
// before: emitted {"nameid":"user-1"}
new Claim(ClaimTypes.NameIdentifier, "user-1")

// after: emits {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier":"user-1"}
//   -> change it to:
new Claim(JwtRegisteredClaimNames.Sub, "user-1")
```

Audit every `ClaimTypes.*` constant that reaches `SecurityTokenDescriptor.Subject` or
`SecurityTokenDescriptor.Claims`. If you need the old table, it is still public:
`JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap` — map your claims yourself before building
the identity.

### 5.2 Use JOSE algorithm names, not the XML-DSig URIs

`OutboundAlgorithmMap` translated `SecurityAlgorithms.RsaSha256Signature` →
`RS256`. `JsonWebTokenHandler` writes `SigningCredentials.Algorithm` as-is.

```csharp
// before (mapped to "RS256" on write)
new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature)

// after — use the JOSE name
new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
```

The same applies to `HmacSha*Signature` → `HS*` and `EcdsaSha*Signature` → `ES*`.

## 6. Reading tokens without validating

```csharp
// before
JwtSecurityToken jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
string sub  = jwt.Payload.Sub;
string kid  = jwt.Header.Kid;
string raw  = jwt.RawData;
object cust = jwt.Payload["custom"];

// after
JsonWebToken jwt = new JsonWebTokenHandler().ReadJsonWebToken(token);
string sub = jwt.Subject;
string kid = jwt.Kid;
string raw = jwt.EncodedToken;
jwt.TryGetPayloadValue("custom", out MyType cust);
```

`JsonWebToken` has no `Header` / `Payload` dictionaries — that is deliberate, and it is where most
of the allocation win comes from. Use the strongly typed accessors:

| `JwtSecurityToken` | `JsonWebToken` |
|---|---|
| `RawData` | `EncodedToken` |
| `RawHeader` / `RawPayload` / `RawSignature` | `EncodedHeader` / `EncodedPayload` / `EncodedSignature` |
| `Payload.Sub` | `Subject` |
| `Payload.Iss` / `Issuer` | `Issuer` |
| `Payload.Aud` / `Audiences` | `Audiences` |
| `Payload.Jti` / `Id` | `Id` |
| `Payload.IssuedAt` | `IssuedAt` |
| `ValidFrom` / `ValidTo` | `ValidFrom` / `ValidTo` |
| `Header.Alg` / `.Kid` / `.Typ` / `.Cty` / `.Enc` / `.Zip` | `Alg` / `Kid` / `Typ` / `Cty` / `Enc` / `Zip` |
| `Header[x]` | `TryGetHeaderValue<T>(x, out …)` / `GetHeaderValue<T>(x)` |
| `Payload[x]` | `TryGetPayloadValue<T>(x, out …)` / `GetPayloadValue<T>(x)` |
| `InnerToken` | `InnerToken` |
| `SigningKey` | `SigningKey` |
| `Claims` | `Claims` |

`ReadJsonWebToken(ReadOnlyMemory<char>)` avoids a string allocation when you already have the
token in a buffer.

## 7. Customization: overrides → delegates

If you derived from `JwtSecurityTokenHandler` to override a `Validate*` method, move the logic
into the matching `TokenValidationParameters` delegate — no subclass required.

| Override you had | Set this instead |
|---|---|
| `ValidateIssuer` | `TokenValidationParameters.IssuerValidator` (or `IssuerValidatorUsingConfiguration`) |
| `ValidateAudience` | `TokenValidationParameters.AudienceValidator` |
| `ValidateLifetime` | `TokenValidationParameters.LifetimeValidator` |
| `ValidateTokenReplay` | `TokenValidationParameters.TokenReplayValidator` (or `TokenReplayCache`) |
| `ValidateIssuerSecurityKey` | `TokenValidationParameters.IssuerSigningKeyValidator` (or `…UsingConfiguration`) |
| `ValidateSignature` | `TokenValidationParameters.SignatureValidator` (or `…UsingConfiguration`) |
| `ResolveIssuerSigningKey` | `TokenValidationParameters.IssuerSigningKeyResolver` (or `…UsingConfiguration`) |
| `ResolveTokenDecryptionKey` | `TokenValidationParameters.TokenDecryptionKeyResolver`, or override `JsonWebTokenHandler.ResolveTokenDecryptionKey(string, JsonWebToken, TokenValidationParameters)` |
| `CreateClaimsIdentity(JwtSecurityToken, string, TVP)` | override `JsonWebTokenHandler.CreateClaimsIdentity(JsonWebToken, TokenValidationParameters, string issuer)` |
| `DecryptToken(JwtSecurityToken, TVP)` | `JsonWebTokenHandler.DecryptToken(JsonWebToken, TokenValidationParameters)` |

Example:

```csharp
// before
public sealed class MyHandler : JwtSecurityTokenHandler
{
    protected override string ValidateIssuer(
        string issuer, JwtSecurityToken jwt, TokenValidationParameters tvp) =>
        issuer.StartsWith("https://contoso.")
            ? issuer
            : throw new SecurityTokenInvalidIssuerException(issuer);
}

// after — no subclass
validationParameters.IssuerValidator = (issuer, token, tvp) =>
    issuer.StartsWith("https://contoso.")
        ? issuer
        : throw new SecurityTokenInvalidIssuerException(issuer);
```

## 8. The actor (`act` / `actort`) claim

- **Reading:** `JsonWebTokenHandler` reads **both**. RFC 8693 `act` (a JSON object) wins when
  present; the legacy `actort` (an unsigned nested JWT string) is still expanded into
  `ClaimsIdentity.Actor`. Tokens issued by `JwtSecurityTokenHandler` keep working.
- **Writing:** `JsonWebTokenHandler` writes **only `act`**, never `actort`. If a downstream
  relying party only understands `actort`, it must be updated (or keep issuing with the old
  handler until it is).
- Nesting depth is bounded by the process-wide static
  `JsonWebTokenHandler.MaxActorChainLength` (default `1`); deeper actors degrade to a JSON-text
  string rather than being dropped.
- `act`-derived actor identities are built **without** inbound claim mapping and with default
  name/role claim types — read them by their raw claim names (`sub`, …) rather than
  `Actor.Name` / `Actor.IsInRole`.

Details: [`src/Microsoft.IdentityModel.JsonWebTokens/ActorClaim.md`](../src/Microsoft.IdentityModel.JsonWebTokens/ActorClaim.md).

## 9. What has no replacement

`JsonWebTokenHandler` derives from `TokenHandler`, not `SecurityTokenHandler`, so the XML
serialization surface is not available:

- `WriteToken(XmlWriter, SecurityToken)`
- `ReadToken(XmlReader, TokenValidationParameters)`
- `WriteToken(SecurityToken) → string`
- `CanWriteToken`
- registration in a `SecurityTokenHandlerCollection`

This matters only for WS-Federation / WS-Trust / WCF hosts that embed a JWT inside an XML
security token. If that is you:

1. Keep the `System.IdentityModel.Tokens.Jwt` reference for the XML plumbing.
2. Do the JWT work with `JsonWebTokenHandler`, and bridge with the (non-obsolete)
   `JwtSecurityTokenConverter`:

```csharp
JsonWebToken jsonWebToken = new JsonWebTokenHandler().ReadJsonWebToken(token);
JwtSecurityToken jwtSecurityToken = JwtSecurityTokenConverter.Convert(jsonWebToken);
```

Also note there is no "serialize an existing `SecurityToken`" API: build tokens from a
`SecurityTokenDescriptor` with `CreateToken`, which returns the string directly.

## 10. Suppressing the warning while you migrate

Per call site:

```csharp
#pragma warning disable CS0618 // Type or member is obsolete
var handler = new JwtSecurityTokenHandler();
#pragma warning restore CS0618
```

Per project (use sparingly — it hides *all* obsolete-API warnings):

```xml
<PropertyGroup>
  <NoWarn>$(NoWarn);CS0618</NoWarn>
</PropertyGroup>
```

## 11. Cheat sheet

| `JwtSecurityTokenHandler` | `JsonWebTokenHandler` |
|---|---|
| `ValidateToken(t, tvp, out SecurityToken)` → `ClaimsPrincipal` (throws) | `await ValidateTokenAsync(t, tvp)` → `TokenValidationResult` (does not throw) |
| `ValidateTokenAsync(t, tvp)` | `ValidateTokenAsync(t, tvp)` (+ `CancellationToken` / `SecurityToken` overloads) |
| `CreateToken(descriptor)` + `WriteToken(token)` | `CreateToken(descriptor)` → `string` |
| `CreateEncodedJwt(...)` / `CreateJwtSecurityToken(...)` | `CreateToken(SecurityTokenDescriptor)` |
| `ReadJwtToken(t)` → `JwtSecurityToken` | `ReadJsonWebToken(t)` → `JsonWebToken` |
| `ReadToken(t)` → `SecurityToken` | `ReadToken(t)` → `SecurityToken` |
| `CanReadToken(t)` | `CanReadToken(t)` |
| `DecryptToken(jwt, tvp)` | `DecryptToken(jwt, tvp)`, `DecryptTokenWithConfigurationAsync(...)` |
| `MapInboundClaims` (default `true`) | `MapInboundClaims` (default **`false`**) |
| `InboundClaimTypeMap`, `ShortClaimTypeProperty` | same |
| `OutboundClaimTypeMap`, `OutboundAlgorithmMap`, `InboundClaimFilter`, `JsonClaimTypeProperty` | **removed** — see §4 / §5 |
| `CreateActorValue(...)` / `actort` | `act` (RFC 8693), `MaxActorChainLength` |
| `virtual Validate*` / `Resolve*` overrides | `TokenValidationParameters` delegates — see §7 |
| `WriteToken(XmlWriter, …)`, `ReadToken(XmlReader, …)`, `CanWriteToken` | **no replacement** — see §9 |
