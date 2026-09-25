# Migrating to Microsoft.IdentityModel 9.0

This guide covers upgrading from 8.x to 9.0 (`Microsoft.IdentityModel.*` and
`System.IdentityModel.Tokens.Jwt`).

Some applications will be able to upgrade with no code changes. The changes that do require action are below in
priority order, each with before/after code and a way to restore the previous behavior where one
exists.

---

## At a glance

| If your code... | Read |
|---|---|
| Calls `JsonWebTokenHandler` / `JwtSecurityTokenHandler` with default settings | [1](#1-upgrade-the-packages), [2](#2-keep-package-versions-aligned), [6](#6-check-your-logging-and-alerting) |
| Uses **Signed HTTP Request** (SHR) or PoP tokens | [3](#3-shr-path-comparison-is-now-case-sensitive) - **action likely required** |
| Reads the `"groups"` claim | [4](#4-the-groups-claim-is-now-renamed-by-inbound-claim-mapping) - **action likely required** |
| Uses delegation / impersonation / `ClaimsIdentity.Actor` | [5](#5-actor-act-claim-support) |
| Makes a `TokenHandler` subclass, or sets `SignedHttpRequestValidationParameters.TokenHandler` | [7](#7-if-your-code-subclasses-tokenhandler) - **action required** |
| Uses the `Microsoft.IdentityModel.Tokens.Experimental` validation APIs | [8](#8-validation-extensibility-apis-changed) - **action required** |
| Calls `JsonWebKeyConverter.ConvertFromX509SecurityKey` with named arguments | [9](#9-api-rename) |

---

## 1. Upgrade the packages

Update **all** `Microsoft.IdentityModel.*` and `System.IdentityModel.Tokens.Jwt` references to
`9.0.0` together.

```xml
<PackageReference Include="Microsoft.IdentityModel.JsonWebTokens" Version="9.0.0" />
<PackageReference Include="Microsoft.IdentityModel.Protocols.OpenIdConnect" Version="9.0.0" />
<PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="9.0.0" />
```

Target frameworks are unchanged. Supported targets remain `net10.0`, `net9.0`, `net8.0`, `net6.0`,
`net462`, `net472`, `netstandard2.0`.

---

## 2. Keep package versions aligned

9.0 adds a build-time check that warns when your project resolves **different versions** of
IdentityModel packages. Mixing versions (for example `Microsoft.IdentityModel.Tokens` 9.0.0 with
`System.IdentityModel.Tokens.Jwt` 8.2.0) is a frequent cause of `MissingMethodException` and
`TypeLoadException` at runtime, so this check catches the problem early.

The check ships in `buildTransitive`, so it applies even when your project references
IdentityModel only indirectly.

**If you see a new `IDX00001` warning**, the fix is almost always to add explicit `PackageReference`
entries at 9.0.0 for every IdentityModel package in your graph - including ones pulled in
transitively by ASP.NET Core, Microsoft.Identity.Web, or the Azure SDKs.


>If you'd like to disable this feature you can add the below in relevant csproj files.
>
> ```xml
> <PropertyGroup>
>   <DisableIdentityModelVersionMismatchCheck>true</DisableIdentityModelVersionMismatchCheck>
> </PropertyGroup>
> ```
>
> However, our recommendation is to prefer fixing the mismatch. The warning usually indicates a valid latent issue.

---

## 3. SHR path comparison is now case-sensitive

**Applies to:** applications validating Signed HTTP Requests / PoP tokens.

The `p` (path) claim is now compared **case-sensitively** by default, matching
[RFC 3986 section 3.3](https://www.rfc-editor.org/rfc/rfc3986#section-3.3).

**The AppContext switch no longer exists.**
`Switch.Microsoft.IdentityModel.SignedHttpRequest.UseCaseSensitivePClaimComparison` has been removed in 9.0. If your project uses this switch it will
now be **silently ignored** and requests may start failing validation if the casing differs.

**Is your application affected?** Only if your clients and server can have different path casing - a
client that lowercases URLs, a proxy that normalizes casing, or route templates matched
case-insensitively by your web framework.

**What to do:** make the client and server agree on casing. The `p` claim the client signs must
match the path the server validates character for character - usually by stopping a client or proxy
from normalizing URL casing, rather than by relaxing validation.

---

## 4. The `groups` claim is now renamed by inbound claim mapping

**Applies to:** applications using the obsoleted `JwtSecurityTokenHandler`, or another handler with inbound claim
mapping enabled, that reads the `"groups"` claim.

The inbound claim type map now includes:

```
"groups"  ->  "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
```

This makes `groups` consistent with the other Microsoft-standard claim mappings. But after
upgrading, this code **stops finding anything**:

```csharp
// Returns no claims in 9.0 when inbound claim mapping is enabled
var groups = principal.FindAll("groups");

// Silently evaluates to false
if (principal.HasClaim("groups", "admins")) { /* ... */ }
```
**This change does not throw.** If your code uses group membership for authorization, an affected
check evaluates to `false` - access is denied where it previously was granted, with no exception.

### Option A - read the mapped claim type

```csharp
const string GroupsClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups";
var groups = principal.FindAll(GroupsClaimType);
```

### Option B - turn off inbound claim mapping (recommended for new code)

This yields the raw, unmodified claims exactly as they appear in the token:

```csharp
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;
// or per handler:
var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
```

`JsonWebTokenHandler` already defaults to no inbound mapping.

---

## 5. Actor (`act`) claim support

**Applies to:** delegation and impersonation scenarios; anyone who sets
`SecurityTokenDescriptor.Subject.Actor`, reads `ClaimsIdentity.Actor`, or uses the legacy `actort`
claim.

9.0 implements the [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693#section-4.1) `act` claim in
`JsonWebTokenHandler`.

### Creating tokens

If your code sets `SecurityTokenDescriptor.Subject.Actor`, the generated token now contains an `act`
claim. Previously the actor was **not** written at all.

```csharp
var descriptor = new SecurityTokenDescriptor
{
    Subject = new ClaimsIdentity(new[] { new Claim("sub", "alice") })
    {
        Actor = new ClaimsIdentity(new[] { new Claim("sub", "service-a") })
    },
    // ...
};

// 9.0 payload now includes:  "act": { "sub": "service-a" }
var jwt = new JsonWebTokenHandler().CreateToken(descriptor);
```

**What to check:** tests concerning token payloads may need updating; and relying parties that reject unknown claims should be verified.

### Validating tokens

`ClaimsIdentity.Actor` is now populated from `act` when present, falling back to `actort` otherwise.

| Scenario | 8.x | 9.0 |
|---|---|---|
| Token has `act` | ignored | expands into `identity.Actor` |
| Token has `actort` | expands into `identity.Actor` | unchanged |
| Token has **both** | threw `InvalidOperationException` (`IDX14112`) | `act` wins; **no exception** |
| Inbound claim mapping disabled | `Actor` not populated | `Actor` **is** populated |
| Malformed `act` | n/a | logs a warning; `Actor` is `null`; **validation still succeeds** |

---

## 6. Check your logging and alerting

Two logging changes can affect dashboards and alerts. None of them produces an error.

### Successful-validation messages moved to Verbose

`IDX10239` ("lifetime validated") and `IDX10234` ("audience validated") are now logged at **Verbose**
instead of **Informational**. This substantially reduces log volume for applications that do not need
a log line per successful validation.

**If your dashboards, alerts, or audit trails are keyed on these messages**, either lower your log
level to Verbose, or restore the previous behavior:

```csharp
AppContext.SetSwitch(
    "Switch.Microsoft.IdentityModel.SuccessValidationLogsAsInformation",
    true);
```

Or via your project file:

```xml
<ItemGroup>
  <RuntimeHostConfigurationOption
      Include="Switch.Microsoft.IdentityModel.SuccessValidationLogsAsInformation"
      Value="true" />
</ItemGroup>
```

> **Set the switch during startup, before the first token validation.** The value is read once and
> cached for the process lifetime, so changing it later has no effect.

### `LogValidationExceptions = false` is now comprehensive

In 8.x, `TokenValidationParameters.LogValidationExceptions = false` suppressed *some* but not all
validation-failure logging. In 9.0 it suppresses all of it.

If your code sets this flag but you rely on those log entries for diagnostics, set it back to `true`
(the default).

---

## 7. If your code subclasses `TokenHandler`

**Applies to:** anyone deriving from `TokenHandler` (directly or via `JsonWebTokenHandler`), or
assigning `SignedHttpRequestValidationParameters.TokenHandler`.

9.0 adds `CancellationToken` overloads:

```csharp
public virtual Task<TokenValidationResult> ValidateTokenAsync(
    string token, TokenValidationParameters validationParameters, CancellationToken cancellationToken);

public virtual Task<TokenValidationResult> ValidateTokenAsync(
    SecurityToken token, TokenValidationParameters validationParameters, CancellationToken cancellationToken);
```

The two-argument overloads now **forward** to these, and the base three-argument implementations
**throw `NotImplementedException` (`IDX10267`)**.

> **If your handler overrides only the two-argument overload, callers that use the three-argument
> overload get a `NotImplementedException`.** Override the new overload:

```diff
  public class MyTokenHandler : TokenHandler
  {
-     public override Task<TokenValidationResult> ValidateTokenAsync(
-         string token, TokenValidationParameters validationParameters)
+     public override Task<TokenValidationResult> ValidateTokenAsync(
+         string token,
+         TokenValidationParameters validationParameters,
+         CancellationToken cancellationToken)
      {
+         cancellationToken.ThrowIfCancellationRequested();
          // your existing logic
      }
  }
```

### Signed HTTP Request users

`SignedHttpRequestHandler` now calls the three-argument overload. The default handler
(`JsonWebTokenHandler`) implements it, so **code that leaves `TokenHandler` at its default needs no
change**.

If your code assigns a different handler:

```csharp
// Throws NotImplementedException (IDX10267) at validation time in 9.0
validationParameters.TokenHandler = new JwtSecurityTokenHandler();
```

`JwtSecurityTokenHandler`, `SamlSecurityTokenHandler`, and `Saml2SecurityTokenHandler` do not
override the three-argument overload. Use `JsonWebTokenHandler` (the default and the recommended
handler for JWTs), or a custom handler that overrides the three-argument form.

---

## 8. Validation extensibility APIs changed

**Applies to:** users of the `Microsoft.IdentityModel.Tokens.Experimental` validation APIs.

### 8a. Delegates are now interfaces

Validation extensibility moved from delegates to interfaces.

**Before (8.x)**

```csharp
var validationParameters = new ValidationParameters
{
    AudienceValidator = (IList<string> tokenAudiences, SecurityToken? securityToken,
                         ValidationParameters vp, CallContext callContext) =>
    {
        // your logic, returning ValidationResult<string, ValidationError>
    }
};
```

**After (9.0)**

```csharp
internal sealed class MyAudienceValidator : IAudienceValidator
{
    public ValidationResult<string, ValidationError> ValidateAudience(
        IList<string> tokenAudiences,
        SecurityToken? securityToken,
        ValidationParameters validationParameters,
        CallContext callContext)
    {
        // the same body you had before, unchanged
    }
}

var validationParameters = new ValidationParameters
{
    AudienceValidator = new MyAudienceValidator()
};
```

Parameter lists and return types are identical to the delegates they replace, so your existing method
body moves into the interface method unchanged. Only the wrapper changes.

| 8.x delegate | 9.0 interface | Method |
|---|---|---|
| `AlgorithmValidationDelegate` | `IAlgorithmValidator` | `ValidateAlgorithm` |
| `AudienceValidationDelegate` | `IAudienceValidator` | `ValidateAudience` |
| `DecryptionKeyResolverDelegate` | `IDecryptionKeyResolver` | `ResolveDecryptionKey` |
| `IssuerValidationDelegateAsync` | `IIssuerValidator` | `ValidateIssuerAsync` |
| `LifetimeValidationDelegate` | `ILifetimeValidator` | `ValidateLifetime` |
| `SignatureKeyResolverDelegate` | `ISignatureKeyResolver` | `ResolveSignatureKey` |
| `SignatureKeyValidationDelegate` | `ISignatureKeyValidator` | `ValidateSignatureKey` |
| `SignatureValidationDelegate` | `ISignatureValidator` | `ValidateSignature` |
| `TokenReplayValidationDelegate` | `ITokenReplayValidator` | `ValidateTokenReplay` |
| `TokenTypeValidationDelegate` | `ITokenTypeValidator` | `ValidateTokenType` |

If your code previously assigned a built-in default explicitly - to reset a property, or to compose
your own logic around the shipped behavior - the new default implementations
(`DefaultAudienceValidator`, `DefaultLifetimeValidator`, ...) are **`internal`** and cannot be
constructed from your code. The `Validators` statics are still public, so wrap them:

```diff
- validationParameters.LifetimeValidator = Validators.ValidateLifetime;
+ internal sealed class DefaultLifetimeValidatorShim : ILifetimeValidator
+ {
+     public ValidationResult<ValidatedLifetime, ValidationError> ValidateLifetime(
+         DateTime? notBefore, DateTime? expires, SecurityToken? securityToken,
+         ValidationParameters validationParameters, CallContext callContext)
+         => Validators.ValidateLifetime(
+                notBefore, expires, securityToken, validationParameters, callContext);
+ }
+
+ validationParameters.LifetimeValidator = new DefaultLifetimeValidatorShim();
```

The same shim pattern composes custom logic around shipped behavior: call the
`Validators.Validate*` static, then post-process its result.

### 8b. `TryAllSigningKeys` now defaults to `true`

```diff
- public bool TryAllSigningKeys { get; set; }            // 8.x default: false
+ public bool TryAllSigningKeys { get; set; } = true;    // 9.0 default: true
```

When the signature key resolver cannot resolve a key, 9.0 now tries **every** configured signing key
before failing, instead of failing fast. Validation is not weakened - each key is still verified -
but more keys are attempted per failing token, which costs additional cryptographic work when the
configured key set is large.

**To keep the 8.x behavior:**

```csharp
validationParameters.TryAllSigningKeys = false;
```

---

## 9. API rename

`JsonWebKeyConverter.ConvertFromX509SecurityKey` renamed its second parameter. Behavior is identical.

```diff
- JsonWebKeyConverter.ConvertFromX509SecurityKey(key, representAsRsaKey: true);
+ JsonWebKeyConverter.ConvertFromX509SecurityKey(key, extractKeyMaterial: true);
```

Positional callers need no change.

---

## Verification checklist

Work through this after upgrading:

- [ ] All IdentityModel packages resolve to 9.0.0 - no `IDX00001` version-mismatch warnings.
- [ ] The application builds with no new warnings, or you have consciously suppressed them.
- [ ] Token validation succeeds end to end against your real identity provider.
- [ ] **Group-based authorization:** a user in a group is still authorized. *(Step 4 - fails silently.)*
- [ ] **Signed HTTP Requests:** SHR validation still succeeds, including for clients that may vary
      path casing. *(Step 3)*
- [ ] **Delegation:** `ClaimsIdentity.Actor` is populated as expected, and downstream relying parties
      accept the new `act` claim. *(Step 5)*
- [ ] Logging dashboards and alerts still receive the events they expect. *(Step 6)*
- [ ] **Custom `TokenHandler`:** it overrides the three-argument `ValidateTokenAsync`. *(Step 7)*
- [ ] **Validation extensibility:** validators compile as interfaces, and `TryAllSigningKeys` is set
      explicitly if your code relied on the old `false` default. *(Step 8)*
- [ ] Tests over generated token payloads have been reviewed.
- [ ] Custom crypto error handling still behaves correctly on .NET 6+ - AES-GCM is now backed by the
      platform implementation, so exception types and messages for malformed input may differ.

---

## Getting help

- **Issues and questions:** <https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues>
- **Release notes:** <https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/releases>
- **Actor claim design details:** `src/Microsoft.IdentityModel.JsonWebTokens/ActorClaim.md`

If you hit something during migration that isn't covered here, please open an issue - it likely means
this guide has a gap we should fill.
