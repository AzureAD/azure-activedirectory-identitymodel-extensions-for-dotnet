# Microsoft.IdentityModel 9.0.0 - Customer Impact Audit (v8 -> v9)

> **Provenance - the exact commits this document was read at.** Quote these when acting on any
> finding below, and re-verify if either tip has moved.
>
> | Name used here | Branch | Full SHA (as read) | `git describe` |
> |---|---|---|---|
> | **v9** | `dev` | `07d040498c3d887bccc202849d833181646852a6` | `8.15.0-55-g07d04049` |
> | **v8** | `origin/dev8x` | `155e9cb9fcb15514718ed7414f0c63ace530a2b9` | `8.22.0-7-g155e9cb9` |
>
> Read on **2026-08-31**. Every file:line citation and the public API delta are anchored to these two
> commits. Line numbers drift with any new commit; confirm with
> `git rev-parse dev origin/dev8x` before relying on them.
>
> The `describe` values are **not** a version comparison: `8.16.0`-`8.22.0` were tagged on the v8
> branch only, so v9 still resolves to `8.15.0` despite being the newer branch. See Section 0.

> **Audience:** maintainers, release managers, and downstream owners (ASP.NET Core,
> Microsoft.Identity.Web, Azure SDKs) who need an evidence-backed inventory of every
> consumer-observable change in 9.0.0.
>
> **Scope:** this document describes what 9.x delivers - it is intended to be read alongside
> the shipped release.
>
> **Companion:** [`v9-migration-guide.v2.md`](./v9-migration-guide.v2.md) - the customer-facing
> upgrade instructions.

---

## 0. Baseline and method

| Item | Value |
|---|---|
| Old baseline | v8 - `origin/dev8x` @ `155e9cb9` |
| New release branch | v9 - `dev` @ `07d04049` |
| Comparison | **Tip-to-tip** `git diff origin/dev8x dev` -> **333 files, +9499 / -17594** |
| Read at | 2026-08-31 (see the provenance block at the top for full SHAs) |
| Commit attribution | `git log --cherry-pick --left-only/--right-only dev...origin/dev8x` |
| Public API delta | Set difference over the **union** of `PublicAPI.Shipped.txt` + `PublicAPI.Unshipped.txt` across the root and every TFM folder |
| Build/test rig | .NET SDK 10.0.400; `Microsoft.IdentityModel.JsonWebTokens.Tests` builds clean on `net9.0` |

**Verification labels.** Each finding is marked `verified-by-execution` (code was built and run) or
`verified-by-reading` (traced in source). Findings here are reading-verified against both branch
tips.

> **Methodology warning.** Use two-dot `git diff origin/dev8x dev` to compare file contents. Do
> **not** use three-dot `git diff origin/dev8x...dev`: that diffs the merge-base against v9 only, so every v8-side change is invisible and unchanged files can look modified.
>
> Three-dot is correct for `git log`, where it means something different - the symmetric difference,
> i.e. commits on either branch but not both (54 + 38 = 92).
>
> Do not diff `PublicAPI.*.txt` directly either - entries legitimately migrate between `Shipped`
> and `Unshipped` at release time. Compare the *union set*.

---

## Classification legend

| Attribute | Values |
|---|---|
| **Kind** | `Source break` / `Binary break` / `Behavioral default` / `Security/protocol` / `Diagnostics` / `Build/packaging` / `Additive` |
| **Severity** | High / Medium / Low |
| **Blast radius** | All consumers / Feature users / Extenders (subclass or implement) |
| **Detection** | How a customer finds out: compile error, runtime exception, silent behavior change, log change |
| **Opt-out** | Whether old behavior can be restored, and how |

**Silent changes.** Changes detected only as silent behavior shifts will not fail a build or a smoke
test. They are marked **[SILENT]**.

---

## 1. Breaking changes

### 1.1 Validation delegates replaced by interfaces

**Kind:** `Source break` + `Binary break` - **Sev:** High -
**Blast radius:** Feature users - **Detection:** compile error - **Opt-out:** none -
**PR:** #3399 - **Verification:** verified-by-reading (public API set difference)

The whole `Microsoft.IdentityModel.Tokens.Experimental` validation extensibility surface moved from
`delegate` types to interfaces: 10 delegates removed, 10 interfaces added, and the matching
`ValidationParameters` properties retyped.

| Removed (8.x delegate) | Added (9.0 interface) | Interface method | `ValidationParameters` property |
|---|---|---|---|
| `AlgorithmValidationDelegate` | `IAlgorithmValidator` | `ValidateAlgorithm` | `AlgorithmValidator` |
| `AudienceValidationDelegate` | `IAudienceValidator` | `ValidateAudience` | `AudienceValidator` |
| `DecryptionKeyResolverDelegate` | `IDecryptionKeyResolver` | `ResolveDecryptionKey` | `DecryptionKeyResolver` |
| `IssuerValidationDelegateAsync` | `IIssuerValidator` | `ValidateIssuerAsync` | `IssuerValidatorAsync` |
| `LifetimeValidationDelegate` | `ILifetimeValidator` | `ValidateLifetime` | `LifetimeValidator` |
| `SignatureKeyResolverDelegate` | `ISignatureKeyResolver` | `ResolveSignatureKey` | `SignatureKeyResolver` |
| `SignatureKeyValidationDelegate` | `ISignatureKeyValidator` | `ValidateSignatureKey` | `SignatureKeyValidator` |
| `SignatureValidationDelegate` | `ISignatureValidator` | `ValidateSignature` | `SignatureValidator` |
| `TokenReplayValidationDelegate` | `ITokenReplayValidator` | `ValidateTokenReplay` | `TokenReplayValidator` |
| `TokenTypeValidationDelegate` | `ITokenTypeValidator` | `ValidateTokenType` | `TokenTypeValidator` |

Parameter lists and return types are **identical** to the delegates they replace, so migration is
mechanical: the body moves into a class unchanged. Defaults also changed shape -
`Validators.ValidateAudience` (a public static method group) became `new DefaultAudienceValidator()`,
in the new `Experimental/DefaultValidators.cs`.

> **Composability regression.** The new `Default*` implementations are **`internal sealed`**
> (`Experimental/DefaultValidators.cs`). In 8.x a customer could write
> `validationParameters.LifetimeValidator = Validators.ValidateLifetime;` to restore or wrap the
> shipped behavior. In 9.0 there is no public way to obtain a default validator instance. The
> `Validators.Validate*` statics remain public, so a hand-written shim works.
> **Recommendation: make the `Default*` classes public**, or add
> `ValidationParameters.CreateDefault*Validator()` factories.

### 1.2 `ValidationParameters.TryAllSigningKeys` now defaults to `true`

**Kind:** `Behavioral default` - **Sev:** Medium - **Blast radius:** Feature users -
**Detection:** **[SILENT]** - **Opt-out:** set the property to `false` -
**PR:** #3602 - **Verification:** verified-by-reading

```diff
-[DefaultValue(false)]
-public bool TryAllSigningKeys { get; set; }
+[DefaultValue(true)]
+public bool TryAllSigningKeys { get; set; } = true;
```

Additionally, a bug was fixed where `TryAllSigningKeys` was **not** copied by the
`ValidationParameters` copy constructor and so silently reverted to its default on every clone.

**Impact.** When the signature key resolver cannot resolve a key, 9.0 now tries **every** configured
signing key by default instead of failing fast. That widens the set of keys attempted per token -
more cryptographic work on failure paths (a DoS consideration with large key sets) and different
failure messages. It does not weaken validation, since each key is still verified, but it changes
which key can end up validating a token.

### 1.3 `JsonWebKeyConverter.ConvertFromX509SecurityKey` parameter rename

**Kind:** `Source break` - **Sev:** Low - **Blast radius:** callers using named arguments -
**Detection:** compile error (`CS1739`) - **PR:** #3394 -
**Verification:** verified-by-reading (public API set difference)

```diff
- public static JsonWebKey ConvertFromX509SecurityKey(X509SecurityKey key, bool representAsRsaKey)
+ public static JsonWebKey ConvertFromX509SecurityKey(X509SecurityKey key, bool extractKeyMaterial)
```

Behavior is unchanged. The old name became inaccurate once the method learned to extract ECDsa and
ML-DSA key material in addition to RSA. Positional callers are unaffected; `representAsRsaKey:`
callers fail to compile.

### 1.4 Signed HTTP Request `p` (path) claim is now case-**sensitive**

**Kind:** `Behavioral default` + `Security/protocol` - **Sev:** High -
**Blast radius:** SHR / PoP users - **Detection:** **runtime validation failures** -
**Opt-out:** no - **PRs:** #3539, #3569 -
**Verification:** verified-by-reading

```diff
- internal const bool DefaultUseCaseSensitivePClaimComparison = false;
+ internal const bool DefaultUseCaseSensitivePClaimComparison = true;(SignedHttpRequestValidationParameters.cs:85)
```

Path comparison is now case-sensitive by default, per RFC 3986 section 3.3.

**The AppContext switch is removed.** `Switch.Microsoft.IdentityModel.SignedHttpRequest.UseCaseSensitivePClaimComparison` Applications
that set it to `false` in v8 will silently lose the opt-out and begin rejecting requests whose path
casing differs.

### 1.5 Actor claim handling rewritten (`act` / `actort`)

**Kind:** `Behavioral default` + `Additive` - **Sev:** Medium -
**Blast radius:** users of `ClaimsIdentity.Actor`, delegation/impersonation, or `actort` -
**Detection:** **[SILENT]** - token wire format changes; `Actor` populated differently -
**PRs:** #3560, #3571 - **Design doc:** `src/Microsoft.IdentityModel.JsonWebTokens/ActorClaim.md` -
**Verification:** verified-by-reading

`JsonWebTokenHandler` now implements the RFC 8693 `act` claim on **both** the write and read paths.

**Write path (new emission - this changes bytes on the wire):**

| 8.x | 9.0 |
|---|---|
| `SecurityTokenDescriptor.Subject.Actor` was **not serialized** | `Subject.Actor` (or a `ClaimsIdentity` under `Claims["act"]`) is serialized as a structural RFC 8693 `act` **JSON object** |
| n/a | Delegation chains nest as `act.act...`, bounded by `MaxActorChainLength` (default **1**) |
| n/a | Levels beyond the limit degrade to a **JSON-text string** (lossless, never a JWT) |
| n/a | `act` objects deliberately carry **identity claims only** - no injected `exp`/`nbf`/`iat`/`aud`/`iss` |

Any relying party, log scrubber, token-size budget, or test that assumed `CreateToken`
output contains no `act` member will see a difference.

**Read path (precedence and shape changed):**

| Aspect | 8.x | 9.0 |
|---|---|---|
| Source of `identity.Actor` | `actort` only, and only when inbound claim mapping produced `ClaimTypes.Actor` | `act` (JSON object) when present; otherwise `actort` |
| Inbound claim mapping off | `Actor` **not** populated | `Actor` **is** populated (lookup is on the raw claim name) |
| Both `act` and `actort` present | n/a | `act` wins; **no exception** |
| Duplicate actor claims | threw `InvalidOperationException` **`IDX14112`** | **no longer thrown** - `act` wins |
| Actor identity type | per `validationParameters.CreateClaimsIdentity` | `act` -> bare `CaseSensitiveClaimsIdentity`; `actort` -> `CreateClaimsIdentity` (unchanged) |
| Actor claim `Issuer` | outer/validated issuer | `act` -> outer validated issuer; `actort` -> the **nested token's own** issuer (`GetActualIssuer`) |
| Name/Role claim types on actor | configured | `act` actors use **defaults** and get **no inbound mapping** |
| Failure mode | exception | **never fails validation** - warns `IDX14313` / `IDX14314` and leaves `Actor` null |

`IDX14112` still exists in v9, but only in
`Experimental/JsonWebTokenHandler.ClaimsIdentity.cs:79,127`. The mainline throw site that v8
retains at `JsonWebTokenHandler.cs:293` is gone.

**Test for:**

- Code relying on `IDX14112` to reject ambiguous actor claims no longer gets an exception.
- `identity.Actor.Name` and `identity.Actor.IsInRole(...)` break for `act`-sourced actors, because
  those actors are built without the configured `NameClaimType` / `RoleClaimType`.
- Actor name/role behavior now differs purely by which wire format the *sender* used. `ActorClaim.md`
  documents this as intentional.

**New API:** `JsonWebTokenHandler.MaxActorChainLength` (static; default `1`; minimum `1`;
`ArgumentOutOfRangeException` / `IDX14317` below 1), `TokenValidationParameters.ActClaimRetriever`,
the `ActClaimRetriever` delegate, and `JwtRegisteredClaimNames.Act` in both JWT packages.

### 1.6 Successful-validation logs downgraded to Verbose

**Kind:** `Diagnostics` - **Sev:** Medium - **Blast radius:** anyone alerting on these events -
**Detection:** **[SILENT]** - log lines disappear - **Opt-out:** AppContext switch - **PR:** #3409 -
**Verification:** verified-by-reading (`Validators.cs:191,261`; `AppContextSwitches.cs:105`)

`IDX10239` (lifetime validated) and `IDX10234` (audience validated) moved from **Informational** to
**Verbose**. Dashboards, alerts, log queries, and compliance audit trails keyed on these messages
at Informational go silent - no error, no warning, no build failure.

**Opt-out:** `AppContext.SetSwitch("Switch.Microsoft.IdentityModel.SuccessValidationLogsAsInformation", true)`.
The value is read once and cached (`_successValidationLogsAsInformation ??= ...`), so it **must be
set before the first token validation**.

### 1.7 `LogValidationExceptions = false` now suppresses logs

**Kind:** `Diagnostics` - **Sev:** Low - **Blast radius:** those who set the flag -
**Detection:** **[SILENT]** - **Opt-out:** leave the flag `true` (the default) - **PR:** #3425 -
**Verification:** verified-by-reading (`Validators.cs`, `ValidatorUtilities.cs`)

`TokenValidationParameters.LogValidationExceptions` controls whether a validation failure is
written to the log before its exception is thrown.

In 8.x most validators ignored the flag and logged unconditionally:

```csharp
// 8.x - always logs, then throws
throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidAlgorithmException(...));

// 9.0 - logs only when the flag is true
if (!validationParameters.LogValidationExceptions)
    throw ex;

throw LogHelper.LogExceptionMessage(ex);
```

The flag was checked at **2** sites in 8.x and is checked at **25** in 9.0 (21 in `Validators.cs`,
4 in `ValidatorUtilities.cs`). Callers who set it to `false` and still relied on the previously
unconditional log lines for forensics no longer get them. Affected: `IDX10204`, `IDX10206`,
`IDX10207`, `IDX10208`, `IDX10211`, `IDX10232`, `IDX10248`, `IDX10249`.

### 1.8 `TokenValidationParameters` copy constructor drops a custom `PropertyBag` comparer

**Kind:** `Behavioral` - **Sev:** Low - **Blast radius:** extenders using a custom comparer -
**Detection:** **[SILENT]** - lookups start failing or become case-sensitive - **PR:** #3403 -
**Verification:** verified-by-reading

```csharp
// v9 (TokenValidationParameters.cs:76)
PropertyBag = other.PropertyBag is not null ? new Dictionary<string, object>(other.PropertyBag) : null;

// released 8.22.0
PropertyBag = other.PropertyBag switch
{
    null => null,
    Dictionary<string, object> dictionary => new Dictionary<string, object>(dictionary, dictionary.Comparer),
    _ => new Dictionary<string, object>(other.PropertyBag)
};
```

A bag created with `StringComparer.OrdinalIgnoreCase` silently becomes ordinal/case-sensitive after
`Clone()`. This is a regression against **released** 8.22.0. The `Clone()` XML doc was also
reverted to "This is a deep Clone." - now only partially true.

### 1.9 `groups` added to the inbound claim type map

**Kind:** `Behavioral default` - **Sev:** Medium -
**Blast radius:** `JwtSecurityTokenHandler` / mapped-claims users who read `"groups"` -
**Detection:** **[SILENT]** - authorization can change - **PR:** #3391 -
**Verification:** verified-by-reading (`Microsoft.IdentityModel.JsonWebTokens/ClaimTypeMapping.cs:73`; absent in v8)

```csharp
{ "groups", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups" },
```

Code doing `identity.FindAll("groups")` or `User.HasClaim("groups", ...)` against a handler with
inbound claim mapping enabled now finds **nothing**, because the claim has been renamed. Nothing
throws; matching stops, and a group-based check evaluates to `false`.

**Opt-out:** `handler.InboundClaimTypeMap.Remove("groups")`, or disable mapping entirely
(`handler.MapInboundClaims = false` / `JwtSecurityTokenHandler.DefaultMapInboundClaims = false`).

### 1.10 Latent break - `NotImplementedException` from the new 3-argument `ValidateTokenAsync`

**Kind:** `Binary/behavioral break` - **Sev:** High -
**Blast radius:** SHR users with a non-default `TokenHandler`; anyone subclassing `TokenHandler` -
**Detection:** **runtime `NotImplementedException` (`IDX10267`)** -
**Opt-out:** override the new overload - **PR:** #3401 -
**Verification:** verified-by-reading (`TokenHandler.cs:79-119`)

```csharp
// 9.0 - TokenHandler.cs
public virtual Task<TokenValidationResult> ValidateTokenAsync(string token, TokenValidationParameters vp)
    => ValidateTokenAsync(token, vp, CancellationToken.None);      // now FORWARDS

public virtual Task<TokenValidationResult> ValidateTokenAsync(
    string token, TokenValidationParameters vp, CancellationToken ct)
    => throw new NotImplementedException(...IDX10267...);          // base throws
```

`JsonWebTokenHandler` is the **only** type in the repository that overrides the 3-argument forms
(`JsonWebTokenHandler.ValidateToken.cs:541,579`). `JwtSecurityTokenHandler`,
`SamlSecurityTokenHandler`, `Saml2SecurityTokenHandler`, and any customer handler written against
8.x override **only** the 2-argument form.

`SignedHttpRequestHandler.cs:557` now calls the **3-argument** overload, and
`SignedHttpRequestValidationParameters.TokenHandler` is typed as the base `TokenHandler`. Therefore:

> Setting `SignedHttpRequestValidationParameters.TokenHandler` to a `JwtSecurityTokenHandler`, a
> `Saml*SecurityTokenHandler`, or any 8.x-era custom handler throws `NotImplementedException`
> (`IDX10267`) at validation time. This works fine on 8.22.

The default (`new JsonWebTokenHandler()`) is unaffected, so default-configuration testing does not
surface this.

**Recommended fix:** make the base 3-argument overload forward to the 2-argument overload rather
than throw, so 8.x-era subclasses keep working and merely *ignore* cancellation. Because the
2-argument overload already forwards to the 3-argument one, the two must not delegate to each other
unguarded - break the cycle with a protected virtual core method or an internal re-entrancy flag.

---

## 2. Non-breaking additions

### 2.1 Complete public API delta

Computed as a union-set difference over every `PublicAPI.Shipped.txt` + `PublicAPI.Unshipped.txt`
under `src/`, per package, across all TFM folders. **Only three packages have any delta:**

| Package | Added | Removed |
|---|---|---|
| `Microsoft.IdentityModel.JsonWebTokens` | 5 | 0 |
| `Microsoft.IdentityModel.Tokens` | 38 | 30 |
| `System.IdentityModel.Tokens.Jwt` | 1 | 0 |


**`Microsoft.IdentityModel.JsonWebTokens` (+5)**

| API | Notes |
|---|---|
| `override JsonWebTokenHandler.ValidateTokenAsync(string, TokenValidationParameters, CancellationToken)` | Cancellation support (2.2) |
| `override JsonWebTokenHandler.ValidateTokenAsync(SecurityToken, TokenValidationParameters, CancellationToken)` | Cancellation support (2.2) |
| `static JsonWebTokenHandler.MaxActorChainLength.get -> int` | Default `1`, min `1`; process-wide static (1.5) |
| `static JsonWebTokenHandler.MaxActorChainLength.set -> void` | |
| `const JwtRegisteredClaimNames.Act = "act"` | |

**`Microsoft.IdentityModel.Tokens` (+38 / -30)**

*Added, `Microsoft.IdentityModel.Tokens`:*

| API | Notes |
|---|---|
| `virtual TokenHandler.ValidateTokenAsync(string, TokenValidationParameters, CancellationToken)` | **see 1.10** - base throws |
| `virtual TokenHandler.ValidateTokenAsync(SecurityToken, TokenValidationParameters, CancellationToken)` | **see 1.10** - base throws |
| `delegate ActClaimRetriever(JsonElement actClaim, TokenValidationParameters tokenValidationParameters) -> ClaimsIdentity` | Custom `act` deserialization hook |
| `TokenValidationParameters.ActClaimRetriever { get; set; }` | Fully owns actor construction when set; exceptions are swallowed and warn `IDX14313` |
| `JsonWebKeyConverter.ConvertFromX509SecurityKey(X509SecurityKey, bool extractKeyMaterial)` | Rename; old signature recorded as `*REMOVED*` (1.3) |

*Added, `Microsoft.IdentityModel.Tokens.Experimental`:* the 10 `I*Validator` / `I*Resolver`
interfaces and their methods, the 9 retyped `ValidationParameters.*Validator` getters, and
`SignatureValidationFailure.SignatureProviderCreationFailed` (a new categorized failure).

*Removed:* the 10 delegates plus their `Invoke` members, the 9 old delegate-typed
`ValidationParameters` getters, and the old `ConvertFromX509SecurityKey` overload (1.1, 1.3).

**`System.IdentityModel.Tokens.Jwt` (+1):** `const JwtRegisteredClaimNames.Act = "act"` (mirror).

**Packages with no public API delta:** `Microsoft.IdentityModel.Dpop`, `...Protocols`,
`...Protocols.OpenIdConnect`, `...Protocols.WsFederation`, `...Protocols.SignedHttpRequest`,
`...Validators`, `...Xml`, `...Tokens.Saml`, `...Logging`, `...Abstractions`.

> `SignedHttpRequestValidationParameters.UseCaseSensitivePClaimComparison` shows **no** delta because
> v8 also carries it (backported by #3577). Its *default value* still changed - see 1.4. A
> public API diff cannot detect default-value changes; that is why sections 1.2, 1.4, and 1.9 exist.

### 2.2 Cancellation support

`JsonWebTokenHandler` threads the `CancellationToken` through validation, including the
configuration-manager fetch. Previously a hung metadata retrieval could not be cancelled by the
caller.

### 2.3 Cryptography

| Change | Impact | PR |
|---|---|---|
| **AES-GCM uses the BCL `System.Security.Cryptography.AesGcm` on .NET 6+** instead of the vendored implementation | Cross-platform AES-GCM; better performance; picks up OS/FIPS-validated crypto. Error *types and messages* on malformed input may differ. | #3396 |
| **Plaintext buffer zeroed on AES-GCM decrypt failure** (`CryptographicOperations.ZeroMemory`) | Defense in depth - partial plaintext no longer survives a failed decrypt | #3432 |
| **AES-KW uses one-shot `Aes.EncryptEcb` / `DecryptEcb` on .NET 10+** | Avoids `CipherMode.ECB` transform objects; fewer allocations | #3404 |

### 2.4 Internal correctness fixes

| Change | Customer-visible? | PR |
|---|---|---|
| `JsonSerializerPrimitives` reader positioning honors the `read` parameter instead of unconditionally calling `reader.Read()` | Only for extenders calling these `internal` helpers, or exotic custom-JSON payload shapes; fixes reader desynchronization | #3430 |
| Error-message wording adjustments | Only if you string-match on messages | #3482, #3592 |

---

## 3. Build and packaging

### 3.1 New: automatic version-mismatch build warning

**Kind:** `Build/packaging` - **Sev:** Medium - **Blast radius:** ***all consumers*** -
**Detection:** **new warnings in every build** - **Opt-out:** yes - **PR:** #3423 -
**Verification:** verified-by-reading (`build/common.props` +19 lines; `src/Common/Microsoft.IdentityModel.VersionMismatch*.{targets,cs}`)

`build/common.props` now packs two files into **every** `Microsoft.IdentityModel.*` and
`System.IdentityModel.*` package:

```xml
<None Include="...\src\Common\Microsoft.IdentityModel.VersionMismatch.targets"
      Pack="true" PackagePath="buildTransitive\$(PackageId).targets" />
<None Include="...\src\Common\Microsoft.IdentityModel.VersionMismatchTask.cs"
      Pack="true" PackagePath="buildTransitive\Microsoft.IdentityModel.VersionMismatchTask.cs" />
```

The targets file hooks `AfterTargets="ResolvePackageAssets"`, inspects `@(RuntimeCopyLocalItems)`
metadata via a `RoslynCodeTaskFactory` inline task, and **warns when resolved IdentityModel package
versions are not all identical**.

Mixed IdentityModel versions are a common source of runtime failures. This change has the broadest
blast radius in the release, because `buildTransitive` propagates it to every consuming project,
including transitive ones:

- Customers building with `TreatWarningsAsErrors=true` may see **builds start failing** purely from
  the upgrade - including on graphs they do not control (ASP.NET Core or the Azure SDKs bringing in
  a different IdentityModel version transitively).
- The check is skipped during design-time builds and runs at most once per project.
- Warning code **`IDX00001`** (`Microsoft.IdentityModel.VersionMismatchTask.cs:153`), suppressible
  with `<NoWarn>$(NoWarn);IDX00001</NoWarn>`.
- Full opt-out: `<DisableIdentityModelVersionMismatchCheck>true</DisableIdentityModelVersionMismatchCheck>`.

**Recommendation:** document `IDX00001` and `DisableIdentityModelVersionMismatchCheck` in the
release notes, since the warning will surface in consumer builds immediately on upgrade.

### 3.2 Other build changes

| Change | Impact |
|---|---|
| `global.json` SDK `10.0.100` -> `10.0.103` | Contributors only |
| `build/cgmanifest.json`: outdated Newtonsoft.Json registration removed | Compliance reporting only |
| `build/credscan-exclusion.json`: 4 entries removed | Contributors only |
| `build/strongNameBypass.reg`: missing entries added | Test/dev machines only |
| `build/targetsTest.props`: EOL .NET 6 warning suppression | Contributors only |
| `NuGet.Config`: switched to the approved feed (#3598) | Contributors only |
| CI: pinned action SHAs, manual workflow triggers, test tenant migration | Contributors only |

**Target frameworks are unchanged:** `net10.0`, `net9.0`, `net8.0`, `net6.0`, `net462`, `net472`,
`netstandard2.0`.

The IdentityModel packages' dependencies **on each other** move from `8.x` to `9.0.0`:
`build/version.props` raises `MicrosoftIdentityModelCurrentVersion` from `8.22.1` to `9.0.0`, and
each package references its siblings by `ProjectReference`, so the packed dependency version follows.
This is what the `IDX00001` version-mismatch check exists to catch.

---

## 4. Consolidated risk register

Changes that ship in 9.0.0.

| Change | Kind | Sev | Detection | Opt-out |
|---|---|---|---|---|
| 3-arg `ValidateTokenAsync` throws for 8.x handlers | Binary | **High** | `NotImplementedException` `IDX10267` | override the overload |
| SHR `p` claim case-sensitive; 8.22.0 AppContext switch ignored | Behavior | **High** | SHR validation failures | `UseCaseSensitivePClaimComparison = false` |
| Validation delegates -> interfaces | Source | **High** | compile error | none |
| `TryAllSigningKeys` defaults to `true` | Behavior | Medium | **[SILENT]** | set to `false` |
| Actor `act` write/read semantics | Behavior | Medium | **[SILENT]** | `MaxActorChainLength`, `ActClaimRetriever` |
| `groups` inbound claim mapping | Behavior | Medium | **[SILENT]** authz change | remove map entry / disable mapping |
| Version-mismatch build warning `IDX00001` | Build | Medium | new warnings/errors | `DisableIdentityModelVersionMismatchCheck` |
| `IDX10239`/`IDX10234` -> Verbose | Diag | Medium | **[SILENT]** log loss | `SuccessValidationLogsAsInformation` switch |
| `LogValidationExceptions` now honored | Diag | Low | **[SILENT]** log loss | leave flag `true` |
| `PropertyBag` comparer lost on copy | Behavior | Low | **[SILENT]** lookup failures | rebuild bag manually |
| `ConvertFromX509SecurityKey` param rename | Source | Low | compile error | rename argument |
| `Default*` validators are `internal` | Source/usability | Low | compile error on `new Default*()` | shim over `Validators.Validate*` |
| AES-GCM now BCL-backed on .NET 6+ | Behavior | Low | different exception text | none |

---

## Appendix A - 9.0-only commits (authored in v9, not in v8)

`git log --cherry-pick --left-only --no-merges dev...origin/dev8x` - customer-relevant entries only.

| Commit | Date | Summary |
|---|---|---|
| `6a1b575b` | 2026-01-12 | Claim type mapping: missing `groups` (#3391) |
| `1a559193` | 2026-01-14 | Update signature for `JsonWebKeyConverter` (#3394) |
| `cb6958c7` | 2026-01-14 | Cross-platform AES-GCM for .NET 6+ (#3396) |
| `38224047` | 2026-01-22 | Add `CancellationToken` to `ValidateTokenAsync` (#3401) |
| `0408a007` | 2026-01-22 | `TokenValidationParameters` copy ctor deep copy (#3403) |
| `e80574dc` | 2026-02-02 | Default KW for .NET 10 (#3404) |
| `c074b468` | 2026-02-05 | `IDX10239`/`IDX10234` -> Verbose with opt-in switch (#3409) |
| `7dc6f553` | 2026-02-19 | Respect `LogValidationExceptions` in all validators (#3425) |
| `f02a3a87` | 2026-02-23 | Emit warning for package version mismatch (#3423) |
| `8c90b15c` | 2026-03-09 | Clear plaintext on decrypt failure (#3432) |
| `cdac1ecf` | 2026-03-11 | Restore reader positioning in `JsonSerializerPrimitives` (#3430) |
| `e9200421` | 2026-03-16 | Convert validation delegates to interfaces (#3399) |
| `01273779` | 2026-07-08 | SHR `p` claim comparison case-sensitive (#3539) |
| `4aea30f2` | 2026-07-29 | Configure SHR path comparison (#3569) |
| `42aa347d` | 2026-08-05 | Actor (`act`) claim serialization (#3560) |
| `c361f59a` | 2026-08-17 | Change error message to fit available information (#3592) |
| `ce3e8f1e` | 2026-08-19 | Deserialize actor claim `act` (#3571) |
| `07d04049` | 2026-08-27 | **Fix `ValidationParameter` issues (#3602)** - `TryAllSigningKeys` default flip (1.2) |

Omitted as not independently customer-relevant: version bumps, CHANGELOG edits, CI/lab/test-only
commits (`1f8efea1` #3589, `17794c8f` #3598, `e714eba1`, `8bf229b2`, `532cc64c`, `2a47bda9`,
`8ffd5b04`, `aa4bdc81`, `38957005`, `c58a4511`), and cherry-picks of 8.x work (DPoP
#3443/#3501/#3504/#3506, ML-DSA #3532, `CacheCustomProviders` #3536,
`IgnoreCaseWhenValidatingAudience` #3558, header replacement #3552, SHR hex-case #3561).


## Appendix B - Reproducing this audit

```powershell
git fetch --all --tags
git diff --shortstat origin/dev8x dev                              
git describe --tags dev                                            # 8.15.0-55-g07d04049
git describe --tags origin/dev8x                                   # 8.22.0-7-g155e9cb9
git log --cherry-pick --right-only --no-merges dev...origin/dev8x  # 8.x-only work
git log --cherry-pick --left-only  --no-merges dev...origin/dev8x  # 9.0-only work

# Public API set-diff per package, immune to Shipped/Unshipped churn:
#   union(all src/**/PublicAPI.Shipped.txt + PublicAPI.Unshipped.txt) per branch,
#   read via `git show <branch>:<path>`, trimmed, '#nullable enable' dropped,
#   then set-differenced per package.

# Build rig used for execution-verified findings:
dotnet build test/Microsoft.IdentityModel.JsonWebTokens.Tests/Microsoft.IdentityModel.JsonWebTokens.Tests.csproj -f net9.0
```
