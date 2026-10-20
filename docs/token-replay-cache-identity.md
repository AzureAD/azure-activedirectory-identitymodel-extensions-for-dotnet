# Opt-in replay cache identities

`TokenValidationParameters.UseTokenReplayCacheIdentity` and experimental
`ValidationParameters.UseTokenReplayCacheIdentity` are additive options, both
defaulting to `false`. They apply to the built-in validation paths of
`JwtSecurityTokenHandler`, `JsonWebTokenHandler`, `SamlSecurityTokenHandler`, and
`Saml2SecurityTokenHandler` (including the experimental JSON/SAML paths).

**Existing integrations are not automatically protected.** With the option off,
the cache still receives the legacy token string, including its signature, and
the existing replay callback order is preserved. An alternate valid ECDSA
signature can therefore bypass raw-string replay detection. An exact replay is
still detected. Updating the library alone does not close this bypass.

## Enable the built-in protection

Configure a replay cache and enable the option for every accepting instance:

```csharp
var parameters = new TokenValidationParameters
{
    // Also configure the trusted issuers, audiences, and signing keys.
    ValidateTokenReplay = true,
    UseTokenReplayCacheIdentity = true,
    TokenReplayCache = replayCache
};
```

For experimental `ValidationParameters`, configure `TokenReplayCache` and set
`UseTokenReplayCacheIdentity = true`; there is no separate `ValidateTokenReplay`
switch. The option is preserved by both parameter types' copy constructors and
`Clone()`.

Retain signature verification, trusted issuer/key policy, and the other
validations appropriate to the application. The option is not an authentication
mechanism, and cannot make an accepting custom signature validator trustworthy.
It neither rejects high-S ECDSA signatures nor rewrites signatures or tokens.
It requires no JWT `jti` claim.

## Identity and validation order

Only the built-in cache receives an opaque, versioned, domain-separated SHA-256
identity (currently prefixed with `IM.Replay.v1.`). Do not parse this key as a
serialized token or depend on its representation in application code.

* **JWT:** the exact encoded `header + "." + payload` signing input, excluding
  the signature. It is not decoded, normalized, or reserialized. Semantically
  equivalent but differently encoded signing inputs remain distinct. For a
  decrypted JWE, identity is derived from the validated inner JWS, not the outer
  encryption or signature bytes.
* **SAML:** an unambiguous length-prefixed tuple of assertion format (`SAML1` or
  `SAML2`), authenticated assertion issuer, and assertion ID. The issuer is the
  case-sensitive issuer carried in the signed assertion, **not** a normalized
  alias returned by a custom issuer validator. The format separates SAML 1 and
  SAML 2 even when issuer and ID match. Issuers must ensure assertion-ID
  uniqueness within their own scope; distinct assertions reusing an ID are
  treated as replays.

With the option enabled, replay handling occurs after the applicable signature
verification, signing-key policy, and other handler validations succeed.
Invalid signatures and rejected signing keys do not reserve an identity.
Signature-last and experimental flows follow this rule, including configuration
refresh/last-known-good retries. A failed attempt does not preempt a later
successful authenticated retry.

The existing expiration passed to the cache is retained; this change does not
extend replay entries by clock skew or change global lifetime validation.
Replay cache processing requires an expiration. In particular, opt-in current
SAML validation no longer skips replay processing when `Conditions` is absent:
with built-in caching enabled it fails closed for the missing expiration, even
if lifetime validation was disabled. The legacy mode's skip is unchanged.

## Extension points and direct APIs

No `ITokenReplayCache` method signature or default input contract changes.
Custom replay delegates/validators and existing protected replay overrides
still receive the original legacy argument (the compact JWT, or SAML
`CanonicalString`, including its signature), and the original validation
parameters. They retain their replacement semantics: an accepting replacement
does not fall through to built-in cache processing.

**Replacement replay delegates, experimental replay validators, and protected
overrides that do not call the base implementation are not automatically
fixed.** They own signature-independent replay protection. Opt-in changes their
invocation to the authenticated, late stage; default-off invocation order
remains unchanged. Overridden validation entry points or other extensions that
bypass built-in validation likewise own the resulting security contract.

Direct public `Validators.ValidateTokenReplay` calls continue to use the
supplied string unchanged, even when the option is enabled. They have no
authenticated token-format context and do not parse arbitrary input to derive
an identity. Applications using those APIs must supply their own authenticated
replay key or use the format-aware handlers.

## Distributed caches and deployment

The backing cache must implement **atomic insert-if-absent**, including across
processes/nodes. `TryFind` followed by an unconditional write is not sufficient:
two concurrent requests may both observe absence. `TryAdd` must return `false`
when another request has already inserted the key. Built-in validation fails
closed when adding fails. The library does not turn a non-atomic cache into an
atomic one.

All accepting instances must share the appropriate cache scope, identity
version, and enabled mode. Legacy raw-token entries and identity entries do
not match, are not dual-read/dual-written, and cannot generally be migrated
without the original authenticated token data. An enabled instance does not
recognize a prior legacy insertion, and a legacy instance remains bypassable.
Mixed versions/modes, switching cache namespaces, clearing a cache, or changing
the identity algorithm can create a replay window.

Plan a coordinated rollout/cutover, with application-specific admission controls
or a drain of previously accepted tokens for their entire remaining acceptance
window (including the application's clock-skew policy). Keep cache state for
that window. Do not assume enabling the option retroactively protects tokens
accepted under the old contract.

This feature does not provide a transaction across actor/outer tokens, multiple
independent validations, cache insertion and downstream application actions, or
configuration changes. An actor identity may already have been inserted if a
later outer-token validation fails. Cache retention/availability, distributed
atomicity, issuer-ID uniqueness, customized validation, and rollout coordination
remain application responsibilities.
