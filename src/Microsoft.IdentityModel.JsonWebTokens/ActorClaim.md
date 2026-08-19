# Actor (`act`) Claim Support in `JsonWebTokenHandler`

This document is the detailed reference for actor-claim handling in
`Microsoft.IdentityModel.JsonWebTokens`. The PR descriptions stay short and point here for
design rationale, precedence rules, performance, and test coverage.

- **Serialization** (write path): shipped in PR #3560.
- **Deserialization** (read path): stacked PR #3571.

---

## 1. Background: what the `act` claim is

RFC 8693 (§4.1) defines the `act` (actor) claim to express **delegation** — that one party is
acting on behalf of another. It is a **JSON object** of identity claims:

```json
{
  "sub": "resource-owner",
  "act": { "sub": "delegate-service" }
}
```

Nested `act` objects express a delegation chain — the current actor is outermost, prior actors
are nested. Per RFC 8693, only the **top-level** `act` is used for access-control decisions;
nested/prior actors are informational only.

Non-identity claims (`exp`, `nbf`, `iat`, `aud`, `iss`) "are not meaningful when used within an
`act` claim and are therefore not used."

### `act` vs the legacy `actort`

`JwtSecurityTokenHandler` writes the legacy **`actort`** claim (an unsigned-JWT **string**).
`JsonWebTokenHandler` writes only the modern **`act`** (JSON object). It never writes `actort`.

---

## 2. How serialization works

`WriteJwsPayload` skips the actor during normal claim processing and calls a dedicated,
allocation-light writer chain:

```
WriteActor            resolves the actor + seeds the depth budget (MaxActorChainLength)
  └ WriteActorValue   object while within the budget, else a JSON-text string
      └ WriteActorObject   writes identity claims, recurses for the nested (prior) actor
          └ WriteIdentityClaims   duplicate claim types coalesced into JSON arrays
```

The actor is written **directly from its `ClaimsIdentity`** — no per-level
`SecurityTokenDescriptor` is allocated, and the shipped `WriteJwsPayload` / `AddSubjectClaims`
**signatures** are unchanged.

---

## 3. Actor source and precedence

The actor is resolved by `GetActorIdentity` and the `act` member is **single-sourced** — the
payload always has exactly one `act`. Resolution order:

1. **`Claims["act"]` is a `ClaimsIdentity`** → serialized as the structural `act` object.
   Highest precedence (consistent with "dictionary overrides Subject").
2. **`Claims["act"]` is a non-`ClaimsIdentity` value** → written **verbatim** as an ordinary
   claim; this **suppresses** `Subject.Actor` (the `act` key already occupies the slot).
3. **`Subject.Actor`** → serialized as the structural `act` object when no `Claims["act"]`
   exists.

### Avoiding duplicate `act` members

Two independent code paths can write a property named `act`: `WriteActor` (from the structural
actor) and `AddSubjectClaims` (if a claim in `Subject.Claims` happens to be typed `act`). Left
unguarded, an identity that carries **both** `Subject.Actor` and a literal `act` claim would
emit two `act` members. `Utf8JsonWriter` does not dedupe property names, so this would produce a
malformed/ambiguous token.

Guards:

- The claim loop records when a non-`ClaimsIdentity` `Claims["act"]` was written verbatim and
  then **does not** also write `Subject.Actor`.
- `AddSubjectClaims` **skips** any `Subject.Claims` entry typed `act` when `Subject.Actor` is
  set (the check is hoisted and short-circuited, so non-actor tokens pay only a bool check).

> **Round-trip note:** deserialization sets `identity.Actor` **and** retains the raw `act`
> claim. Re-issuing a token from such an identity is exactly the "both present" case above —
> which is why single-sourcing matters in practice, not just in theory.

### Why the claim name is hardcoded (security)

The actor is written via `Utf8JsonWriter.WritePropertyName("act")`, unconditionally, after the
registered claims. A configurable actor claim name could be set to a registered name and produce
duplicate/ambiguous keys a lenient parser might resolve to the actor object. Hardcoding `"act"`
closes that footgun.

---

## 4. `MaxActorChainLength`

`public static int JsonWebTokenHandler.MaxActorChainLength` — **default `1`, minimum `1`, no
maximum.** Setting it below 1 throws `ArgumentOutOfRangeException` (`IDX14317`).

- **Process-wide ("Wilson-level") static**, shared by serialization *and* deserialization, so a
  token round-trips consistently. A per-call setting could drift between write and read.
- **Within the limit:** each actor level is a nested `act` **object**.
- **Beyond the limit:** the remaining actor subtree **degrades to a JSON-text string** (never a
  JWT) — `"We cannot drop the data; we pass it as-is."` This degradation is still bounded by the
  library's global JSON depth limit of **64**: an actor nested beyond depth 64 fails fast with
  `IDX10815` on write, and a token whose `act` nests beyond 64 fails to **read** (`IDX14101`
  wrapping a depth-64 `JsonReaderException`).
- **Default of 1** is RFC-informed (only the current actor is used for access control) and keeps
  the common case cheap; callers who need deeper chains opt in explicitly.

### Termination and cycles

The recursion terminates on a `null` `Actor` at the end of the chain (the string-degrade path
expands the remainder with `int.MaxValue`, i.e. losslessly). This is safe because
`ClaimsIdentity.Actor` is guaranteed **finite and acyclic** — its setter throws
`InvalidOperationException` on any circular reference, so a cycle can never reach the serializer.

### Deserialization (read path)

On validation, `JsonWebTokenHandler` populates `ClaimsIdentity.Actor` from the token:

- **`act` (RFC 8693) takes precedence whenever the claim is present — in *any* form** — and always
  suppresses the legacy `actort`. A JSON **object** is expanded into `Actor`. A non-expandable `act`
  (a JSON **array**, or a **primitive** such as a string/number) warns (`IDX14314`), leaves `Actor`
  null, and is kept as an ordinary claim — but it *still* wins, so `actort` is not consulted. When
  there is no `act` at all, the legacy `actort` (an unsigned nested-JWT string) is expanded for read
  back-compatibility (this handler writes `act`, never `actort`). The `actort` chain is **not**
  bounded by `MaxActorChainLength` (that bounds `act` only).
- **Degrade, don't throw.** Nested `act` objects are expanded up to `MaxActorChainLength`; deeper
  levels are **kept as a claim** (silent). A within-limit non-object `act` logs a warning
  (`IDX14314`) and is kept as a claim. A failing custom `ActClaimRetriever` logs a warning
  (`IDX14313`, PII-scrubbed) and leaves `Actor` null. **Nothing in the actor read path fails token
  validation** (except a null `TokenValidationParameters`).
- **Issuer.** `act`-derived actor claims carry the **outer token's validated issuer** on
  `Claim.Issuer` (the `act` object is asserted by the outer token). `actort`-derived actor claims,
  by contrast, carry the **nested actor JWT's own issuer** (`GetActualIssuer(actor)`), since `actort`
  is an independent (if unsigned) token.
- **Config asymmetry (`act` vs `actort`).** `act` actors are built as a **bare**
  `CaseSensitiveClaimsIdentity`, so they use **default** `NameClaimType` / `RoleClaimType` /
  `AuthenticationType` and no inbound mapping — read them via their **raw claims** (`sub`, …), not
  `Actor.Name` / `IsInRole`. `actort` actors are built through
  `validationParameters.CreateClaimsIdentity(...)`, so they **do** get the configured name/role/auth
  types and inbound mapping. So an actor's name/role behavior can differ purely based on the wire
  format the sender used — by design. The raw `act` path is deliberate: it preserves the actor's
  claims **verbatim**, without the renaming/transformation inbound mapping would apply, so no actor
  information is lost.
- **Extensibility.** Override `CreateClaimsIdentity` to customize `actort`-derived actors, or set
  `TokenValidationParameters.ActClaimRetriever` to fully own `act` construction.

---

## 5. RFC 8693 §4.1 compliance

Each `act` object contains **identity claims only**. The handler never injects its own default
temporal claims (`exp`/`nbf`/`iat`) into `act`; the top-level payload's default-times behavior is
unchanged. Caller-provided non-identity claims on the actor identity are **written verbatim**
(not stripped) — the RFC does not require a serializer to strip them, and we don't drop data.

An earlier iteration reused `WriteJwsPayload` per actor level, which injected default
`exp`/`iat`/`nbf` into every `act` object (non-compliant). The dedicated writer fixes this, and
it was fixed before the feature shipped, so there is no back-compat cost.

---

## 6. Public API additions

- `static int JsonWebTokenHandler.MaxActorChainLength { get; set; }`
- `const string JwtRegisteredClaimNames.Act = "act"` (mirrored into
  `System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Act`)

New message: `IDX14317` — `MaxActorChainLength` must be ≥ 1.

No shipped internal API **signatures** changed.

---

## 7. Performance

Actor serialization adds **no meaningful latency** — every `CreateToken` performs one RSA-2048
signature (~600 µs) that dominates; latency deltas are within run StdDev. **Allocation** is the
only signal that moves, so optimization targeted allocation.

The final design serializes each actor **directly from its `ClaimsIdentity`** (no per-level
`SecurityTokenDescriptor`, no pooling / thread-static retention):

| Condition | Original redesign | **This PR (STD-free)** |
|---|---:|---:|
| No actor (baseline) | 2.62 KB | 2.62 KB (unchanged) |
| 1 actor (default) | 3.82 KB | **2.97 KB (−22%)** |
| 5-deep chain, limit 1 (deep degrade) | 14.48 KB | 10.49 KB |

~**0.35 KB per actor level** (just the coalescing dictionary), down from ~1.1 KB/level. The
shipped internal API signatures are untouched. Benchmarks: `ActorClaimSerializationBenchmarks` and
`ActorClaimDeserializationBenchmarks` in `Microsoft.IdentityModel.Benchmarks`.

---

## 8. Testing

`ActClaimSerializationTests` — **17 tests**. The process-wide static is reset after every test
via the non-parallel `ActClaimTests` collection. Coverage:

- **`MaxActorChainLength`**: default is 1; `< 1` throws `IDX14317`.
- **RFC compliance**: `act` objects (top-level and every nested level) carry no injected
  `exp`/`nbf`/`iat`, while the top-level payload still does; caller-provided non-identity claims
  survive verbatim.
- **Source & precedence**: actor from `Subject.Actor`; from `Claims["act"]` (`ClaimsIdentity`);
  `Claims` wins over `Subject.Actor`.
- **Single-sourcing (dedupe)**:
  - non-`ClaimsIdentity` `Claims["act"]` **with** `Subject.Actor` → single `act` (Claims wins).
  - non-`ClaimsIdentity` `Claims["act"]` **without** `Subject.Actor` → written verbatim once
    (backward compatible).
  - `Subject.Actor` **plus** a literal `act` claim on `Subject.Claims` → single structural
    `act`.
- **Nested / degrade**: nested actors as objects (raised limit); overflow degrading to a
  JSON-text string (both `Subject.Actor` and `Claims` paths); a chain at exactly the limit.
- **Cyclic guard**: `ClaimsIdentity.Actor` rejects self/mutual cycles (documents the guarantee
  the recursion relies on; verified on net8.0 and net472).

All pass across net6/8/9/10/462/472.

---

## 9. Consequences (by design)

- **Round-trip is lossy beyond `MaxActorChainLength`.** Levels past the limit are stored as an
  opaque JSON-text string; deserialization keeps them as a claim rather than expanding them into
  the `Actor` chain. Intentional and consistent with RFC 8693 (nested actors are informational
  only).
- **The static guarantees intra-process consistency.** A token written and read in the same
  process with the same `MaxActorChainLength` round-trips predictably. Across processes with
  different values, writer and reader depths are independent — the reader expands up to its own
  limit and keeps the rest as claims.
