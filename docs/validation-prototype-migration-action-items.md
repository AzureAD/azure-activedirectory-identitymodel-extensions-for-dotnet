# Validation Prototype Migration Action Items

## Scope and audit baseline

This checklist tracks gaps in the migration from `TokenValidationParameters` and
`TokenValidationResult` to `ValidationParameters` and
`ValidationResult<ValidatedToken, ValidationError>`.

The audit was performed on 2026-10-19 against commit `bfb4f180f3263da74645affa918f63729f431dd2`.
It covered 762 tracked C# files and found 1,107 explicit legacy-type references in
580 members across 100 files. Untracked repro files were excluded.

The confirmed production backlog consists of **13 members without counterparts**
and **two members with partial counterparts**. Constructors are counted separately.
Renamed implementations, consolidated/shared implementations, and validator-interface
replacements count as counterparts; identical method names are not required.

Test/data findings marked "no direct counterpart identified" are review candidates,
not proof that equivalent scenario coverage is absent from another prototype suite.
Do not duplicate tests or APIs solely to eliminate a legacy-type reference.

All paths below are relative to the repository root. Line numbers refer to the audit
commit and may move. All action items are initially open.

## Required production counterparts

These items can proceed independently unless a dependency is stated.

### SRC-01: Configuration-aware JWT decryption

- [ ] Add a `ValidationParameters` counterpart to `JsonWebTokenHandler.DecryptTokenWithConfigurationAsync`.

**Location:** `src\Microsoft.IdentityModel.JsonWebTokens\JsonWebTokenHandler.cs:320`.

**Acceptance:** The entry point obtains configuration rather than requiring callers
to supply it, and follows the prototype's result/error conventions. Preserve the
applicable configuration, key-resolution, decryption, and cancellation behavior.
Cover successful decryption and relevant failure paths. The existing experimental
`DecryptToken`, which accepts an already-obtained `BaseConfiguration`, is not a
complete replacement for this entry point.

### SRC-02: Token-reader and pre-signature transformation hooks

- [ ] Provide prototype equivalents for `TokenReader` and `TransformBeforeSignatureValidation`.

**Locations:** `src\Microsoft.IdentityModel.Tokens\Delegates.cs:146,173`;
`src\Microsoft.IdentityModel.Tokens\Experimental\Validation\ValidationParameters.cs`;
`src\Microsoft.IdentityModel.Tokens\Experimental\Interfaces.cs`.

**Acceptance:** The hooks are configurable through the experimental contract and are
invoked at the appropriate points in the applicable handler pipelines. Cover custom
token readers, incorrect token types, null results, thrown errors, transformation,
and invocation order. Any intentional departure from legacy behavior must be
explicitly reviewed and documented rather than silently omitted.

### SRC-03: SAML2 subject and confirmation extension hooks

- [ ] Provide prototype counterparts for `Saml2SecurityTokenHandler.ValidateSubject` and `ValidateConfirmationData`, and connect them to validation.

**Locations:** `src\Microsoft.IdentityModel.Tokens.Saml\Saml2\Saml2SecurityTokenHandler.cs:303,365`.

**Acceptance:** The prototype exposes equivalent customization points and preserves
the applicable subject/confirmation behavior. Cover hook invocation and error
propagation. The legacy default confirmation-data hook logs unsupported processing;
this item does not require inventing new subject-confirmation support.

### SRC-04: Complete and invoke SAML2 condition validation

- [ ] Complete the partial counterparts for legacy `ValidateConditions` and `ValidateOneTimeUseCondition`.

**Legacy locations:** `src\Microsoft.IdentityModel.Tokens.Saml\Saml2\Saml2SecurityTokenHandler.cs:1046,1091`.

**Prototype locations:** `src\Microsoft.IdentityModel.Tokens.Saml\Saml2\Experimental\Saml2SecurityTokenHandler.ValidateToken.Internal.cs:209,216`.

**Acceptance:** Experimental `ValidateOneTimeUseCondition` and
`ValidateProxyRestriction` no longer act as unconditional success stubs, and the
prototype validation pipeline actually calls the condition handling. Preserve
legacy rejection/unsupported behavior where applicable; do not silently add support
or accept previously rejected conditions. Cover condition-bearing tokens and
propagated errors. Retain the lifetime/audience checks already implemented inline.

## Signed HTTP Request integration

These four items cover eight of the 13 missing production members. Keep existing
legacy APIs working while adding experimental counterparts.

### SHR-01: Access-token validation context

- [ ] Add an experimental context/API representation using `ValidationParameters`.

**Location:** `src\Microsoft.IdentityModel.Protocols.SignedHttpRequest\SignedHttpRequestValidationContext.cs:21,33,46,59,71`.

**Acceptance:** Cover the four existing constructor forms and the
`AccessTokenValidationParameters` property. Preserve the applicable defaults,
argument validation, `CallContext`, and Signed HTTP Request options. Choose an
additive experimental representation rather than changing existing public property
types or removing legacy constructors.

### SHR-02: Access-token validation result

- [ ] Add an experimental counterpart to `SignedHttpRequestValidationResult.AccessTokenValidationResult`.

**Location:** `src\Microsoft.IdentityModel.Protocols.SignedHttpRequest\SignedHttpRequestValidationResult.cs:17`.

**Acceptance:** Represent access-token validation with
`ValidationResult<ValidatedToken, ValidationError>`, including both success and
failure. Preserve the outer Signed HTTP Request result semantics and the applicable
claims/security-token access without requiring the prototype path to convert back
to `TokenValidationResult`.

### SHR-03: End-to-end access-token validation

- [ ] Add the prototype path for `ValidateAccessTokenAsync` and wire it through `ValidateSignedHttpRequestAsync`.

**Depends on:** SHR-01 and SHR-02.

**Locations:** `src\Microsoft.IdentityModel.Protocols.SignedHttpRequest\SignedHttpRequestHandler.cs:486,552`.

**Acceptance:** The outer Signed HTTP Request flow consumes the new context and
generic access-token result end to end. Preserve cancellation, propagate validation
errors consistently, and cover valid/invalid access tokens and the surrounding
signed-request success/failure behavior. The legacy path remains functional.

### SHR-04: Symmetric PoP-key decryption

- [ ] Add a prototype counterpart to `SignedHttpRequestUtilities.DecryptSymmetricPopKeyAsync`.

**Depends on:** SRC-01 and SHR-01.

**Location:** `src\Microsoft.IdentityModel.Protocols.SignedHttpRequest\SignedHttpRequestUtilities.cs:76`.

**Acceptance:** The experimental PoP-key flow uses new validation parameters and
configuration-aware decryption without constructing `TokenValidationParameters`.
Preserve the applicable key-resolver, configuration, cancellation, and error
behavior. Cover successful key recovery and decryption failures.

## Supporting tests and shared infrastructure

### TEST-01: Shared helpers, factories, and theory data

- [ ] Add missing direct prototype helpers where needed by callers, reusing existing paired helpers instead of duplicating them.

**Scope:** `test\Microsoft.IdentityModel.TestUtils`.

Add a `ValidationParameters` entry to the comparer registry in
`IdentityComparer.cs:150`. Its existing `ValidatedTokenType` comparer is not a
comparer for the `ValidatedToken` result payload.

Review the parameter factories in `Default.cs` and `NotDefault.cs`, the
`ValidateToken`/`ValidateTokenReplay` helpers in `TestUtilities.cs:375,394`, and the
legacy-only fields/properties in `TokenTheoryData.cs` and
`JWEDecompressionTheoryData.cs`. Check declared types, not property names.

After SRC-02, add counterparts for the five token-reader helpers in
`ValidationDelegates.cs:171-191` and the transformation helper at line 240.

**Acceptance:** Prototype callers can construct data, compare parameters/results,
and exercise the new hooks without depending on legacy parameter/result types.
Retain intentional conversion bridges and helpers already exercising both models.

### TEST-02: Result-payload contracts and concurrent claims access

- [ ] Add applicable prototype equivalents for the direct result-object tests.

**Locations:** `test\Microsoft.IdentityModel.Tokens.Tests\TokenValidationResultTests.cs:17,51`
(`GetSets` and `ClaimsIdentity_ConcurrencyTest`).

**Acceptance:** Cover the corresponding contracts on the generic result and
`ValidatedToken`, including concurrent claims-identity access. Test the new model's
actual contracts rather than copying legacy mutable-property assertions onto a
different result representation.

### TEST-03: Triage remaining legacy-only fixtures

- [ ] Classify the 214 test/data members with no direct counterpart identified, using the file-level scope below.

For each candidate, record an existing prototype counterpart, a focused follow-up
test/data action, or an intentional legacy-only rationale. The count includes
shared-helper/data candidates addressed by TEST-01; do not count those twice.

Prioritize claims-identity/AppContext behavior, SAML telemetry, crypto/roundtrip
scenarios, logging, and the Signed HTTP Request fixtures blocked on SHR integration.
Some JWT telemetry, actor-claim, ML-DSA, AAD-extension, and other scenarios already
have prototype coverage, so compare behavior before adding cases.

**Acceptance:** Each candidate has a recorded disposition. Add only genuinely
missing behavioral cases, with relevant production items as prerequisites.
Do not treat a different test name as evidence of missing coverage.

## Benchmark counterparts

### PERF-01: Clone/retry and telemetry variants

- [ ] Add paired prototype benchmarks for the unpaired variants in `ValidateTokenAsyncTests.cs`.

**Location:** `benchmark\Microsoft.IdentityModel.Benchmarks\ValidateTokenAsyncTests.cs:94,123,155,238,250,262`.

**Acceptance:** Cover modified clones, clone/retry success on the third and fifth
attempts, and applicable telemetry-disabled/enabled tracking variants. Use the
prototype's actual telemetry controls and document any intentionally unsupported
legacy-only variant. Preserve equivalent workloads and avoid duplicating the
already-paired ordinary success, non-clone retry, and claims-materialization cases.

### PERF-02: JWE and Signed HTTP Request validation

- [ ] Add prototype benchmark paths in `ValidateJWEAsyncTests.cs` and `ValidateSignedHttpRequestAsyncTests.cs`.

**Scope:** `benchmark\Microsoft.IdentityModel.Benchmarks`.

**Dependencies:** The Signed HTTP Request benchmark depends on SHR-03 and SHR-04;
the existing prototype JWE pipeline can be benchmarked independently.

**Acceptance:** Pair the JSON JWE-validation scenario and the Signed HTTP Request
validation scenario using new parameters/results, with equivalent tokens, keys,
configuration, and claims-materialization behavior.

### PERF-03: Actor claims and audience validation

- [ ] Add prototype pairs for actor-claim deserialization and list-based audience validation.

**Locations:** `benchmark\Microsoft.IdentityModel.Benchmarks\ActorClaimBenchmarks.cs`;
`benchmark\Microsoft.IdentityModel.Benchmarks\ValidatorBenchmarks.cs`.

**Acceptance:** Pair `ValidateNoActor`, `ValidateAct1`, `ValidateAct2_Degrade`, and
`ValidateActort_Legacy`, plus `ValidateAudience_WithList`. The enumerable-only
audience variant is legacy-specific because the new parameters use `IList<string>`;
document that distinction rather than fabricating an equivalent collection API.

## Legacy-only scope and completion

### SCOPE-01: Record intentional migration boundaries

- [ ] Document the disposition of legacy-only APIs that do not require duplicate prototype implementations.

The obsolete `System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler` has no
same-handler prototype validation pipeline; its migration target is
`JsonWebTokenHandler`. Do not duplicate its 28 legacy-containing members solely to
achieve same-class overload parity.

Also record migration paths for `ISecurityTokenValidator.ValidateToken`,
`SecurityTokenHandler` synchronous/`XmlReader` facades, and the corresponding SAML
reader/validation facades. Shared readers followed by asynchronous
`IResultBasedValidation` validation provide the normal replacement path.

**Acceptance:** Each intentional legacy-only surface has an explicit replacement
or compatibility rationale. Preserve existing compatibility tests and conversion
bridges. Already-paired core JWT/SAML validation, claims creation, ordinary
validators, AAD validators, and delegate-to-interface replacements are not reopened
as missing implementations.

### CLOSE-01: Close the migration inventory

- [ ] Reconcile the inventory after the production, supporting-code, and scope items are complete.

**Acceptance:** Every original missing/partial source member maps to a completed
counterpart or an explicitly reviewed migration decision. Remaining legacy uses
are classified rather than assumed to require duplicate APIs. For implementation
changes, update the appropriate `PublicAPI.Unshipped.txt` or
`InternalAPI.Unshipped.txt`, add focused behavioral tests, and run the relevant
existing build/test/analyzer checks. Verify paired benchmark workloads when their
counterparts are implemented. This checklist itself does not implement any gaps.

## Test/data candidate file scope

The following 44 files contain the 214 direct-counterpart review candidates for
TEST-03. Counts are legacy-containing members, not missing-test counts. Paths are
relative to `test`. The nine additional specifically flagged helper/result-test
members are described in TEST-01 and TEST-02.

| File | Candidate members |
| --- | ---: |
| `Microsoft.IdentityModel.Dpop.Tests\DpopProofCreatorOptions.cs` | 1 |
| `Microsoft.IdentityModel.JsonWebTokens.Tests\JsonWebTokenHandlerClaimsIdentityTests.cs` | 5 |
| `Microsoft.IdentityModel.JsonWebTokens.Tests\JsonWebTokenHandlerTelemetryTests.cs` | 1 |
| `Microsoft.IdentityModel.JsonWebTokens.Tests\JsonWebTokenHandlerTests.cs` | 30 |
| `Microsoft.IdentityModel.JsonWebTokens.Tests\JsonWebTokenTests.cs` | 2 |
| `Microsoft.IdentityModel.JsonWebTokens.Tests\JsonWebTokenTheoryData.cs` | 1 |
| `Microsoft.IdentityModel.JsonWebTokens.Tests\JwtTokenUtilitiesTests.cs` | 7 |
| `Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests\End2EndTests.cs` | 1 |
| `Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests\SignedHttpRequestCreationTests.cs` | 2 |
| `Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests\SignedHttpRequestE2ETests.cs` | 1 |
| `Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests\SignedHttpRequestHandlerPublic.cs` | 1 |
| `Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests\SignedHttpRequestTestUtils.cs` | 1 |
| `Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests\SignedHttpRequestValidationTests.cs` | 2 |
| `Microsoft.IdentityModel.Protocols.Tests\CrossTokenTests.cs` | 1 |
| `Microsoft.IdentityModel.Protocols.WsFederation.Tests\WsFederationMessageTests.cs` | 4 |
| `Microsoft.IdentityModel.TestUtils\Default.cs` | 7 |
| `Microsoft.IdentityModel.TestUtils\JWEDecompressionTheoryData.cs` | 1 |
| `Microsoft.IdentityModel.TestUtils\NotDefault.cs` | 2 |
| `Microsoft.IdentityModel.TestUtils\ReferenceSaml.cs` | 2 |
| `Microsoft.IdentityModel.TestUtils\TestUtilities.cs` | 2 |
| `Microsoft.IdentityModel.TestUtils\TokenTheoryData.cs` | 2 |
| `Microsoft.IdentityModel.Tokens.Saml.Tests\CreateTokenTheoryData.cs` | 1 |
| `Microsoft.IdentityModel.Tokens.Saml.Tests\RoundTripSamlTokenTests.cs` | 1 |
| `Microsoft.IdentityModel.Tokens.Saml.Tests\Saml2SecurityTokenHandlerTests.cs` | 9 |
| `Microsoft.IdentityModel.Tokens.Saml.Tests\SamlSecurityTokenHandlerTests.cs` | 10 |
| `Microsoft.IdentityModel.Tokens.Saml.Tests\SamlTestData.cs` | 1 |
| `Microsoft.IdentityModel.Tokens.Saml.Tests\Telemetry\SamlSignatureValidationTelemetryTests.cs` | 7 |
| `Microsoft.IdentityModel.Tokens.Saml.Tests\ValidateTheoryData.cs` | 2 |
| `Microsoft.IdentityModel.Tokens.Tests\AbstractVirtualsTests.cs` | 3 |
| `Microsoft.IdentityModel.Tokens.Tests\CaseSensitiveClaimsIdentityTests.cs` | 2 |
| `Microsoft.IdentityModel.Tokens.Tests\ClaimsIdentityFactoryTests.cs` | 2 |
| `Microsoft.IdentityModel.Tokens.Tests\CrossTokenTests.cs` | 2 |
| `Microsoft.IdentityModel.Tokens.Tests\CryptoExtensibilityTests.cs` | 2 |
| `Microsoft.IdentityModel.Tokens.Tests\IdentityComparerTests.cs` | 1 |
| `Microsoft.IdentityModel.Tokens.Tests\JsonWebKeySetTests.cs` | 2 |
| `Microsoft.IdentityModel.Tokens.Tests\JweUsingEchdTests.cs` | 8 |
| `Microsoft.IdentityModel.Tokens.Tests\MlDsaSecurityKeyTests.cs` | 5 |
| `Microsoft.IdentityModel.Tokens.Tests\MultiThreadingTests.cs` | 2 |
| `Microsoft.IdentityModel.Tokens.Tests\TamperedTokenTests.cs` | 2 |
| `Microsoft.IdentityModel.Tokens.Tests\Telemetry\SignatureValidationTelemetryTests.cs` | 11 |
| `Microsoft.IdentityModel.Tokens.Tests\Validation\LogValidationExceptionsTests.cs` | 44 |
| `Microsoft.IdentityModel.Tokens.Tests\Validation\SuccessValidationLoggingTests.cs` | 6 |
| `Microsoft.IdentityModel.Tokens.Tests\Validation\ValidatorsTests.cs` | 12 |
| `Microsoft.IdentityModel.Validators.Tests\MicrosoftIdentityIssuerValidatorTest.cs` | 3 |
