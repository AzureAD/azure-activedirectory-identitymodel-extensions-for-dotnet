# Experimental Signed HTTP Request validation

The existing `SignedHttpRequestHandler` has a parallel validation overload accepting
the existing `SignedHttpRequestValidationContext` and an explicit
`Microsoft.IdentityModel.Tokens.Experimental.ValidationParameters` argument. It returns
`ValidationResult<ValidatedSignedHttpRequest, ValidationError>`.
These result-based APIs may change. Both overloads share the existing SHR context and
settings. The legacy delegates and `SignedHttpRequestValidationResult` remain unchanged.

## Usage

Given a compact signed request (`encodedShr`), the incoming `HttpRequestData`
(`request`), a trusted access-token signing key (`trustedSigningKey`), and a
`CancellationToken` (`cancellationToken`):

```csharp
using Microsoft.IdentityModel.Protocols.SignedHttpRequest;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

var accessTokenParameters = new ValidationParameters();
accessTokenParameters.SigningKeys.Add(trustedSigningKey);
accessTokenParameters.ValidIssuers.Add("https://issuer.example");
accessTokenParameters.ValidAudiences.Add("https://api.example");

var context = new SignedHttpRequestValidationContext(
    encodedShr,
    request,
    new TokenValidationParameters(),
    new SignedHttpRequestValidationParameters(),
    new CallContext());

var result = await new SignedHttpRequestHandler()
    .ValidateSignedHttpRequestAsync(context, accessTokenParameters, cancellationToken);

if (!result.Succeeded)
{
    // Error inspection does not require constructing an exception.
    Console.WriteLine(result.Error!.Message);
    return;
}

var validatedShr = result.Result!;
var accessTokenIdentity = validatedShr.AccessTokenValidationResult.ClaimsIdentity;
var verifiedRequestToken = validatedShr.ValidatedToken;
```

The explicit experimental parameters and the context's call context are passed to the configured
`TokenHandler` without converting to `TokenValidationParameters`. A custom token handler
must implement the experimental `ValidateTokenAsync` overload. The context's
`AccessTokenValidationParameters` property is used only by the legacy overload;
the result-based overload uses its explicit `ValidationParameters` argument instead.

## Policies and extension points

By default, validation requires a signed JWS, a valid embedded access token, a resolved
confirmation key, a valid SHR signature, and matching `ts`, `m`, `u`, and `p` claims.
The SHR lifetime defaults to five minutes. Timestamp validation shares the access-token
validation clock, with no additional clock-skew or future-timestamp policy.
Query, header, and body validation are opt-in through `ValidateQ`, `ValidateH`, and
`ValidateB`. `ValidatePresentClaims` and `ClaimsToValidateWhenPresent` allow selected
optional claims to be checked when present. Path comparison is case-sensitive by default,
while accepting equivalent hexadecimal casing within percent-encoded triplets.

Confirmation-key resolution supports asymmetric `jwk`, encrypted symmetric `jwe`,
allowlisted `jku`, and `kid` references to the outer SHR confirmation claim.
JKU retrieval is disabled by default and requires an explicit host allowlist when enabled;
HTTPS is required unless explicitly disabled.

The shared SHR settings expose result-returning interfaces alongside the legacy delegates:

| Property | Interface |
|---|---|
| `PopKeyResolver` | `IPopKeyResolver` |
| `PopKeyResolverFromKeyId` | `IPopKeyResolverFromKeyId` |
| `CnfDecryptionKeysResolver` | `ICnfDecryptionKeysResolver` |
| `SignatureValidator` | `ISignedHttpRequestSignatureValidator` |
| `NonceValidator` | `INonceValidator` |
| `ReplayValidator` | `IReplayValidator` |

All interfaces are in `Microsoft.IdentityModel.Protocols.SignedHttpRequest`.
Callbacks receive the shared SHR context and cancellation token. Return a successful
value or a `ValidationError`; nonce and replay validators must return `true` on success.
An error returned by a callback is preserved. Callback exceptions, null successes, and
uninitialized results are rejected. Nonce and replay validation are not performed unless
their callbacks are configured; applications requiring replay protection must provide it.
Legacy validation overrides and delegates are not adapters for the experimental pipeline.

Expected validation failures are returned rather than thrown. SHR-specific errors expose
a failure stage and, where applicable, `ClaimName` or `InnerValidationError`. Call
`GetException()` only when an exception is needed; it lazily creates the corresponding
legacy SHR exception. Requested cancellation propagates as `OperationCanceledException`.
