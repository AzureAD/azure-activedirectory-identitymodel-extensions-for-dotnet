// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Dpop;

/// <summary>
/// Categorical reason for a DPoP proof validation failure.
/// </summary>
/// <remarks>
/// <para>
/// Each <see cref="DPoPValidationResult"/> with <see cref="DPoPValidationResult.IsValid"/>
/// set to <see langword="false"/> carries a <see cref="DPoPValidationError"/> whose
/// <see cref="DPoPValidationError.FailureType"/> is one of the static instances on this
/// type, so callers can branch on a stable identifier without parsing the human-readable
/// message.
/// </para>
/// <para>
/// This type is a small, extensible category enum implemented as a class with
/// <c>public static readonly</c> instances so additional reasons can be added over time
/// without breaking exhaustive <c>switch</c> consumers. Its shape mirrors
/// <c>Microsoft.IdentityModel.Tokens.Experimental.ValidationFailureType</c> so DPoP can
/// adopt the result-pattern surface in the future without re-shaping the public API.
/// </para>
/// </remarks>
public class DPoPValidationFailureType
{
    /// <summary>
    /// Gets the stable identifier for this failure category. Suitable for
    /// telemetry, log correlation, and SIEM grouping.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Initializes a new <see cref="DPoPValidationFailureType"/>.
    /// </summary>
    /// <param name="name">The stable identifier for this failure category.</param>
    protected DPoPValidationFailureType(string name) => Name = name;

    // -- Configuration / input shape (caller-side) -------------------------------------------------

    /// <summary>
    /// The validator was invoked without configured replay protection and the caller did not
    /// declare that replay protection is handled externally. Specifically,
    /// <see cref="DPoPValidationOptions.ExpectedNonce"/> and
    /// <see cref="DPoPValidationOptions.JtiReplayCache"/> are both <see langword="null"/>,
    /// and <see cref="DPoPValidationOptions.ReplayProtectionHandledExternally"/> is
    /// <see langword="false"/>. The validator fails closed to surface a silent loss of
    /// RFC 9449 §4.3 replay protection.
    /// </summary>
    public static readonly DPoPValidationFailureType ReplayProtectionNotConfigured =
        new("ReplayProtectionNotConfigured");

    /// <summary>
    /// A <see cref="DPoPValidationOptions"/> setting is missing or has an invalid value
    /// (for example, an empty <c>AllowedSigningAlgorithms</c> set or a whitespace-only
    /// <c>ExpectedNonce</c>).
    /// </summary>
    public static readonly DPoPValidationFailureType InvalidConfiguration =
        new("InvalidConfiguration");

    /// <summary>The DPoP proof input was null, empty, or whitespace.</summary>
    public static readonly DPoPValidationFailureType ProofMissing =
        new("ProofMissing");

    /// <summary>The DPoP proof exceeded <see cref="DPoPValidationOptions.MaxProofTokenSizeInBytes"/>.</summary>
    public static readonly DPoPValidationFailureType ProofExceedsMaxSize =
        new("ProofExceedsMaxSize");

    /// <summary>The access token argument was null, empty, or whitespace.</summary>
    public static readonly DPoPValidationFailureType AccessTokenMissing =
        new("AccessTokenMissing");

    /// <summary>The expected <c>cnf.jkt</c> thumbprint argument was null, empty, or whitespace.</summary>
    public static readonly DPoPValidationFailureType CnfJktMissing =
        new("CnfJktMissing");

    /// <summary>An unexpected exception was caught during validation.</summary>
    public static readonly DPoPValidationFailureType UnexpectedError =
        new("UnexpectedError");

    // -- Proof structure (RFC 9449 §4.3 steps 4-5) -------------------------------------------------

    /// <summary>The DPoP proof could not be parsed as a JWT, or its <c>jwk</c> header was malformed.</summary>
    public static readonly DPoPValidationFailureType ProofParseFailure =
        new("ProofParseFailure");

    /// <summary>The DPoP proof's <c>typ</c> header was not <c>dpop+jwt</c>.</summary>
    public static readonly DPoPValidationFailureType TokenTypeInvalid =
        new("TokenTypeInvalid");

    /// <summary>
    /// The DPoP proof's <c>alg</c> header was missing, was <c>none</c>, was a symmetric
    /// algorithm, or was not in <see cref="DPoPValidationOptions.AllowedSigningAlgorithms"/>.
    /// </summary>
    public static readonly DPoPValidationFailureType AlgorithmDisallowed =
        new("AlgorithmDisallowed");

    // -- JWK validation (step 6) --------------------------------------------------------------------

    /// <summary>The DPoP proof header did not contain a <c>jwk</c> parameter.</summary>
    public static readonly DPoPValidationFailureType JwkMissing =
        new("JwkMissing");

    /// <summary>
    /// The DPoP proof JWK was not acceptable: contained private key material, advertised a
    /// <c>kty</c>/<c>alg</c>/<c>crv</c> combination that does not match, had an RSA modulus
    /// outside the configured size bounds, or could not be converted to a supported asymmetric key.
    /// </summary>
    public static readonly DPoPValidationFailureType JwkInvalid =
        new("JwkInvalid");

    // -- Signature (step 7) -------------------------------------------------------------------------

    /// <summary>The DPoP proof signature did not verify with the proof's own JWK.</summary>
    public static readonly DPoPValidationFailureType SignatureInvalid =
        new("SignatureInvalid");

    // -- Method / URI binding (steps 8-9) -----------------------------------------------------------

    /// <summary>The DPoP proof was missing the <c>htm</c> (HTTP method) claim.</summary>
    public static readonly DPoPValidationFailureType HtmMissing =
        new("HtmMissing");

    /// <summary>The DPoP proof's <c>htm</c> claim did not match the request's HTTP method.</summary>
    public static readonly DPoPValidationFailureType HtmMismatch =
        new("HtmMismatch");

    /// <summary>The DPoP proof was missing the <c>htu</c> (HTTP URI) claim.</summary>
    public static readonly DPoPValidationFailureType HtuMissing =
        new("HtuMissing");

    /// <summary>The DPoP proof's <c>htu</c> claim did not match the request URI.</summary>
    public static readonly DPoPValidationFailureType HtuMismatch =
        new("HtuMismatch");

    // -- Freshness (step 10) ------------------------------------------------------------------------

    /// <summary>The DPoP proof was missing the <c>iat</c> (issued-at) claim.</summary>
    public static readonly DPoPValidationFailureType IatMissing =
        new("IatMissing");

    /// <summary>The DPoP proof's <c>iat</c> claim was older than the configured maximum lifetime.</summary>
    public static readonly DPoPValidationFailureType ProofExpired =
        new("ProofExpired");

    /// <summary>The DPoP proof's <c>iat</c> claim was in the future beyond the configured clock skew.</summary>
    public static readonly DPoPValidationFailureType ProofIssuedInFuture =
        new("ProofIssuedInFuture");

    // -- Identity & replay (step 11) ----------------------------------------------------------------

    /// <summary>The DPoP proof was missing the <c>jti</c> (JWT ID) claim.</summary>
    public static readonly DPoPValidationFailureType JtiMissing =
        new("JtiMissing");

    /// <summary>The DPoP proof's <c>jti</c> was found in <see cref="DPoPValidationOptions.JtiReplayCache"/>.</summary>
    public static readonly DPoPValidationFailureType JtiReplayDetected =
        new("JtiReplayDetected");

    // -- Binding (step 12) --------------------------------------------------------------------------

    /// <summary>The DPoP proof was missing the <c>ath</c> (access-token hash) claim.</summary>
    public static readonly DPoPValidationFailureType AthMissing =
        new("AthMissing");

    /// <summary>The DPoP proof's <c>ath</c> claim did not match the SHA-256 hash of the access token.</summary>
    public static readonly DPoPValidationFailureType AthMismatch =
        new("AthMismatch");

    /// <summary>The DPoP proof's JWK thumbprint did not match the expected <c>cnf.jkt</c> binding.</summary>
    public static readonly DPoPValidationFailureType CnfJktMismatch =
        new("CnfJktMismatch");

    // -- Nonce (RFC 9449 §8) ------------------------------------------------------------------------

    /// <summary>
    /// A nonce was required but the DPoP proof did not contain a <c>nonce</c> claim. The server
    /// should issue a fresh nonce in the <c>DPoP-Nonce</c> response header.
    /// </summary>
    public static readonly DPoPValidationFailureType NonceRequired =
        new("NonceRequired");

    /// <summary>
    /// The DPoP proof's <c>nonce</c> claim did not match <see cref="DPoPValidationOptions.ExpectedNonce"/>.
    /// The server should issue a fresh nonce in the <c>DPoP-Nonce</c> response header.
    /// </summary>
    public static readonly DPoPValidationFailureType NonceMismatch =
        new("NonceMismatch");
}
