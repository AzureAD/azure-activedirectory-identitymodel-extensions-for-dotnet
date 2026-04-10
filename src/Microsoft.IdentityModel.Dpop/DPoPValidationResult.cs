// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Dpop;

/// <summary>
/// Represents the result of server-side DPoP proof validation.
/// Use the static factory methods to create instances.
/// </summary>
public sealed class DPoPValidationResult
{
    private DPoPValidationResult()
    {
    }

    /// <summary>
    /// Gets a value indicating whether the DPoP proof is valid.
    /// </summary>
    public bool IsValid { get; private set; }

    /// <summary>
    /// Gets the human-readable error description if the proof is invalid.
    /// </summary>
    public string Error { get; private set; }

    /// <summary>
    /// Gets the RFC 9449 error code (e.g., "invalid_dpop_proof", "use_dpop_nonce").
    /// </summary>
    public string ErrorCode { get; private set; }

    /// <summary>
    /// Gets the computed base64url-encoded SHA-256 JWK thumbprint (RFC 7638) of the proof's public key.
    /// Only set on successful validation.
    /// </summary>
    public string JwkThumbprint { get; private set; }

    /// <summary>
    /// Gets the extracted public key from the DPoP proof's <c>jwk</c> header parameter.
    /// Only set on successful validation.
    /// </summary>
    public JsonWebKey ProofKey { get; private set; }

    /// <summary>
    /// Gets a value indicating whether the server should issue a nonce challenge
    /// via the <c>DPoP-Nonce</c> response header.
    /// </summary>
    public bool IsNonceRequired { get; private set; }

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    /// <param name="jwkThumbprint">The base64url-encoded SHA-256 JWK thumbprint of the proof's public key.</param>
    /// <param name="proofKey">The extracted public key from the proof.</param>
    /// <returns>A successful <see cref="DPoPValidationResult"/>.</returns>
    public static DPoPValidationResult Success(string jwkThumbprint, JsonWebKey proofKey) =>
        new()
        {
            IsValid = true,
            JwkThumbprint = jwkThumbprint,
            ProofKey = proofKey,
        };

    /// <summary>
    /// Creates a failed validation result.
    /// </summary>
    /// <param name="error">A human-readable error description.</param>
    /// <param name="errorCode">The RFC 9449 error code.</param>
    /// <returns>A failed <see cref="DPoPValidationResult"/>.</returns>
    public static DPoPValidationResult Failed(string error, string errorCode) =>
        new()
        {
            IsValid = false,
            Error = error,
            ErrorCode = errorCode,
        };

    /// <summary>
    /// Creates a result indicating that a server nonce is required.
    /// The caller should respond with a <c>DPoP-Nonce</c> header.
    /// </summary>
    /// <returns>A <see cref="DPoPValidationResult"/> indicating nonce is required.</returns>
    public static DPoPValidationResult NonceRequired() =>
        new()
        {
            IsValid = false,
            Error = "DPoP nonce is required.",
            ErrorCode = DPoPErrorCodes.UseDPoPNonce,
            IsNonceRequired = true,
        };
}
