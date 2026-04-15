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
    /// Gets the exception that caused the validation failure, if any.
    /// Only set when an unexpected exception occurs during validation.
    /// </summary>
    public System.Exception Exception { get; private set; }

    /// <summary>
    /// Gets the computed base64url-encoded SHA-256 JWK thumbprint (RFC 7638) of the proof's public key.
    /// Only set on successful validation.
    /// </summary>
    public string JwkThumbprint { get; private set; }

    /// <summary>
    /// Gets a value indicating whether the server should issue a nonce challenge
    /// via the <c>DPoP-Nonce</c> response header.
    /// </summary>
    public bool IsNonceRequired { get; private set; }

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    public static DPoPValidationResult Success(string jwkThumbprint) =>
        new()
        {
            IsValid = true,
            JwkThumbprint = jwkThumbprint,
        };

    /// <summary>
    /// Creates a failed validation result.
    /// </summary>
    public static DPoPValidationResult Failed(string error, System.Exception exception = null) =>
        new()
        {
            IsValid = false,
            Error = error,
            Exception = exception,
        };

    /// <summary>
    /// Creates a result indicating that a server nonce is required.
    /// </summary>
    public static DPoPValidationResult NonceRequired() =>
        new()
        {
            IsValid = false,
            Error = "DPoP nonce is required.",
            IsNonceRequired = true,
        };
}
