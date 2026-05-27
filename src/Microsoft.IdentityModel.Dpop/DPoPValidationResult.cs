// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

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
    /// Gets an extracted nonce value from the DPoP proof, if present.
    /// </summary>
    public string Nonce { get; private set; }

    /// <summary>
    /// Gets the per-call failure detail (category, message, exception) when
    /// <see cref="IsValid"/> is <see langword="false"/>. <see langword="null"/> on success.
    /// </summary>
    public DPoPValidationError Error { get; private set; }

    /// <summary>
    /// Gets the RFC 9449 §7.1 error code for use in the <c>WWW-Authenticate</c> response header.
    /// </summary>
    /// <remarks>
    /// Per RFC 9449 §7.1, the error code is either <c>invalid_token</c> (for all proof and
    /// binding failures) or <c>use_dpop_nonce</c> (when a server nonce is required).
    /// This value drives the <c>error</c> parameter in the <c>WWW-Authenticate: DPoP</c> challenge.
    /// </remarks>
    public string ErrorCode { get; private set; }

    /// <summary>
    /// Gets a value indicating whether the server should issue a nonce challenge
    /// via the <c>DPoP-Nonce</c> response header.
    /// </summary>
    public bool IsNonceRequired { get; private set; }

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    public static DPoPValidationResult Success(string nonce = null) =>
        new()
        {
            IsValid = true,
            Nonce = nonce,
        };

    /// <summary>
    /// Creates a failed validation result with the <c>invalid_token</c> RFC 9449 §7.1 wire code
    /// and an explicit categorical failure reason.
    /// </summary>
    /// <param name="message">Human-readable error description.</param>
    /// <param name="failureType">The categorical failure reason.</param>
    /// <param name="exception">Optional inner exception.</param>
    public static DPoPValidationResult Failed(
        string message,
        DPoPValidationFailureType failureType,
        Exception exception = null) =>
        new()
        {
            IsValid = false,
            Error = new DPoPValidationError(failureType, message, exception),
            ErrorCode = DPoPErrorCodes.InvalidToken,
        };

    /// <summary>
    /// Creates a result indicating that a server nonce is required.
    /// Uses the <c>use_dpop_nonce</c> error code per RFC 9449 §7.1 and sets
    /// <see cref="IsNonceRequired"/> so the caller knows to issue a fresh <c>DPoP-Nonce</c> header.
    /// </summary>
    public static DPoPValidationResult NonceRequired() =>
        new()
        {
            IsValid = false,
            Error = new DPoPValidationError(DPoPValidationFailureType.NonceRequired, "DPoP nonce is required."),
            ErrorCode = DPoPErrorCodes.UseDPoPNonce,
            IsNonceRequired = true,
        };

    /// <summary>
    /// Creates a result indicating that the provided nonce did not match.
    /// Uses the <c>use_dpop_nonce</c> error code per RFC 9449 §7.1 so the server
    /// sends a fresh nonce in the response.
    /// </summary>
    public static DPoPValidationResult NonceValidationFailed() =>
        new()
        {
            IsValid = false,
            Error = new DPoPValidationError(DPoPValidationFailureType.NonceMismatch, "DPoP nonce validation failed."),
            ErrorCode = DPoPErrorCodes.UseDPoPNonce,
            IsNonceRequired = true,
        };
}
