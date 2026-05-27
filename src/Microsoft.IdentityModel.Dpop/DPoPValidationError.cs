// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace Microsoft.IdentityModel.Dpop;

/// <summary>
/// Per-call detail describing a DPoP proof validation failure. Pairs a categorical
/// <see cref="DPoPValidationFailureType"/> with the specific human-readable message
/// and any inner exception captured during validation.
/// </summary>
/// <remarks>
/// <see cref="DPoPValidationFailureType"/> is a singleton category (suitable for telemetry
/// and SIEM correlation); <see cref="DPoPValidationError"/> is created fresh per failure and
/// carries the specifics — the offending value in the message, the captured exception, etc.
/// </remarks>
public sealed class DPoPValidationError
{
    /// <summary>
    /// Gets the categorical failure reason.
    /// </summary>
    public DPoPValidationFailureType FailureType { get; }

    /// <summary>
    /// Gets the human-readable error description.
    /// </summary>
    public string Message { get; }

    /// <summary>
    /// Gets the exception that caused the validation failure, if any.
    /// Only populated when an exception was caught during validation.
    /// </summary>
    public Exception Exception { get; }

    /// <summary>
    /// Initializes a new <see cref="DPoPValidationError"/>.
    /// </summary>
    /// <param name="failureType">The categorical failure reason.</param>
    /// <param name="message">Human-readable description.</param>
    /// <param name="exception">Optional inner exception.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="failureType"/> is null.</exception>
    public DPoPValidationError(DPoPValidationFailureType failureType, string message, Exception exception = null)
    {
        FailureType = failureType ?? throw new ArgumentNullException(nameof(failureType));
        Message = message;
        Exception = exception;
    }
}
