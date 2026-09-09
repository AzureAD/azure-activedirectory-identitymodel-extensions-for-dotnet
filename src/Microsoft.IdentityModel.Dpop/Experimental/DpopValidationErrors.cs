// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.Dpop.Experimental;

internal class DpopProofValidationError : ValidationError
{
    private static readonly ValidationFailureType s_dpopValidationFailed =
        new DpopValidationFailure("DpopProofValidationFailed");

    internal DpopProofValidationError(
        string message,
        DpopValidationFailureType dpopFailureType,
        Exception? innerException = null)
        : this(message, dpopFailureType, s_dpopValidationFailed, innerException)
    {
    }

    internal DpopProofValidationError(
        string message,
        DpopValidationFailureType dpopFailureType,
        ValidationFailureType validationFailureType,
        Exception? innerException)
        : base(
            new MessageDetail(message),
            validationFailureType,
            ValidationError.GetCurrentStackFrame(),
            innerException)
    {
        DpopFailureType = dpopFailureType;
    }

    internal DpopValidationFailureType DpopFailureType { get; }

    private sealed class DpopValidationFailure(string name)
        : ValidationFailureType(name)
    {
    }
}

internal sealed class DpopProofClaimValidationError : DpopProofValidationError
{
    internal DpopProofClaimValidationError(
        string claimName,
        string message,
        DpopValidationFailureType failureType,
        Exception? innerException = null)
        : base(message, failureType, innerException)
    {
        ClaimName = claimName;
    }

    internal string ClaimName { get; }
}

internal sealed class DpopCnfThumbprintMismatchError(
    string message,
    Exception? innerException = null)
    : DpopProofValidationError(
        message,
        DpopValidationFailureType.CnfJktMismatch,
        innerException)
{
}

internal sealed class DpopNonceRequiredError(
    string message,
    Exception? innerException = null)
    : DpopProofValidationError(
        message,
        DpopValidationFailureType.NonceRequired,
        innerException)
{
}
