// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest.Experimental;

internal sealed class SignedHttpRequestValidationError : ValidationError
{
    internal SignedHttpRequestValidationError(
        MessageDetail messageDetail,
        ValidationFailureType validationFailure,
        StackFrame stackFrame,
        Exception innerException = null)
        : base(messageDetail, validationFailure, stackFrame, innerException)
    {
    }

    public override Exception GetException()
    {
        if (Exception is not null)
            return Exception;

        if (FailureType == SignedHttpRequestValidationFailure.InvalidAtClaim)
            Exception = new SignedHttpRequestInvalidAtClaimException(Message, InnerException);
        else if (FailureType == SignedHttpRequestValidationFailure.InvalidCnfClaim)
            Exception = new SignedHttpRequestInvalidCnfClaimException(Message, InnerException);
        else if (FailureType == SignedHttpRequestValidationFailure.InvalidPopKey)
            Exception = new SignedHttpRequestInvalidPopKeyException(Message, InnerException);
        else if (FailureType == SignedHttpRequestValidationFailure.InvalidSignature)
            Exception = new SignedHttpRequestInvalidSignatureException(Message, InnerException);
        else if (FailureType == SignedHttpRequestValidationFailure.InvalidNonceClaim)
            Exception = new SignedHttpRequestInvalidNonceClaimException(Message, InnerException);
        else if (FailureType == SignedHttpRequestValidationFailure.InvalidTsClaim)
            Exception = new SignedHttpRequestInvalidTsClaimException(Message, InnerException);
        else if (FailureType == SignedHttpRequestValidationFailure.InvalidMClaim)
            Exception = new SignedHttpRequestInvalidMClaimException(Message, InnerException);
        else if (FailureType == SignedHttpRequestValidationFailure.InvalidUClaim)
            Exception = new SignedHttpRequestInvalidUClaimException(Message, InnerException);
        else if (FailureType == SignedHttpRequestValidationFailure.InvalidPClaim)
            Exception = new SignedHttpRequestInvalidPClaimException(Message, InnerException);
        else if (FailureType == SignedHttpRequestValidationFailure.InvalidQClaim)
            Exception = new SignedHttpRequestInvalidQClaimException(Message, InnerException);
        else if (FailureType == SignedHttpRequestValidationFailure.InvalidHClaim)
            Exception = new SignedHttpRequestInvalidHClaimException(Message, InnerException);
        else if (FailureType == SignedHttpRequestValidationFailure.InvalidBClaim)
            Exception = new SignedHttpRequestInvalidBClaimException(Message, InnerException);
        else if (FailureType == SignedHttpRequestValidationFailure.CreationFailed)
            Exception = new SignedHttpRequestCreationException(Message, InnerException);
        else
            Exception = new SignedHttpRequestValidationException(Message, InnerException);

        return Exception;
    }
}

internal sealed class SignedHttpRequestValidationFailure : ValidationFailureType
{
    private SignedHttpRequestValidationFailure(string name) : base(name)
    {
    }

    internal static readonly SignedHttpRequestValidationFailure InvalidAtClaim = new(nameof(InvalidAtClaim));
    internal static readonly SignedHttpRequestValidationFailure InvalidCnfClaim = new(nameof(InvalidCnfClaim));
    internal static readonly SignedHttpRequestValidationFailure InvalidPopKey = new(nameof(InvalidPopKey));
    internal static readonly SignedHttpRequestValidationFailure InvalidSignature = new(nameof(InvalidSignature));
    internal static readonly SignedHttpRequestValidationFailure InvalidNonceClaim = new(nameof(InvalidNonceClaim));
    internal static readonly SignedHttpRequestValidationFailure InvalidTsClaim = new(nameof(InvalidTsClaim));
    internal static readonly SignedHttpRequestValidationFailure InvalidMClaim = new(nameof(InvalidMClaim));
    internal static readonly SignedHttpRequestValidationFailure InvalidUClaim = new(nameof(InvalidUClaim));
    internal static readonly SignedHttpRequestValidationFailure InvalidPClaim = new(nameof(InvalidPClaim));
    internal static readonly SignedHttpRequestValidationFailure InvalidQClaim = new(nameof(InvalidQClaim));
    internal static readonly SignedHttpRequestValidationFailure InvalidHClaim = new(nameof(InvalidHClaim));
    internal static readonly SignedHttpRequestValidationFailure InvalidBClaim = new(nameof(InvalidBClaim));
    internal static readonly SignedHttpRequestValidationFailure CreationFailed = new(nameof(CreationFailed));
    internal static readonly SignedHttpRequestValidationFailure ValidationFailed = new(nameof(ValidationFailed));
}
