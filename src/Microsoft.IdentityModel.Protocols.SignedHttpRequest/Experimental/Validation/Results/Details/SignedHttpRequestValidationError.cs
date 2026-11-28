// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest
{
    /// <summary>Contains an SHR failure without constructing an exception until requested.</summary>
    public class SignedHttpRequestValidationError : ValidationError
    {
        /// <summary>Initializes an SHR validation error.</summary>
        /// <param name="messageDetail">The safely formatted diagnostic.</param>
        /// <param name="failureType">The failed validation stage.</param>
        /// <param name="stackFrame">The location of the failure.</param>
        /// <param name="claimName">The claim being validated, if applicable.</param>
        /// <param name="innerValidationError">The nested result-based error, if applicable.</param>
        /// <param name="innerException">An exception thrown by a callback or external operation.</param>
        public SignedHttpRequestValidationError(
            MessageDetail messageDetail,
            SignedHttpRequestValidationFailure failureType,
            StackFrame stackFrame,
            string? claimName = null,
            ValidationError? innerValidationError = null,
            Exception? innerException = null)
            : base(messageDetail, failureType, stackFrame, innerException)
        {
            ClaimName = claimName;
            InnerValidationError = innerValidationError;
        }

        /// <summary>Gets the claim associated with this failure.</summary>
        public string? ClaimName { get; }

        /// <summary>Gets the original nested validation error without materializing its exception.</summary>
        public ValidationError? InnerValidationError { get; }

        /// <inheritdoc/>
        public override Exception GetException()
        {
            if (Exception is not null)
                return Exception;

            Exception? inner = InnerValidationError?.GetException() ?? InnerException;
            if (FailureType == SignedHttpRequestValidationFailure.AccessToken)
                Exception = new SignedHttpRequestInvalidAtClaimException(Message, inner);
            else if (FailureType == SignedHttpRequestValidationFailure.ConfirmationClaim)
                Exception = new SignedHttpRequestInvalidCnfClaimException(Message, inner);
            else if (FailureType == SignedHttpRequestValidationFailure.PopKey)
                Exception = new SignedHttpRequestInvalidPopKeyException(Message, inner);
            else if (FailureType == SignedHttpRequestValidationFailure.Signature)
                Exception = new SignedHttpRequestInvalidSignatureException(Message, inner);
            else if (FailureType == SignedHttpRequestValidationFailure.Nonce)
                Exception = new SignedHttpRequestInvalidNonceClaimException(Message, inner);
            else if (FailureType == SignedHttpRequestValidationFailure.Claim)
                Exception = ClaimName switch
                {
                    SignedHttpRequestClaimTypes.Ts => new SignedHttpRequestInvalidTsClaimException(Message, inner),
                    SignedHttpRequestClaimTypes.M => new SignedHttpRequestInvalidMClaimException(Message, inner),
                    SignedHttpRequestClaimTypes.U => new SignedHttpRequestInvalidUClaimException(Message, inner),
                    SignedHttpRequestClaimTypes.P => new SignedHttpRequestInvalidPClaimException(Message, inner),
                    SignedHttpRequestClaimTypes.Q => new SignedHttpRequestInvalidQClaimException(Message, inner),
                    SignedHttpRequestClaimTypes.H => new SignedHttpRequestInvalidHClaimException(Message, inner),
                    SignedHttpRequestClaimTypes.B => new SignedHttpRequestInvalidBClaimException(Message, inner),
                    _ => new SignedHttpRequestValidationException(Message, inner)
                };
            else
                Exception = new SignedHttpRequestValidationException(Message, inner);

            return Exception;
        }
    }
}
