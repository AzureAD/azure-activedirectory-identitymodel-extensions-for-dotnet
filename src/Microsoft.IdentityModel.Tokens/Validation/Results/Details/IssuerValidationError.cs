// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal class IssuerValidationError : ValidationError
    {
        internal IssuerValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidIssuer,
            Exception? innerException = null)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, innerException)
        {
            InvalidIssuer = invalidIssuer;
        }

        internal string? InvalidIssuer { get; }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(SecurityTokenInvalidIssuerException))
            {
                SecurityTokenInvalidIssuerException exception = new(MessageDetail.Message, InnerException)
                {
                    InvalidIssuer = InvalidIssuer
                };
                exception.SetValidationError(this);

                return exception;
            }

            return base.GetException();
        }
    }
}
#nullable restore
