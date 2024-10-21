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
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidIssuer)
            : base(messageDetail, ValidationFailureType.IssuerValidationFailed, exceptionType, stackFrame)
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

                return exception;
            }

            return base.GetException();
        }
    }
}
#nullable restore
