// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal class TokenTypeValidationError : ValidationError
    {
        internal TokenTypeValidationError(
            MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidTokenType,
            ValidationFailureType? validationFailureType = null,
            Exception? innerException = null)
            : base(messageDetail, exceptionType, stackFrame, validationFailureType ?? ValidationFailureType.TokenTypeValidationFailed, innerException)
        {
            InvalidTokenType = invalidTokenType;
        }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(SecurityTokenInvalidTypeException))
            {
                SecurityTokenInvalidTypeException exception = new(MessageDetail.Message, InnerException)
                {
                    InvalidType = InvalidTokenType
                };
                exception.SetValidationError(this);

                return exception;
            }

            return base.GetException();
        }

        internal static new TokenTypeValidationError NullParameter(string parameterName, StackFrame stackFrame) => new(
            MessageDetail.NullParameter(parameterName),
            typeof(SecurityTokenArgumentNullException),
            stackFrame,
            null, // invalidTokenType
            ValidationFailureType.NullArgument);

        protected string? InvalidTokenType { get; set; }
    }
}
#nullable restore
