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
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidTokenType,
            Exception? innerException = null)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, innerException)
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
            ValidationFailureType.NullArgument,
            typeof(SecurityTokenArgumentNullException),
            stackFrame,
            null); // invalidTokenType

        protected string? InvalidTokenType { get; }
    }
}
#nullable restore
