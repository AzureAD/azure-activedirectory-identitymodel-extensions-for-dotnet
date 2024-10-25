// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal class TokenTypeValidationError : ValidationError
    {
        protected string? _invalidTokenType;

        internal TokenTypeValidationError(
            MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidTokenType)
            : base(messageDetail, ValidationFailureType.TokenTypeValidationFailed, exceptionType, stackFrame)
        {
            _invalidTokenType = invalidTokenType;
        }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(SecurityTokenInvalidTypeException))
            {
                SecurityTokenInvalidTypeException exception = new(MessageDetail.Message, InnerException)
                {
                    InvalidType = _invalidTokenType
                };

                return exception;
            }

            return base.GetException();
        }
    }
}
#nullable restore
