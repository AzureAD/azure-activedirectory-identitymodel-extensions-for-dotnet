// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics;
using System;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal class IssuerSigningKeyValidationError : ValidationError
    {
        internal IssuerSigningKeyValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            SecurityKey? invalidSigningKey,
            Exception? innerException = null)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, innerException)
        {
            InvalidSigningKey = invalidSigningKey;
        }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(SecurityTokenInvalidSigningKeyException))
            {
                SecurityTokenInvalidSigningKeyException? exception = new(MessageDetail.Message, InnerException)
                {
                    SigningKey = InvalidSigningKey
                };
                exception.SetValidationError(this);

                return exception;
            }

            return base.GetException();
        }

        internal static new IssuerSigningKeyValidationError NullParameter(string parameterName, StackFrame stackFrame) => new(
            MessageDetail.NullParameter(parameterName),
            ValidationFailureType.NullArgument,
            typeof(SecurityTokenArgumentNullException),
            stackFrame,
            null); // InvalidSigningKey

        protected SecurityKey? InvalidSigningKey { get; }
    }
}
#nullable restore
