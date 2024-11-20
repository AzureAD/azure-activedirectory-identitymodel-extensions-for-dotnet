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
            Type exceptionType,
            StackFrame stackFrame,
            SecurityKey? invalidSigningKey,
            ValidationFailureType? failureType = null,
            Exception? innerException = null)
            : base(messageDetail, exceptionType, stackFrame, failureType ?? ValidationFailureType.SigningKeyValidationFailed, innerException)
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
            typeof(SecurityTokenArgumentNullException),
            stackFrame,
            null, // InvalidSigningKey
            ValidationFailureType.NullArgument);

        protected SecurityKey? InvalidSigningKey { get; set; }
    }
}
#nullable restore
