// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal class TokenReplayValidationError : ValidationError
    {
        internal TokenReplayValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            DateTime? expirationTime,
            Exception? innerException = null)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, innerException)
        {
            ExpirationTime = expirationTime;
        }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(SecurityTokenReplayDetectedException))
            {
                SecurityTokenReplayDetectedException exception = new(MessageDetail.Message, InnerException);
                exception.SetValidationError(this);

                return exception;
            }
            else if (ExceptionType == typeof(SecurityTokenReplayAddFailedException))
            {
                SecurityTokenReplayAddFailedException exception = new(MessageDetail.Message, InnerException);
                exception.SetValidationError(this);

                return exception;
            }

            return base.GetException();
        }

        internal static new TokenReplayValidationError NullParameter(string parameterName, StackFrame stackFrame) => new(
            MessageDetail.NullParameter(parameterName),
            ValidationFailureType.NullArgument,
            typeof(SecurityTokenArgumentNullException),
            stackFrame,
            null);

        protected DateTime? ExpirationTime { get; }
    }
}
#nullable restore
