// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal class SignatureValidationError : ValidationError
    {
        public SignatureValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            ValidationError? innerValidationError = null,
            Exception? innerException = null) :
            base(messageDetail, validationFailureType, exceptionType, stackFrame, innerException)
        {
            InnerValidationError = innerValidationError;
        }

        internal override Exception GetException()
        {
            var inner = InnerException ?? InnerValidationError?.GetException();

            if (ExceptionType == typeof(SecurityTokenInvalidSignatureException))
            {
                SecurityTokenInvalidSignatureException exception = new(MessageDetail.Message, inner);
                exception.SetValidationError(this);

                return exception;
            }
            else if (ExceptionType == typeof(SecurityTokenSignatureKeyNotFoundException))
            {
                SecurityTokenSignatureKeyNotFoundException exception = new(MessageDetail.Message, inner);
                exception.SetValidationError(this);

                return exception;
            }

            return base.GetException();
        }

        internal static new SignatureValidationError NullParameter(
            string parameterName, StackFrame stackFrame) => new(
                MessageDetail.NullParameter(parameterName),
                ValidationFailureType.NullArgument,
                typeof(SecurityTokenArgumentNullException),
                stackFrame,
                null); // innerValidationError

        protected internal ValidationError? InnerValidationError { get; }
    }
}
#nullable restore
