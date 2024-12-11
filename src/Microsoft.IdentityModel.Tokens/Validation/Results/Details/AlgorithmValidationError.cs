// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal class AlgorithmValidationError : ValidationError
    {
        public AlgorithmValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidAlgorithm,
            Exception? innerException = null) :
            base(messageDetail, validationFailureType, exceptionType, stackFrame, innerException)
        {
            InvalidAlgorithm = invalidAlgorithm;
        }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(SecurityTokenInvalidAlgorithmException))
            {
                SecurityTokenInvalidAlgorithmException exception = new(MessageDetail.Message, InnerException)
                {
                    InvalidAlgorithm = InvalidAlgorithm
                };
                exception.SetValidationError(this);

                return exception;
            }

            return base.GetException();
        }

        protected string? InvalidAlgorithm { get; }
    }
}
#nullable restore
