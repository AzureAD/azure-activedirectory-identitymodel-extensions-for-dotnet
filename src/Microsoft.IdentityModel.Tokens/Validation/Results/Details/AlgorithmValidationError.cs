// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal class AlgorithmValidationError : ValidationError
    {
        protected string? _invalidAlgorithm;

        public AlgorithmValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidAlgorithm,
            Exception? innerException = null) :
            base(messageDetail, validationFailureType, exceptionType, stackFrame, innerException)
        {
            _invalidAlgorithm = invalidAlgorithm;
        }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(SecurityTokenInvalidAlgorithmException))
            {
                SecurityTokenInvalidAlgorithmException exception = new(MessageDetail.Message, InnerException)
                {
                    InvalidAlgorithm = _invalidAlgorithm
                };

                return exception;
            }

            return base.GetException();
        }

        internal string? InvalidAlgorithm => _invalidAlgorithm;
    }
}
#nullable restore
