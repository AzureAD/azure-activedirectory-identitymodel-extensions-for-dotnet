// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents a validation error that occurs when a token's algorithm cannot be validated.
    /// If available, the invalid algorithm is stored in <see cref="InvalidAlgorithm"/>.
    /// </summary>
    internal class AlgorithmValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlgorithmValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" /> contains information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/> is the type of validation failure that occurred.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        /// <param name="invalidAlgorithm"/> is the algorithm that could not be validated. Can be null if the algorithm is missing from the token.
        /// <param name="innerException"/> if present, represents the exception that occurred during validation.
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

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
        protected override Exception CreateException()
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

            return base.CreateException();
        }

        /// <summary>
        /// The algorithm that could not be validated.
        /// </summary>
        public string? InvalidAlgorithm { get; }
    }
}
#nullable restore
