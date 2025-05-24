// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents an error that occurs when the token's signature cannot be validated.
    /// </summary>
    internal class SignatureValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" /> contains information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/> is the type of validation failure that occurred.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        /// <param name="innerValidationError"/> if present, is the inner validation error that caused this signature validation error.
        /// <param name="innerException"/> if present, represents the exception that occurred during validation.
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

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an exception.</returns>
        protected override Exception CreateException()
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

            return base.CreateException();
        }

        /// <summary>
        /// Creates a new instance of <see cref="SignatureValidationError"/> representing a null parameter.
        /// </summary>
        /// <param name="parameterName">The name of the parameter.</param>
        /// <param name="stackFrame">The stack frame where the error occurred.</param>
        /// <returns>A new <see cref="SignatureValidationError"/>.</returns>
        public static new SignatureValidationError NullParameter(
            string parameterName, StackFrame stackFrame) => new(
                MessageDetail.NullParameter(parameterName),
                ValidationFailureType.NullArgument,
                typeof(SecurityTokenArgumentNullException),
                stackFrame,
                null); // innerValidationError

        /// <summary>
        /// The inner validation error that caused this signature validation error.
        /// </summary>
        public ValidationError? InnerValidationError { get; }
    }
}
#nullable restore
