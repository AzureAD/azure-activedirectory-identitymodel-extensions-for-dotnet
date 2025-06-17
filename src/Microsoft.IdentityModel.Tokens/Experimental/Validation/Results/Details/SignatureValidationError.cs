// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents a validation error when a <see cref="SecurityToken"/> signature is not valid.
    /// </summary>
    public class SignatureValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        public SignatureValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame)
            : this(messageDetail, validationFailureType, stackFrame, null, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="innerValidationError"/>If present, is the inner validation error that caused this signature validation error.
        /// <param name="innerException"/>If present, represents the exception that occurred during validation.
        public SignatureValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            ValidationError? innerValidationError,
            Exception? innerException) :
            base(messageDetail,
                validationFailureType,
                stackFrame,
                innerException)
        {
            InnerValidationError = innerValidationError;
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an exception.</returns>
        protected override Exception CreateException()
        {
            return new SecurityTokenInvalidSignatureException(MessageDetail.Message, this, InnerException);
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
                stackFrame,
                null,
                null); // innerValidationError

        /// <summary>
        /// The inner validation error that caused this signature validation error.
        /// </summary>
        public ValidationError? InnerValidationError { get; }
    }
}
#nullable restore
