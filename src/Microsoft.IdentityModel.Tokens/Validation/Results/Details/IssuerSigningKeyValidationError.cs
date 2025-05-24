// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics;
using System;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents a validation error that occurs when the issuer signing key cannot be validated.
    /// If available, the invalid signing key is stored in <see cref="InvalidSigningKey"/>.
    /// </summary>
    internal class IssuerSigningKeyValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IssuerSigningKeyValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" /> contains information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/> is the type of validation failure that occurred.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        /// <param name="invalidSigningKey"/> is the signing key that could not be validated. Can be null if the signing key for the token is missing.
        /// <param name="innerException"/> if present, represents the exception that occurred during validation.
        public IssuerSigningKeyValidationError(
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

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
        protected override Exception CreateException()
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

            return base.CreateException();
        }

        /// <summary>
        /// Creates a new instance of <see cref="IssuerSigningKeyValidationError"/> representing a null parameter.
        /// </summary>
        /// <param name="parameterName">The name of the parameter.</param>
        /// <param name="stackFrame">The stack frame where the error occurred.</param>
        /// <returns>A new <see cref="IssuerSigningKeyValidationError"/>.</returns>
        public static new IssuerSigningKeyValidationError NullParameter(string parameterName, StackFrame stackFrame) => new(
            MessageDetail.NullParameter(parameterName),
            ValidationFailureType.NullArgument,
            typeof(SecurityTokenArgumentNullException),
            stackFrame,
            null); // InvalidSigningKey

        /// <summary>
        /// The signing key that was found invalid.
        /// </summary>
        protected SecurityKey? InvalidSigningKey { get; }
    }
}
#nullable restore
