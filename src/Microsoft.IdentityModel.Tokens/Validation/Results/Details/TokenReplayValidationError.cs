// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents an error that occurs when a token cannot be validated against being re-used or replay is detected.
    /// If available, the expiration time of the token that failed the validation is included.
    /// </summary>
    internal class TokenReplayValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IssuerSigningKeyValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" /> contains information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/> is the type of validation failure that occurred.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        /// <param name="expirationTime"/> is the expiration time of the token that failed the validation. Can be null if the token does not have an expiration time.
        /// <param name="innerException"/> if present, represents the exception that occurred during validation.
        public TokenReplayValidationError(
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

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an exception.</returns>
        protected override Exception CreateException()
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

            return base.CreateException();
        }

        /// <summary>
        /// Creates a new instance of <see cref="TokenReplayValidationError"/> representing a null parameter.
        /// </summary>
        /// <param name="parameterName">The name of the parameter.</param>
        /// <param name="stackFrame">The stack frame where the error occurred.</param>
        /// <returns>A new <see cref="TokenReplayValidationError"/>.</returns>
        public static new TokenReplayValidationError NullParameter(string parameterName, StackFrame stackFrame) => new(
            MessageDetail.NullParameter(parameterName),
            ValidationFailureType.NullArgument,
            typeof(SecurityTokenArgumentNullException),
            stackFrame,
            null);

        /// <summary>
        /// The expiration time of the token that failed the validation.
        /// </summary>
        public DateTime? ExpirationTime { get; }
    }
}
#nullable restore
