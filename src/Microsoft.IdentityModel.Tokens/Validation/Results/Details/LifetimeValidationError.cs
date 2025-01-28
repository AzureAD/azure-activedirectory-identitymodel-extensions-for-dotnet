// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents an error that occurs when a token's lifetime cannot be validated.
    /// If available, the not before and expires values are stored in <see cref="NotBefore"/> and <see cref="Expires"/>.
    /// </summary>
    internal class LifetimeValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="LifetimeValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" /> contains information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/> is the type of validation failure that occurred.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        /// <param name="notBefore"/> is the date from which the token is valid. Can be null if the token does not contain a not before claim.
        /// <param name="expires"/> is the date at which the token expires. Can be null if the token does not contain an expires claim.
        /// <param name="innerException"/> if present, represents the exception that occurred during validation.
        public LifetimeValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            DateTime? notBefore,
            DateTime? expires,
            Exception? innerException = null)

            : base(messageDetail, validationFailureType, exceptionType, stackFrame, innerException)
        {
            NotBefore = notBefore;
            Expires = expires;
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
        protected override Exception CreateException()
        {
            if (ExceptionType == typeof(SecurityTokenNoExpirationException))
            {
                var exception = new SecurityTokenNoExpirationException(MessageDetail.Message, InnerException);
                exception.SetValidationError(this);
                return exception;
            }
            else if (ExceptionType == typeof(SecurityTokenInvalidLifetimeException))
            {
                var exception = new SecurityTokenInvalidLifetimeException(MessageDetail.Message, InnerException)
                {
                    NotBefore = NotBefore,
                    Expires = Expires
                };
                exception.SetValidationError(this);
                return exception;
            }
            else if (ExceptionType == typeof(SecurityTokenNotYetValidException))
            {
                var exception = new SecurityTokenNotYetValidException(MessageDetail.Message, InnerException)
                {
                    NotBefore = (DateTime)NotBefore!
                };
                exception.SetValidationError(this);
                return exception;
            }
            else if (ExceptionType == typeof(SecurityTokenExpiredException))
            {
                var exception = new SecurityTokenExpiredException(MessageDetail.Message, InnerException)
                {
                    Expires = (DateTime)Expires!
                };
                exception.SetValidationError(this);
                return exception;
            }
            else
                return base.CreateException(ExceptionType, null);
        }

        /// <summary>
        /// The date from which the token is valid.
        /// </summary>
        public DateTime? NotBefore { get; }

        /// <summary>
        /// The date at which the token expires.
        /// </summary>
        public DateTime? Expires { get; }
    }
}
#nullable restore
