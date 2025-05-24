// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents an error that occurs when the issuer of a token cannot be validated.
    /// If available, the invalid issuer is stored in <see cref="InvalidIssuer"/>.
    /// </summary>
    internal class IssuerValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IssuerValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" /> contains information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/> is the type of validation failure that occurred.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        /// <param name="invalidIssuer"/> is the issuer that could not be validated. Can be null if the issuer is missing from the token.
        /// <param name="innerException"/> if present, represents the exception that occurred during validation.
        public IssuerValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidIssuer,
            Exception? innerException = null)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, innerException)
        {
            InvalidIssuer = invalidIssuer;
        }

        /// <summary>
        /// The issuer that could not be validated.
        /// </summary>
        public string? InvalidIssuer { get; }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an exception.</returns>
        protected override Exception CreateException()
        {
            if (ExceptionType == typeof(SecurityTokenInvalidIssuerException))
            {
                SecurityTokenInvalidIssuerException exception = new(MessageDetail.Message, InnerException)
                {
                    InvalidIssuer = InvalidIssuer
                };
                exception.SetValidationError(this);

                return exception;
            }

            return base.CreateException();
        }
    }
}
#nullable restore
