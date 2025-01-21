// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents an error that occurs when the token's audience cannot be validated.
    /// If available, the invalid audiences from the token are stored in <see cref="TokenAudiences"/>
    /// and the allowed audiences are stored in <see cref="ValidAudiences"/>.
    /// </summary>
    internal class AudienceValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IssuerSigningKeyValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" /> contains information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/> is the type of validation failure that occurred.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        /// <param name="tokenAudiences"/> are the audiences that were in the token. Can be null if no audiences were found in the token.
        /// <param name="validAudiences"/> are the audiences that were expected. Can be null if no valid audiences were provided in the validation parameters.
        /// <param name="innerException"/> if present, represents the exception that occurred during validation.
        public AudienceValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            IList<string>? tokenAudiences,
            IList<string>? validAudiences,
            Exception? innerException = null)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, innerException)
        {
            TokenAudiences = tokenAudiences;
            ValidAudiences = validAudiences;
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
        protected override Exception CreateException()
        {
            if (ExceptionType == typeof(SecurityTokenInvalidAudienceException))
            {
                var exception = new SecurityTokenInvalidAudienceException(MessageDetail.Message, InnerException) { InvalidAudience = Utility.SerializeAsSingleCommaDelimitedString(TokenAudiences) };
                exception.SetValidationError(this);

                return exception;
            }

            return base.CreateException(ExceptionType, null);
        }

        /// <summary>
        /// The audiences that were in the token.
        /// </summary>
        public IList<string>? TokenAudiences { get; }

        /// <summary>
        /// The audiences that were expected.
        /// </summary>
        public IList<string>? ValidAudiences { get; }
    }
}
#nullable restore
