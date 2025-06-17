// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents a validation error when a <see cref="SecurityToken"/> audience is not valid.
    /// If available, the audiences from the <see cref="SecurityToken"/> are stored in <see cref="TokenAudiences"/>.
    /// Valid audiences are stored in <see cref="ValidAudiences"/>.
    /// </summary>
    public class AudienceValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of <see cref="AudienceValidationError"/>.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="tokenAudiences"/>The audiences that were in the <see cref="SecurityToken"/>. Can be null if no audiences were found in the token.
        /// <param name="validAudiences"/>The audiences that were expected. Can be null if no valid audiences were provided in the validation parameters.
        public AudienceValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            IList<string>? tokenAudiences,
            IList<string>? validAudiences)
            : this(messageDetail,
                  validationFailureType,
                  stackFrame,
                  tokenAudiences,
                  validAudiences,
                  null)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="AudienceValidationError"/>.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="tokenAudiences"/>The audiences that were in the <see cref="SecurityToken"/>. Can be null if no audiences were found in the token.
        /// <param name="validAudiences"/>The audiences that were expected. Can be null if no valid audiences were provided in the validation parameters.
        /// <param name="innerException"/>If present, represents the exception that occurred during validation.
        public AudienceValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            IList<string>? tokenAudiences,
            IList<string>? validAudiences,
            Exception? innerException)
            : base(messageDetail, validationFailureType, stackFrame, innerException)
        {
            TokenAudiences = tokenAudiences;
            ValidAudiences = validAudiences;
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
#pragma warning disable RS0016 // Add public types and members to the declared API
        public override Exception GetException()
#pragma warning restore RS0016 // Add public types and members to the declared API
        {
            if (FailureType == ValidationFailureType.NullArgument)
            {
                return new ArgumentNullException(MessageDetail.Message);
            }

            if (TokenAudiences == null)
                return new SecurityTokenInvalidAudienceException(MessageDetail.Message, this, InnerException);

            return new SecurityTokenInvalidAudienceException(
                    MessageDetail.Message,
                    this,
                    InnerException)
            {
                InvalidAudience = Utility.SerializeAsSingleCommaDelimitedString(TokenAudiences)
            };
        }

        /// <summary>
        /// Creates a new instance of <see cref="AudienceValidationError"/> representing a null parameter.
        /// </summary>
        /// <param name="parameterName">The name of the parameter.</param>
        /// <param name="stackFrame">The stack frame where the error occurred.</param>
        /// <returns>A new <see cref="AudienceValidationError"/>.</returns>
        public static new AudienceValidationError NullParameter(string parameterName, StackFrame stackFrame) => new(
            MessageDetail.NullParameter(parameterName),
            ValidationFailureType.NullArgument,
            stackFrame,
            null, // TokenAudiences
            null); // ValidAudiences

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
