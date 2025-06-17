// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents a validation error when a <see cref="SecurityToken"/> type is not valid.
    /// If available, the invalid token type is stored in <see cref="InvalidTokenType"/>.
    /// </summary>
    public class TokenTypeValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TokenTypeValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="invalidTokenType"/>The token type that was not valid. Can be null if the token type is missing from the token.
        public TokenTypeValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            string? invalidTokenType)
            : this(messageDetail,
                  validationFailureType,
                  stackFrame,
                  invalidTokenType,
                  null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenTypeValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="invalidTokenType"/>The token type that was not valid. Can be null if the token type is missing from the token.
        /// <param name="innerException"/>If present, represents the exception that occurred during validation.
        public TokenTypeValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            string? invalidTokenType,
            Exception? innerException)
            : base(messageDetail, validationFailureType, stackFrame, innerException)
        {
            InvalidTokenType = invalidTokenType;
        }

        /// <summary>
        /// Get the <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an exception.</returns>
#pragma warning disable RS0016 // Add public types and members to the declared API
        public override Exception GetException()
#pragma warning restore RS0016 // Add public types and members to the declared API
        {
            if (Exception != null)
                return Exception;

            if (FailureType == ValidationFailureType.NullArgument)
                Exception = new ArgumentNullException(MessageDetail.Message);
            else
                Exception = new SecurityTokenInvalidTypeException(MessageDetail.Message, this, InnerException)
                {
                    InvalidType = InvalidTokenType
                };

            return Exception;
        }

        /// <summary>
        /// Creates a new instance of <see cref="TokenTypeValidationError"/> representing a null parameter.
        /// </summary>
        /// <param name="parameterName">The name of the parameter.</param>
        /// <param name="stackFrame">The stack frame where the error occurred.</param>
        /// <returns>A new <see cref="TokenTypeValidationError"/>.</returns>
        public static new TokenTypeValidationError NullParameter(string parameterName, StackFrame stackFrame) => new(
            MessageDetail.NullParameter(parameterName),
            ValidationFailureType.NullArgument,
            stackFrame,
            null);

        /// <summary>
        /// The token type that could not be validated.
        /// </summary>
        public string? InvalidTokenType { get; }
    }
}
#nullable restore
