// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics;
using System;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents a validation error when the <see cref="SecurityToken.SecurityKey"/> is not valid.
    /// If available, the invalid signing key is stored in <see cref="InvalidSigningKey"/>.
    /// </summary>
    public class IssuerSigningKeyValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IssuerSigningKeyValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="invalidSigningKey"/>The <see cref="SecurityKey"/> that was not valid. Can be null if <see cref="SecurityToken.SigningKey"/> is missing.
        public IssuerSigningKeyValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            SecurityKey? invalidSigningKey)
            : this(messageDetail,
                  validationFailureType,
                  stackFrame,
                  invalidSigningKey,
                  null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="IssuerSigningKeyValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="invalidSigningKey"/>The <see cref="SecurityKey"/> that was not valid. Can be null if <see cref="SecurityToken.SigningKey"/> is missing.
        /// <param name="innerException"/>If present, represents the exception that occurred during validation.
        public IssuerSigningKeyValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            SecurityKey? invalidSigningKey,
            Exception? innerException)
            : base(messageDetail,
                  validationFailureType,
                  stackFrame,
                  innerException)
        {
            InvalidSigningKey = invalidSigningKey;
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
#pragma warning disable RS0016 // Add public types and members to the declared API
        public override Exception GetException()
#pragma warning restore RS0016 // Add public types and members to the declared API
        {
            if (Exception != null)
                return Exception;

            if (FailureType == ValidationFailureType.NullArgument)
                Exception = new ArgumentNullException(MessageDetail.Message);
            else
                Exception = new SecurityTokenInvalidSigningKeyException(MessageDetail.Message, this, InnerException)
                {
                    SigningKey = InvalidSigningKey
                };

            return Exception;
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
            stackFrame,
            null);

        /// <summary>
        /// The signing key that was found invalid.
        /// </summary>
        protected SecurityKey? InvalidSigningKey { get; }
    }
}
#nullable restore
