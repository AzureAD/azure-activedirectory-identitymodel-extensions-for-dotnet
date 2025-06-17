// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents a validation error when a <see cref="SecurityToken.Issuer"/> is not valid.
    /// If available, the invalid issuer is stored in <see cref="InvalidIssuer"/>.
    /// </summary>
    public class IssuerValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IssuerValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="invalidIssuer"/>The issuer that was not valid. Can be null if the issuer is missing from the token.
        public IssuerValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            string? invalidIssuer)
            : this(messageDetail, validationFailureType, stackFrame, invalidIssuer, null)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="IssuerValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="invalidIssuer"/>The issuer that was not valid. Can be null if the issuer is missing from the token.
        /// <param name="innerException"/>If present, represents the exception that occurred during validation.
        public IssuerValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            string? invalidIssuer,
            Exception? innerException)
            : base(messageDetail,
                  validationFailureType,
                  stackFrame,
                  innerException)
        {
            InvalidIssuer = invalidIssuer;
        }

        /// <summary>
        /// The issuer that could not be validated.
        /// </summary>
        public string? InvalidIssuer { get; }

        /// <summary>
        /// Creates an instance of an <see cref="SecurityTokenInvalidIssuerException"/> using <see cref="ValidationError"/>
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

            Exception ??= new SecurityTokenInvalidIssuerException(MessageDetail.Message, this, InnerException)
            {
                InvalidIssuer = InvalidIssuer
            };

            return Exception!;
        }
    }
}
#nullable restore
