// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents a validation error when a <see cref="SecurityToken"/> replay is detected.
    /// If available, the expiration time of the <see cref="SecurityToken"/> that failed the validation is included.
    /// </summary>
    public class TokenReplayValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TokenReplayValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail"/>Information about the error that is can be used to generate an exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="expirationTime"/>The <see cref="DateTime"/> of the <see cref="SecurityToken"/> that failed the validation. Can be null if the token does not have an expiration time.
        public TokenReplayValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            DateTime? expirationTime)
            : this(messageDetail,
                  validationFailureType,
                  stackFrame,
                  expirationTime,
                  null)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenReplayValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="expirationTime"/>The <see cref="DateTime"/> of the <see cref="SecurityToken"/> that failed the validation. Can be null if the token does not have an expiration time.
        /// <param name="innerException"/>If present, represents the exception that occurred during validation.
        public TokenReplayValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            DateTime? expirationTime,
            Exception? innerException)
            : base(messageDetail,
                  validationFailureType,
                  stackFrame,
                  innerException)
        {
            ExpirationTime = expirationTime;
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
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
                Exception = new SecurityTokenReplayDetectedException(MessageDetail.Message, this, InnerException);

            return Exception;
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
            stackFrame,
            null);

        /// <summary>
        /// The expiration time of the token that failed the validation.
        /// </summary>
        public DateTime? ExpirationTime { get; }
    }
}
#nullable restore
