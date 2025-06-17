// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents an error that occurs when a token's lifetime cannot be validated.
    /// If available, the not before and expires values are stored in <see cref="NotBefore"/> and <see cref="Expires"/>.
    /// </summary>
    public class LifetimeValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="LifetimeValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="notBefore"/>The <see cref="DateTime"/> from which the <see cref="SecurityToken"/> is valid. Can be null if the <see cref="SecurityToken"/> does not contain a not before claim.
        /// <param name="expires"/>The <see cref="DateTime"/> at which the <see cref="SecurityToken"/> expires. Can be null if the <see cref="SecurityToken"/> does not contain an expires claim.
        /// <param name="innerException"/> If present, represents the exception that occurred during validation.
        public LifetimeValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            DateTime? notBefore,
            DateTime? expires,
            Exception? innerException)

            : base(messageDetail, validationFailureType, stackFrame, innerException)
        {
            NotBefore = notBefore;
            Expires = expires;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="LifetimeValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="notBefore"/>The <see cref="DateTime"/> from which the <see cref="SecurityToken"/> is valid. Can be null if the <see cref="SecurityToken"/> does not contain a not before claim.
        /// <param name="expires"/>The <see cref="DateTime"/> at which the <see cref="SecurityToken"/> expires. Can be null if the <see cref="SecurityToken"/> does not contain an expires claim.
        public LifetimeValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            DateTime? notBefore,
            DateTime? expires)
            : this(messageDetail,
                  validationFailureType,
                  stackFrame,
                  notBefore,
                  expires,
                  null)
        {
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
#pragma warning disable RS0016 // Add public types and members to the declared API
        public override Exception GetException()
#pragma warning restore RS0016 // Add public types and members to the declared API
        {
            if (Exception is not null)
                return Exception;

            if (FailureType == ValidationFailureType.NullArgument)
                Exception = new ArgumentNullException(MessageDetail.Message);
            else
                Exception = new SecurityTokenInvalidLifetimeException(MessageDetail.Message, this, InnerException)
                {
                    NotBefore = NotBefore,
                    Expires = Expires
                };

            return Exception;
        }

        /// <summary>
        /// Creates a new instance of <see cref="LifetimeValidationError"/> representing a null parameter.
        /// </summary>
        /// <param name="parameterName">The name of the parameter.</param>
        /// <param name="stackFrame">The stack frame where the error occurred.</param>
        /// <returns>A new <see cref="LifetimeValidationError"/>.</returns>
        public static new LifetimeValidationError NullParameter(string parameterName, StackFrame stackFrame) => new(
            MessageDetail.NullParameter(parameterName),
            ValidationFailureType.NullArgument,
            stackFrame,
            null,
            null);

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
