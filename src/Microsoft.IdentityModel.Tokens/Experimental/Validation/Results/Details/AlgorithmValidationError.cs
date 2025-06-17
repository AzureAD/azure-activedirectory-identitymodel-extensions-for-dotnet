// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using Microsoft.IdentityModel.Logging;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents a validation error when a <see cref="SecurityToken"/> algorithm is not valid.
    /// If available, the invalid algorithm is stored in <see cref="InvalidAlgorithm"/>.
    /// </summary>
    public class AlgorithmValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlgorithmValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="invalidAlgorithm"/>The algorithm that could not be validated. Can be null if the algorithm is missing from the token.
        public AlgorithmValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            string? invalidAlgorithm) :
            this(messageDetail,
                validationFailureType,
                stackFrame,
                invalidAlgorithm,
                null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlgorithmValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" />Information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the exception occurred.
        /// <param name="invalidAlgorithm"/>The algorithm that could not be validated. Can be null if the algorithm is missing from the token.
        /// <param name="innerException"/>If present, represents the exception that occurred during validation.
        public AlgorithmValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            string? invalidAlgorithm,
            Exception? innerException) :
            base(messageDetail,
                validationFailureType,
                stackFrame,
                innerException)
        {
            InvalidAlgorithm = invalidAlgorithm;
        }

        /// <summary>
        /// Creates an instance of an <see cref="SecurityTokenInvalidAlgorithmException"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
#pragma warning disable RS0016 // Add public types and members to the declared API
        public override Exception GetException()
#pragma warning restore RS0016 // Add public types and members to the declared API
        {
            if (FailureType == ValidationFailureType.NullArgument)
                return new ArgumentNullException(MessageDetail.Message);

            if (FailureType == ValidationFailureType.InvalidAlgorithm)
                return new SecurityTokenInvalidAlgorithmException(
                    LogHelper.FormatInvariant(
                        LogMessages.IDX10696,
                        LogHelper.MarkAsNonPII(InvalidAlgorithm)))
                {
                    InvalidAlgorithm = InvalidAlgorithm
                };

            return base.CreateException();
        }

        /// <summary>
        /// The algorithm that could not be validated.
        /// </summary>
        public string? InvalidAlgorithm { get; }
    }
}
#nullable restore
