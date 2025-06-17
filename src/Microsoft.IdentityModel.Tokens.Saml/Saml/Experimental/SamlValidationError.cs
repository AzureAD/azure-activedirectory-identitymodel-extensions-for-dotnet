// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml.Experimental
{
    /// <summary>
    /// Represents a SAML validation error.
    /// </summary>
    public class SamlValidationError : ValidationError
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SamlValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" /> contains information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/> is the type of validation failure that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        public SamlValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame)
            : this(messageDetail, validationFailureType, stackFrame, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SamlValidationError"/> class.
        /// </summary>
        /// <param name="messageDetail" /> contains information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/> is the type of validation failure that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        /// <param name="innerException"/> is the inner exception that occurred.
        public SamlValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            Exception? innerException)
            : base(messageDetail, validationFailureType, stackFrame, innerException)
        {
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
        protected override Exception CreateException()
        {
            return new SamlSecurityTokenException(MessageDetail.Message, InnerException);
        }
    }
}
#nullable restore
