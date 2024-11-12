// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    #region IssuerValidationErrors
    internal class CustomIssuerValidationError : IssuerValidationError
    {
        /// <summary>
        /// A custom validation failure type.
        /// </summary>
        public static readonly ValidationFailureType CustomIssuerValidationFailureType = new IssuerValidatorFailure("CustomIssuerValidationFailureType");
        private class IssuerValidatorFailure : ValidationFailureType { internal IssuerValidatorFailure(string name) : base(name) { } }

        public CustomIssuerValidationError(
            MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidIssuer)
            : base(messageDetail, exceptionType, stackFrame, invalidIssuer)
        {
        }

        public CustomIssuerValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidIssuer,
            Exception? innerException)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, invalidIssuer, innerException)
        {
        }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(CustomSecurityTokenInvalidIssuerException))
            {
                var exception = new CustomSecurityTokenInvalidIssuerException(MessageDetail.Message, InnerException) { InvalidIssuer = InvalidIssuer };
                exception.SetValidationError(this);

                return exception;
            }

            return base.GetException();
        }
    }

    internal class CustomIssuerWithoutGetExceptionValidationOverrideError : IssuerValidationError
    {
        public CustomIssuerWithoutGetExceptionValidationOverrideError(MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidIssuer) :
            base(messageDetail, exceptionType, stackFrame, invalidIssuer)
        {
        }
    }
    #endregion

    #region AudienceValidationErrors
    internal class CustomAudienceValidationError : AudienceValidationError
    {
        /// <summary>
        /// A custom validation failure type.
        /// </summary>
        public static readonly ValidationFailureType CustomAudienceValidationFailureType = new AudienceValidatorFailure("CustomAudienceValidationFailureType");
        private class AudienceValidatorFailure : ValidationFailureType { internal AudienceValidatorFailure(string name) : base(name) { } }

        public CustomAudienceValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            IList<string>? tokenAudiences,
            IList<string>? validAudiences,
            Exception? innerException = null)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, tokenAudiences, validAudiences, innerException)
        {
        }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(CustomSecurityTokenInvalidAudienceException))
            {
                var exception = new CustomSecurityTokenInvalidAudienceException(MessageDetail.Message, InnerException) { InvalidAudience = Utility.SerializeAsSingleCommaDelimitedString(TokenAudiences) };
                exception.SetValidationError(this);

                return exception;
            }

            return base.GetException();
        }
    }

    internal class CustomAudienceWithoutGetExceptionValidationOverrideError : AudienceValidationError
    {
        public CustomAudienceWithoutGetExceptionValidationOverrideError(
            MessageDetail messageDetail,
            ValidationFailureType failureType,
            Type exceptionType,
            StackFrame stackFrame,
            IList<string>? tokenAudiences,
            IList<string>? validAudiences) :
            base(messageDetail, failureType, exceptionType, stackFrame, tokenAudiences, validAudiences)
        {
        }
    }
    #endregion
}
#nullable restore
