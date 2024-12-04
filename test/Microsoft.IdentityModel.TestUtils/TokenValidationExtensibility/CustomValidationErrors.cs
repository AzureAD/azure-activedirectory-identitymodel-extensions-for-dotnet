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
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidIssuer,
            Exception? innerException = null)
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
            base(messageDetail, ValidationFailureType.IssuerValidationFailed, exceptionType, stackFrame, invalidIssuer)
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
            Type exceptionType,
            StackFrame stackFrame,
            IList<string>? tokenAudiences,
            IList<string>? validAudiences,
            Exception? innerException = null) :
            base(messageDetail, ValidationFailureType.AudienceValidationFailed, exceptionType, stackFrame, tokenAudiences, validAudiences, innerException)
        {
        }
    }
    #endregion

    #region LifetimeValidationErrors
    internal class CustomLifetimeValidationError : LifetimeValidationError
    {
        /// <summary>
        /// A custom validation failure type.
        /// </summary>
        public static readonly ValidationFailureType CustomLifetimeValidationFailureType = new LifetimeValidationFailure("CustomLifetimeValidationFailureType");
        private class LifetimeValidationFailure : ValidationFailureType { internal LifetimeValidationFailure(string name) : base(name) { } }

        public CustomLifetimeValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            DateTime? notBefore,
            DateTime? expires,
            Exception? innerException = null)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, notBefore, expires)
        {
        }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(CustomSecurityTokenInvalidLifetimeException))
            {
                var exception = new CustomSecurityTokenInvalidLifetimeException(MessageDetail.Message, InnerException) { NotBefore = NotBefore, Expires = Expires };
                exception.SetValidationError(this);

                return exception;
            }

            return base.GetException();
        }
    }

    internal class CustomLifetimeWithoutGetExceptionValidationOverrideError : LifetimeValidationError
    {
        public CustomLifetimeWithoutGetExceptionValidationOverrideError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            DateTime? notBefore,
            DateTime? expires,
            Exception? innerException = null)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, notBefore, expires, innerException)
        {
        }
    }
    #endregion

    #region IssuerSigningKeyValidationErrors
    internal class CustomIssuerSigningKeyValidationError : IssuerSigningKeyValidationError
    {
        /// <summary>
        /// A custom validation failure type.
        /// </summary>
        public static readonly ValidationFailureType CustomIssuerSigningKeyValidationFailureType = new IssuerSigningKeyValidationFailure("CustomIssuerSigningKeyValidationFailureType");
        private class IssuerSigningKeyValidationFailure : ValidationFailureType { internal IssuerSigningKeyValidationFailure(string name) : base(name) { } }

        public CustomIssuerSigningKeyValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            SecurityKey? securityKey,
            Exception? innerException = null)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, securityKey, innerException)
        {
        }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(CustomSecurityTokenInvalidSigningKeyException))
            {
                var exception = new CustomSecurityTokenInvalidSigningKeyException(MessageDetail.Message, InnerException) { SigningKey = InvalidSigningKey };
                exception.SetValidationError(this);
                return exception;
            }
            return base.GetException();
        }
    }

    internal class CustomIssuerSigningKeyWithoutGetExceptionValidationOverrideError : IssuerSigningKeyValidationError
    {
        public CustomIssuerSigningKeyWithoutGetExceptionValidationOverrideError(
            MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            SecurityKey? securityKey,
            Exception? innerException = null)
            : base(messageDetail, ValidationFailureType.SigningKeyValidationFailed, exceptionType, stackFrame, securityKey, innerException)
        {
        }
    }
    #endregion // IssuerSigningKeyValidationErrors

    #region TokenTypeValidationErrors
    internal class CustomTokenTypeValidationError : TokenTypeValidationError
    {
        /// <summary>
        /// A custom validation failure type.
        /// </summary>
        public static readonly ValidationFailureType CustomTokenTypeValidationFailureType = new TokenTypeValidationFailure("CustomTokenTypeValidationFailureType");
        private class TokenTypeValidationFailure : ValidationFailureType { internal TokenTypeValidationFailure(string name) : base(name) { } }

        public CustomTokenTypeValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidTokenType,
            Exception? innerException = null)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, invalidTokenType, innerException)
        {
        }
        internal override Exception GetException()
        {
            if (ExceptionType == typeof(CustomSecurityTokenInvalidTypeException))
            {
                var exception = new CustomSecurityTokenInvalidTypeException(MessageDetail.Message, InnerException) { InvalidType = InvalidTokenType };
                exception.SetValidationError(this);
                return exception;
            }
            return base.GetException();
        }
    }

    internal class CustomTokenTypeWithoutGetExceptionValidationOverrideError : TokenTypeValidationError
    {
        public CustomTokenTypeWithoutGetExceptionValidationOverrideError(
            MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidTokenType,
            Exception? innerException = null)
            : base(messageDetail, ValidationFailureType.TokenTypeValidationFailed, exceptionType, stackFrame, invalidTokenType, innerException)
        {
        }
    }
    #endregion // TokenTypeValidationErrors

    #region SignatureValidationErrors
    internal class CustomSignatureValidationError : SignatureValidationError
    {
        /// <summary>
        /// A custom validation failure type.
        /// </summary>
        public static readonly ValidationFailureType CustomSignatureValidationFailureType = new SignatureValidatorFailure("CustomSignatureValidationFailureType");
        private class SignatureValidatorFailure : ValidationFailureType { internal SignatureValidatorFailure(string name) : base(name) { } }

        public CustomSignatureValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            ValidationError? innerValidationError = null,
            Exception? innerException = null) :
            base(messageDetail, validationFailureType, exceptionType, stackFrame, innerValidationError, innerException)
        {
        }
        internal override Exception GetException()
        {
            if (ExceptionType == typeof(CustomSecurityTokenInvalidSignatureException))
            {
                var exception = new CustomSecurityTokenInvalidSignatureException(MessageDetail.Message, InnerException);
                exception.SetValidationError(this);
                return exception;
            }
            return base.GetException();
        }
    }

    internal class CustomSignatureWithoutGetExceptionValidationOverrideError : SignatureValidationError
    {
        public CustomSignatureWithoutGetExceptionValidationOverrideError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            ValidationError? innerValidationError = null,
            Exception? innerException = null) :
            base(messageDetail, validationFailureType, exceptionType, stackFrame, innerValidationError, innerException)
        {
        }
    }
    #endregion // SignatureValidationErrors

    #region AlgorithmValidationErrors
    internal class CustomAlgorithmValidationError : AlgorithmValidationError
    {
        /// <summary>
        /// A custom validation failure type.
        /// </summary>
        public static readonly ValidationFailureType CustomAlgorithmValidationFailureType = new AlgorithmValidatorFailure("CustomAlgorithmValidationFailureType");
        private class AlgorithmValidatorFailure : ValidationFailureType { internal AlgorithmValidatorFailure(string name) : base(name) { } }

        public CustomAlgorithmValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            string? algorithm,
            Exception? innerException = null)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, algorithm, innerException)
        {
        }
        internal override Exception GetException()
        {
            if (ExceptionType == typeof(CustomSecurityTokenInvalidAlgorithmException))
            {
                var exception = new CustomSecurityTokenInvalidAlgorithmException(MessageDetail.Message, InnerException) { InvalidAlgorithm = InvalidAlgorithm };
                exception.SetValidationError(this);
                return exception;
            }
            return base.GetException();
        }
    }

    internal class CustomAlgorithmWithoutGetExceptionValidationOverrideError : AlgorithmValidationError
    {
        public CustomAlgorithmWithoutGetExceptionValidationOverrideError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidAlgorithm,
            Exception? innerException = null) :
            base(messageDetail, validationFailureType, exceptionType, stackFrame, invalidAlgorithm, innerException)
        {
        }
    }
    #endregion // AlgorithmValidationErrors

    #region TokenReplayValidationErrors
    internal class CustomTokenReplayValidationError : TokenReplayValidationError
    {
        /// <summary>
        /// A custom validation failure type.
        /// </summary>
        public static readonly ValidationFailureType CustomTokenReplayValidationFailureType = new TokenReplayValidationFailure("CustomTokenReplayValidationFailureType");
        private class TokenReplayValidationFailure : ValidationFailureType { internal TokenReplayValidationFailure(string name) : base(name) { } }

        public CustomTokenReplayValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            DateTime? expirationTime,
            Exception? innerException = null)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, expirationTime, innerException)
        {
        }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(CustomSecurityTokenReplayDetectedException))
            {
                var exception = new CustomSecurityTokenReplayDetectedException(MessageDetail.Message, InnerException);
                exception.SetValidationError(this);

                return exception;
            }

            return base.GetException();
        }
    }

    internal class CustomTokenReplayWithoutGetExceptionValidationOverrideError : TokenReplayValidationError
    {
        public CustomTokenReplayWithoutGetExceptionValidationOverrideError(
            MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            DateTime? expirationTime,
            Exception? innerException = null)
            : base(messageDetail, ValidationFailureType.TokenReplayValidationFailed, exceptionType, stackFrame, expirationTime, innerException)
        {
        }
    }
    #endregion

    // Other custom validation errors to be added here for signature validation, issuer signing key, etc.
}
#nullable restore
