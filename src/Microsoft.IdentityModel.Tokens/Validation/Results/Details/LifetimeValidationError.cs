// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal class LifetimeValidationError : ValidationError
    {
        public LifetimeValidationError(
            MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            ValidationFailureType? validationFailureType = null,
            DateTime? notBefore = null,
            DateTime? expires = null,
            Exception? innerException = null)

            : base(messageDetail, validationFailureType ?? ValidationFailureType.LifetimeValidationFailed, exceptionType, stackFrame, innerException)
        {
            if (notBefore.HasValue)
                NotBefore = notBefore.Value;
            if (expires.HasValue)
                Expires = expires.Value;
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
        internal override Exception GetException()
        {
            if (ExceptionType == typeof(SecurityTokenNoExpirationException))
            {
                var exception = new SecurityTokenNoExpirationException(MessageDetail.Message, InnerException);
                exception.SetValidationError(this);
                return exception;
            }
            else if (ExceptionType == typeof(SecurityTokenInvalidLifetimeException))
            {
                var exception = new SecurityTokenInvalidLifetimeException(MessageDetail.Message, InnerException)
                {
                    NotBefore = NotBefore,
                    Expires = Expires
                };
                exception.SetValidationError(this);
                return exception;
            }
            else if (ExceptionType == typeof(SecurityTokenNotYetValidException))
            {
                var exception = new SecurityTokenNotYetValidException(MessageDetail.Message, InnerException)
                {
                    NotBefore = NotBefore
                };
                exception.SetValidationError(this);
                return exception;
            }
            else if (ExceptionType == typeof(SecurityTokenExpiredException))
            {
                var exception = new SecurityTokenExpiredException(MessageDetail.Message, InnerException)
                {
                    Expires = Expires
                };
                exception.SetValidationError(this);
                return exception;
            }
            else
                return base.GetException(ExceptionType, null);
        }

        protected DateTime NotBefore { get; set; }

        protected DateTime Expires { get; set; }
    }
}
#nullable restore
