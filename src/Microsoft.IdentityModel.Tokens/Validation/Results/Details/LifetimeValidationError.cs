// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal class LifetimeValidationError : ValidationError
    {
        DateTime _notBefore;
        DateTime _expires;

        public LifetimeValidationError(
            MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame)
            : base(messageDetail, ValidationFailureType.LifetimeValidationFailed, exceptionType, stackFrame)
        {
        }

        public LifetimeValidationError(
            MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            DateTime notBefore,
            DateTime expires)
            : base(messageDetail, ValidationFailureType.LifetimeValidationFailed, exceptionType, stackFrame)
        {
            _notBefore = notBefore;
            _expires = expires;
        }

        public LifetimeValidationError(
            MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            DateTime expires)
            : base(messageDetail, ValidationFailureType.LifetimeValidationFailed, exceptionType, stackFrame)
        {
            _expires = expires;
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
        internal override Exception GetException()
        {
            if (ExceptionType == typeof(SecurityTokenNoExpirationException))
            {
                return new SecurityTokenNoExpirationException(MessageDetail.Message);
            }
            else if (ExceptionType == typeof(SecurityTokenInvalidLifetimeException))
            {
                return new SecurityTokenInvalidLifetimeException(MessageDetail.Message)
                {
                    NotBefore = _notBefore,
                    Expires = _expires
                };
            }
            else if (ExceptionType == typeof(SecurityTokenNotYetValidException))
            {
                return new SecurityTokenNotYetValidException(MessageDetail.Message)
                {
                    NotBefore = _notBefore
                };
            }
            else if (ExceptionType == typeof(SecurityTokenExpiredException))
            {
                return new SecurityTokenExpiredException(MessageDetail.Message)
                {
                    Expires = _expires
                };
            }
            else
                return base.GetException();
        }
    }
}
#nullable restore
