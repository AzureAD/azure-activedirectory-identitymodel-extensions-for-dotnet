// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal class LifetimeValidationError : ValidationError
    {
        internal record struct AdditionalInformation(
            DateTime? NotBeforeDate,
            DateTime? ExpirationDate);

        private AdditionalInformation _additionalInformation;

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
            AdditionalInformation? additionalInformation)
            : base(messageDetail, ValidationFailureType.LifetimeValidationFailed, exceptionType, stackFrame)
        {
            if (additionalInformation.HasValue)
                _additionalInformation = additionalInformation.Value;
        }

        public LifetimeValidationError(
            MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            Exception innerException,
            AdditionalInformation? additionalInformation)
            : base(messageDetail, ValidationFailureType.LifetimeValidationFailed, exceptionType, stackFrame, innerException)
        {
            if (additionalInformation.HasValue)
                _additionalInformation = additionalInformation.Value;
        }

        protected override void AddAdditionalInformation(Exception exception)
        {
            if (exception is SecurityTokenExpiredException expiredException &&
                _additionalInformation.ExpirationDate.HasValue)
            {
                expiredException.Expires = _additionalInformation.ExpirationDate.Value;
            }
            else if (exception is SecurityTokenNotYetValidException notYetValidException &&
                _additionalInformation.NotBeforeDate.HasValue)
            {
                notYetValidException.NotBefore = _additionalInformation.NotBeforeDate.Value;
            }
            else if (exception is SecurityTokenInvalidLifetimeException invalidLifetimeException)
            {
                if (_additionalInformation.NotBeforeDate.HasValue)
                    invalidLifetimeException.NotBefore = _additionalInformation.NotBeforeDate.Value;

                if (_additionalInformation.ExpirationDate.HasValue)
                    invalidLifetimeException.Expires = _additionalInformation.ExpirationDate.Value;
            }
        }
    }
}
#nullable restore
