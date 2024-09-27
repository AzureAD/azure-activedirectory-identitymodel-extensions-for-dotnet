﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal class AudienceValidationError : ValidationError
    {
        private IList<string>? _invalidAudiences;

        public AudienceValidationError(
            MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            IList<string>? invalidAudiences)
            : base(messageDetail, ValidationFailureType.AudienceValidationFailed, exceptionType, stackFrame)
        {
            _invalidAudiences = invalidAudiences;
        }

        internal override void AddAdditionalInformation(ISecurityTokenException exception)
        {
            if (exception is SecurityTokenInvalidAudienceException invalidAudienceException)
                invalidAudienceException.InvalidAudience = Utility.SerializeAsSingleCommaDelimitedString(_invalidAudiences);
        }
    }
}
#nullable restore
