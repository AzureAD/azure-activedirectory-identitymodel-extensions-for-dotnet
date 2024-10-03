// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal class IssuerValidationError : ValidationError
    {
        private string? _invalidIssuer;

        public IssuerValidationError(
            MessageDetail messageDetail,
            Type exceptionType,
            StackFrame stackFrame,
            string? invalidIssuer)
            : base(messageDetail, ValidationFailureType.IssuerValidationFailed, exceptionType, stackFrame)
        {
            _invalidIssuer = invalidIssuer;
        }

        internal override void AddAdditionalInformation(ISecurityTokenException exception)
        {
            if (exception is SecurityTokenInvalidIssuerException invalidIssuerException)
                invalidIssuerException.InvalidIssuer = _invalidIssuer;
        }
    }
}
#nullable restore
