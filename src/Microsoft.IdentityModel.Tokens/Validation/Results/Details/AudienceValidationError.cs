// Copyright (c) Microsoft Corporation. All rights reserved.
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

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
        internal override Exception GetException()
        {
            if (ExceptionType == typeof(SecurityTokenInvalidAudienceException))
                return new SecurityTokenInvalidAudienceException(MessageDetail.Message) { InvalidAudience = Utility.SerializeAsSingleCommaDelimitedString(_invalidAudiences) };

            return base.GetException();
        }

        internal IList<string>? InvalidAudiences => _invalidAudiences;
    }
}
#nullable restore
