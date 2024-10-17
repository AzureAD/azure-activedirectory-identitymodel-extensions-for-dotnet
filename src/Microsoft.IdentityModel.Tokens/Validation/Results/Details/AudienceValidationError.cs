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
        private IList<string>? _tokenAudiences;
        private IList<string>? _validAudiences;

        // stack frames associated with AudienceValidationErrors
        internal static StackFrame? ValidationParametersNull;
        internal static StackFrame? AudiencesNull;
        internal static StackFrame? AudiencesCountZero;
        internal static StackFrame? ValidationParametersAudiencesCountZero;
        internal static StackFrame? ValidateAudienceFailed;

        public AudienceValidationError(
            MessageDetail messageDetail,
            ValidationFailureType failureType,
            Type exceptionType,
            StackFrame stackFrame,
            IList<string>? tokenAudiences,
            IList<string>? validAudiences)
            : base(messageDetail, failureType, exceptionType, stackFrame)
        {
            _tokenAudiences = tokenAudiences;
            _validAudiences = validAudiences;
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
        internal override Exception GetException()
        {
            if (ExceptionType == typeof(SecurityTokenInvalidAudienceException))
                return new SecurityTokenInvalidAudienceException(MessageDetail.Message) { InvalidAudience = Utility.SerializeAsSingleCommaDelimitedString(_tokenAudiences) };

            return base.GetException(ExceptionType, null);
        }

        internal IList<string>? TokenAudiences => _tokenAudiences;
    }
}
#nullable restore
