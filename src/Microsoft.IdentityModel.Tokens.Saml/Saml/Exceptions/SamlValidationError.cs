// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    internal class SamlValidationError : ValidationError
    {
        internal SamlValidationError(MessageDetail messageDetail, ValidationFailureType failureType, Type exceptionType, StackFrame stackFrame, Exception innerException) : base(messageDetail, failureType, exceptionType, stackFrame, innerException)
        {
        }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(SamlSecurityTokenReadException))
            {
                var exception = new SamlSecurityTokenReadException(MessageDetail.Message, InnerException);
                return exception;
            }

            return base.GetException();
        }
    }
}
