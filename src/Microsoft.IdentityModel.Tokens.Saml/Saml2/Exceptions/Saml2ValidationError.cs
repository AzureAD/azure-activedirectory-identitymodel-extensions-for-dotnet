// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml2
{
    internal class Saml2ValidationError : ValidationError
    {
        internal Saml2ValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            Exception? innerException = null)
            : base(messageDetail, validationFailureType, exceptionType, stackFrame, innerException)
        {
        }

        internal override Exception GetException()
        {
            if (ExceptionType == typeof(Saml2SecurityTokenReadException))
            {
                var exception = new Saml2SecurityTokenReadException(MessageDetail.Message, InnerException);
                return exception;
            }

            return base.GetException();
        }
    }
}
#nullable restore
