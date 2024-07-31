// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.


using System;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.JsonWebTokens.Results
{
#nullable enable
    internal class SignatureValidationResult: ValidationResult
    {
        private Exception? _exception;

        public SignatureValidationResult() : base(ValidationFailureType.ValidationSucceeded)
        {
            IsValid = true;
        }

        public SignatureValidationResult(ValidationFailureType validationFailure, ExceptionDetail? exceptionDetail)
            : base(validationFailure, exceptionDetail)
        {
            IsValid = false;
        }

        public override Exception? Exception
        {
            get
            {
                if (_exception != null || ExceptionDetail == null)
                    return _exception;

                HasValidOrExceptionWasRead = true;
                _exception = ExceptionDetail.GetException();
                _exception.Source = "Microsoft.IdentityModel.JsonWebTokens";

                if (_exception is SecurityTokenException securityTokenException)
                {
                    securityTokenException.ExceptionDetail = ExceptionDetail;
                }

                return _exception;
            }
        }
    }
#nullable restore
}
