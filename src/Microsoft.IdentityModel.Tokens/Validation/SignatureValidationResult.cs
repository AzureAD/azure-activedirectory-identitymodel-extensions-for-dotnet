// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains the result of validating the signature of a <see cref="SecurityToken"/>.
    /// The <see cref="TokenValidationResult"/> contains a collection of <see cref="ValidationResult"/> for each step in the token validation.
    /// </summary>
    internal class SignatureValidationResult : ValidationResult
    {
        private Exception? _exception;

        /// <summary>
        /// Creates an instance of <see cref="SignatureValidationResult"/>
        /// </summary>
        public SignatureValidationResult()
            : base(ValidationFailureType.ValidationSucceeded)
        {
            IsValid = true;
        }

        /// <summary>
        /// Creates an instance of <see cref="SignatureValidationResult"/>
        /// </summary>
        /// <paramref name="validationFailure"/> is the <see cref="ValidationFailureType"/> that occurred during validation.
        /// <paramref name="exceptionDetail"/> is the <see cref="ExceptionDetail"/> that occurred during validation.
        public SignatureValidationResult(ValidationFailureType validationFailure, ExceptionDetail exceptionDetail)
            : base(validationFailure, exceptionDetail)
        {
            IsValid = false;
        }

        /// <summary>
        /// Gets the <see cref="Exception"/> that occurred during validation.
        /// </summary>
        public override Exception? Exception
        {
            get
            {
                if (_exception != null || ExceptionDetail == null)
                    return _exception;

                HasValidOrExceptionWasRead = true;
                _exception = ExceptionDetail.GetException();
                if (_exception is SecurityTokenInvalidSignatureException securityTokenInvalidSignatureException)
                {
                    securityTokenInvalidSignatureException.Source = "Microsoft.IdentityModel.Tokens";
                }

                return _exception;
            }
        }

        public SecurityToken? SecurityToken { get; set; }
    }
}
#nullable restore
