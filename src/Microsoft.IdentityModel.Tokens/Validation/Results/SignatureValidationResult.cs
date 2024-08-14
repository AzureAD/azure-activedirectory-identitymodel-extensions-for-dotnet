// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.JsonWebTokens.Results
{
    /// <summary>
    /// Contains the result of validating a signature.
    /// The <see cref="TokenValidationResult"/> contains a collection of <see cref="ValidationResult"/> for each step in the token validation.
    /// </summary>
    internal class SignatureValidationResult : ValidationResult
    {
        private Exception? _exception;

        /// <summary>
        /// Creates an instance of <see cref="SignatureValidationResult"/> representing the successful result of validating a signature.
        /// </summary>
        public SignatureValidationResult(bool isValid, ValidationFailureType validationFailureType) : base(validationFailureType)
        {
            IsValid = isValid;
        }

        /// <summary>
        /// Creates an instance of <see cref="SignatureValidationResult"/> representing the failed result of validating a signature.
        /// </summary>
        /// <param name="validationFailure"> is the <see cref="ValidationFailure"/> that occurred while validating the signature.</param>
        /// <param name="exceptionDetail"> contains the <see cref="ExceptionDetail"/> of the error that occurred while validating the signature.</param>
        public SignatureValidationResult(ValidationFailureType validationFailure, ExceptionDetail? exceptionDetail)
            : base(validationFailure, exceptionDetail)
        {
            IsValid = false;
        }

        /// <summary>
        /// Creates an instance of <see cref="SignatureValidationResult"/> representing a successful validation.
        /// </summary>
        internal static SignatureValidationResult Success() =>
            new SignatureValidationResult(true, ValidationFailureType.ValidationSucceeded);

        /// <summary>
        /// Creates an instance of <see cref="SignatureValidationResult"/> representing a failure due to a null parameter.
        /// </summary>
        /// <param name="parameterName">The name of the null parameter.</param>
        internal static SignatureValidationResult NullParameterFailure(string parameterName) =>
            new SignatureValidationResult(
                ValidationFailureType.SignatureValidationFailed,
                ExceptionDetail.NullParameter(parameterName));

        /// <summary>
        /// Gets the <see cref="Exception"/> that occurred while validating the signature.
        /// </summary>
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
}
#nullable restore
