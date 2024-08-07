// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains the result of decrypting a securityToken in clear text.
    /// The <see cref="TokenValidationResult"/> contains a collection of <see cref="ValidationResult"/> for each step in the token validation.
    /// </summary>
    internal class TokenDecryptionResult : ValidationResult
    {
        private Exception? _exception;
        private string? _decryptedToken;

        /// <summary>
        /// Creates an instance of <see cref="TokenDecryptionResult"/> containing the clear text result of decrypting a security token.
        /// </summary>
        /// <paramref name="decryptedToken"/>The clear text result of decrypting the security token.
        /// <paramref name="securityToken"/>The SecurityToken that contains the cypher text.
        public TokenDecryptionResult(string decryptedToken, SecurityToken securityToken)
            : base(ValidationFailureType.ValidationSucceeded)
        {
            IsValid = true;
            _decryptedToken = decryptedToken;
            SecurityToken = securityToken;
        }

        /// <summary>
        /// Creates an instance of <see cref="TokenDecryptionResult"/>
        /// </summary>
        /// <paramref name="securityToken"/> is the securityToken that could not be decrypted.
        /// <paramref name="validationFailure"/> is the <see cref="ValidationFailureType"/> that occurred during reading.
        /// <paramref name="exceptionDetail"/> is the <see cref="ExceptionDetail"/> that occurred during reading.
        public TokenDecryptionResult(SecurityToken? securityToken, ValidationFailureType validationFailure, ExceptionDetail exceptionDetail)
            : base(validationFailure, exceptionDetail)
        {
            SecurityToken = securityToken;
            IsValid = false;
        }

        /// <summary>
        /// Creates an instance of <see cref="TokenDecryptionResult"/> representing a failure due to a null parameter.
        /// </summary>
        /// <param name="securityToken">The securityToken that could not be decrypted.</param>
        /// <param name="parameterName">The name of the null parameter.</param>
        internal static TokenDecryptionResult NullParameterFailure(SecurityToken? securityToken, string parameterName) =>
            new TokenDecryptionResult(
                securityToken,
                ValidationFailureType.TokenDecryptionFailed,
                ExceptionDetail.NullParameter(parameterName));

        /// <summary>
        /// Gets the decoded contents of the SecurityToken.
        /// </summary>
        /// <exception cref="InvalidOperationException"/> if the result is not valid, and the decrypted token is not available.
        /// <remarks>It is expected that this method will only be called if <see cref="ValidationResult.IsValid"/> returns true.</remarks>
        public string DecryptedToken()
        {
            if (_decryptedToken is null)
                throw new InvalidOperationException("Attempted to retrieve the DecryptedToken from a failed TokenDecrypting result.");

            return _decryptedToken;
        }

        /// <summary>
        /// Gets the <see cref="Exception"/> that occurred during reading.
        /// </summary>
        public override Exception? Exception
        {
            get
            {
                if (_exception != null || ExceptionDetail == null)
                    return _exception;

                HasValidOrExceptionWasRead = true;
                _exception = ExceptionDetail.GetException();

                if (_exception is SecurityTokenException securityTokenException)
                {
                    securityTokenException.Source = "Microsoft.IdentityModel.Tokens";
                    securityTokenException.ExceptionDetail = ExceptionDetail;
                }

                return _exception;
            }
        }

        /// <summary>
        /// The <see cref="SecurityToken"/> on which decryption was attempted.
        /// </summary>
        public SecurityToken? SecurityToken { get; }
    }
}
#nullable restore
