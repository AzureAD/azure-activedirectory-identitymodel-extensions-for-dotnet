// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <summary>
    /// Contains the result of decrypting a JWT in clear text.
    /// The <see cref="TokenValidationResult"/> contains a collection of <see cref="ValidationResult"/> for each step in the token validation.
    /// </summary>
    internal class TokenDecryptingResult : ValidationResult
    {
        private Exception? _exception;
        private string? _decryptedToken;

        /// <summary>
        /// Creates an instance of <see cref="TokenDecryptingResult"/> containing the clear text result of decrypting a JWE.
        /// </summary>
        /// <paramref name="decryptedToken"/>The clear text result of decrypting the JWE.
        /// <paramref name="jwtToken"/>The JWE that contains the cypher text.
        public TokenDecryptingResult(string decryptedToken, JsonWebToken jwtToken)
            : base(ValidationFailureType.ValidationSucceeded)
        {
            IsValid = true;
            _decryptedToken = decryptedToken;
            JWT = jwtToken;
        }

        /// <summary>
        /// Creates an instance of <see cref="TokenDecryptingResult"/>
        /// </summary>
        /// <paramref name="jwtToken"/> is the JWT that could not be decrypted.
        /// <paramref name="validationFailure"/> is the <see cref="ValidationFailureType"/> that occurred during reading.
        /// <paramref name="exceptionDetail"/> is the <see cref="ExceptionDetail"/> that occurred during reading.
        public TokenDecryptingResult(JsonWebToken? jwtToken, ValidationFailureType validationFailure, ExceptionDetail exceptionDetail)
            : base(validationFailure, exceptionDetail)
        {
            JWT = jwtToken;
            IsValid = false;
        }

        /// <summary>
        /// Gets the decoded contents of the JWE.
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
        /// Gets the string from which the <see cref="SecurityToken"/> was read.
        /// </summary>
        public JsonWebToken? JWT { get; }
    }
}
#nullable restore
