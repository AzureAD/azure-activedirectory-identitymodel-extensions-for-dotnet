// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Tokens
{
#nullable enable
    /// <summary>
    /// Internal class used to track the results of token validation and to provide a way to merge results.
    /// Once all validation is complete, the results can be converted to a TokenValidationResult.
    /// </summary>
    internal class InternalTokenValidationResult
    {
        private bool _isValid;
        private SecurityToken? _securityToken;
        private TokenHandler _tokenHandler;
        private List<ValidationResult> _validationResults = new List<ValidationResult>(20);

        /// <summary>
        /// Creates a new instance of <see cref="InternalTokenValidationResult"/> to aggregate validation results.
        /// </summary>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="tokenHandler">The <see cref="TokenHandler"/> performing the validation.</param>
        /// <exception cref="ArgumentNullException"></exception>
        public InternalTokenValidationResult(SecurityToken? securityToken, TokenHandler tokenHandler)
        {
            _securityToken = securityToken;
            _tokenHandler = tokenHandler ?? throw new ArgumentNullException(nameof(tokenHandler));
            _isValid = true;
        }

        /// <summary>
        /// Adds a <see cref="ValidationResult"/> to the aggregated list of validation results.
        /// </summary>
        /// <param name="validationResult">The <see cref="ValidationResult"/> to store.</param>
        /// <returns>The current IsValid value for the validation.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public bool AddResult(ValidationResult validationResult)
        {
            if (validationResult == null)
                throw new ArgumentNullException(nameof(validationResult));

            _validationResults.Add(validationResult);
            _isValid = _isValid && validationResult.IsValid;

            return IsValid;
        }

        /// <summary>
        /// Adds a list of <see cref="ValidationResult"/> to the aggregated list of validation results.
        /// </summary>
        /// <param name="validationResults">The list of <see cref="ValidationResult"/> to store.</param>
        /// <returns>The current IsValid value for the validation.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public bool AddResults(IList<ValidationResult> validationResults)
        {
            if (validationResults == null)
                throw new ArgumentNullException(nameof(validationResults));

            _validationResults.AddRange(validationResults);
            for (int i = 0; i < validationResults.Count; i++)
                _isValid = _isValid && validationResults[i].IsValid;

            return IsValid;
        }

        /// <summary>
        /// Gets the <see cref="ExceptionDetail"/> for the first failed validation result.
        /// </summary>
        public ExceptionDetail? ExceptionDetail
        {
            get
            {
                if (ValidationResults.Count == 0)
                    return null;

                // Iterate in reverse since the failure should be the last result
                for (int i = ValidationResults.Count - 1; i >= 0; i--)
                {
                    ValidationResult validationResult = ValidationResults[i];
                    if (validationResult.ExceptionDetail != null)
                        return validationResult.ExceptionDetail;
                }

                return null;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the token is valid.
        /// </summary>
        public bool IsValid => _isValid;

        /// <summary>
        /// Merges the results of another <see cref="InternalTokenValidationResult"/> into this instance.
        /// Updates the <see cref="SecurityToken"/> and <see cref="TokenHandler"/> in case they changed.
        /// </summary>
        /// <param name="other">The <see cref="InternalTokenValidationResult"/> to be merged.</param>
        /// <returns></returns>
        public bool Merge(InternalTokenValidationResult other)
        {
            _securityToken = other._securityToken;
            _tokenHandler = other._tokenHandler;

            return AddResults(other.ValidationResults);
        }

        /// <summary>
        /// Gets the <see cref="SecurityToken"/> being validated.
        /// </summary>
        public SecurityToken? SecurityToken => _securityToken;

        /// <summary>
        /// Returns a <see cref="TokenValidationResult"/> based on the aggregated validation results.
        /// </summary>
        /// <returns>The <see cref="TokenValidationResult"/> containing the result of aggregating all the individual results.</returns>
        public TokenValidationResult ToTokenValidationResult()
        {
            if (IsValid)
            {
                // TokenValidationResult uses TokenValidationParameters to create ClaimsIdentity.
                // We need to figure the best way to refactor that, ideally without creating a new TokenValidationResult class.
                return new TokenValidationResult(
                    _securityToken, _tokenHandler, new TokenValidationParameters(), "issuer", _validationResults)
                {
                    IsValid = true
                };
            }

            return new TokenValidationResult
            {
                IsValid = false,
                Exception = ExceptionDetail?.GetException(), // Need to introduce ExceptionDetail to TokenValidationResult
            };
        }

        /// <summary>
        /// Gets the list of <see cref="ValidationResult"/> that were aggregated.
        /// </summary>
        public IList<ValidationResult> ValidationResults => _validationResults;
    }
#nullable restore
}
