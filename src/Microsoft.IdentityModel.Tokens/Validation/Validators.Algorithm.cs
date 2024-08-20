// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Linq;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Definition for delegate that will validate a given algorithm for a <see cref="SecurityKey"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm to be validated.</param>
    /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
    /// <param name="callContext"></param>
    /// <returns>A <see cref="Result{TResult, TError}"/>that contains the results of validating the algorithm.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
    internal delegate Result<string, ITokenValidationError> AlgorithmValidatorDelegate(
        string algorithm,
        SecurityKey securityKey,
        SecurityToken securityToken,
        ValidationParameters validationParameters,
        CallContext callContext);

    public static partial class Validators
    {
        /// <summary>
        /// Validates a given algorithm for a <see cref="SecurityKey"/>.
        /// </summary>
        /// <param name="algorithm">The algorithm to be validated.</param>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="ValidationParameters"/> required for validation.</param>
        /// <param name="callContext"></param>
#pragma warning disable CA1801 // TODO: remove pragma disable once callContext is used for logging
        internal static Result<string, ITokenValidationError> ValidateAlgorithm(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
#pragma warning restore CA1801 // TODO: remove pragma disable once callContext is used for logging
        {
            if (validationParameters == null)
                return new(TokenValidationErrorCommon.NullParameter(nameof(validationParameters), 0x123123));

            if (validationParameters.ValidAlgorithms != null && validationParameters.ValidAlgorithms.Count > 0 && !validationParameters.ValidAlgorithms.Contains(algorithm, StringComparer.Ordinal))
                return new(new TokenValidationError(
                    ValidationErrorType.SecurityTokenInvalidAlgorithm,
                    new MessageDetail(
                        LogMessages.IDX10696,
                        LogHelper.MarkAsNonPII(algorithm)),
                    0x123123,
                    null));

            return new(algorithm);
        }
    }
}
#nullable restore
