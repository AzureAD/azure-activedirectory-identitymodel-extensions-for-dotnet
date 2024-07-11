// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Linq;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    public static partial class Validators
    {
        /// <summary>
        /// Validates if a given algorithm for a <see cref="SecurityKey"/> is valid.
        /// </summary>
        /// <param name="algorithm">The algorithm to be validated.</param>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
        public static void ValidateAlgorithm(string algorithm, SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.AlgorithmValidator != null)
            {
                if (!validationParameters.AlgorithmValidator(algorithm, securityKey, securityToken, validationParameters))
                {
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidAlgorithmException(LogHelper.FormatInvariant(LogMessages.IDX10697, LogHelper.MarkAsNonPII(algorithm), securityKey))
                    {
                        InvalidAlgorithm = algorithm,
                    });
                }

                return;
            }

            if (validationParameters.ValidAlgorithms != null && validationParameters.ValidAlgorithms.Any() && !validationParameters.ValidAlgorithms.Contains(algorithm, StringComparer.Ordinal))
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidAlgorithmException(LogHelper.FormatInvariant(LogMessages.IDX10696, LogHelper.MarkAsNonPII(algorithm)))
                {
                    InvalidAlgorithm = algorithm,
                });
            }
        }
    }
}
