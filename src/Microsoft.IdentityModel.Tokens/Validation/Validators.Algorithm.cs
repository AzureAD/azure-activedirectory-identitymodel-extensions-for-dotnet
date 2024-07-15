// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.Linq;
using Microsoft.IdentityModel.Logging;

#nullable enable
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
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
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

        /// <summary>
        /// Validates a given algorithm for a <see cref="SecurityKey"/> is valid, if given.
        /// </summary>
        /// <param name="algorithm">The algorithm to be validated.</param>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <param name="callContext"></param>
#pragma warning disable CA1801 // TODO: remove pragma disable once callContext is used for logging
        internal static AlgorithmValidationResult ValidateAlgorithm(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            TokenValidationParameters validationParameters,
            CallContext? callContext)
#pragma warning restore CA1801 // TODO: remove pragma disable once callContext is used for logging
        {
            if (validationParameters == null)
            {
                return new AlgorithmValidationResult(
                    algorithm,
                    ValidationFailureType.NullArgument,
                    new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10000,
                            LogHelper.MarkAsNonPII(nameof(validationParameters))),
                        typeof(ArgumentNullException),
                        new StackFrame(true)));
            }

            if (validationParameters.AlgorithmValidator != null)
            {
                if (!validationParameters.AlgorithmValidator(algorithm, securityKey, securityToken, validationParameters))
                {
                    return new AlgorithmValidationResult(
                        algorithm,
                        ValidationFailureType.AlgorithmValidationFailed,
                        new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10697,
                                LogHelper.MarkAsNonPII(algorithm),
                                securityKey),
                            typeof(SecurityTokenInvalidAlgorithmException),
                            new StackFrame(true)));
                }

                return new AlgorithmValidationResult(algorithm);
            }

            if (validationParameters.ValidAlgorithms != null && validationParameters.ValidAlgorithms.Any() && !validationParameters.ValidAlgorithms.Contains(algorithm, StringComparer.Ordinal))
            {
                return new AlgorithmValidationResult(
                    algorithm,
                    ValidationFailureType.AlgorithmValidationFailed,
                    new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10696,
                            LogHelper.MarkAsNonPII(algorithm)),
                        typeof(SecurityTokenInvalidAlgorithmException),
                        new StackFrame(true)));
            }

            return new AlgorithmValidationResult(algorithm);
        }
    }
}
#nullable restore
