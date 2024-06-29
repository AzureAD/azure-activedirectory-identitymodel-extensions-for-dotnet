// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    public static partial class Validators
    {
        /// <summary>
        /// Validates if a token has been replayed.
        /// </summary>
        /// <param name="expirationTime">When does the security token expire.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <exception cref="ArgumentNullException">If 'securityToken' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">If 'validationParameters' is null or whitespace.</exception>
        /// <exception cref="SecurityTokenNoExpirationException">If <see cref="TokenValidationParameters.TokenReplayCache"/> is not null and expirationTime.HasValue is false. When a TokenReplayCache is set, tokens require an expiration time.</exception>
        /// <exception cref="SecurityTokenReplayDetectedException">If the 'securityToken' is found in the cache.</exception>
        /// <exception cref="SecurityTokenReplayAddFailedException">If the 'securityToken' could not be added to the <see cref="TokenValidationParameters.TokenReplayCache"/>.</exception>
        public static void ValidateTokenReplay(DateTime? expirationTime, string securityToken, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrWhiteSpace(securityToken))
                throw LogHelper.LogArgumentNullException(nameof(securityToken));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.TokenReplayValidator != null)
            {
                if (!validationParameters.TokenReplayValidator(expirationTime, securityToken, validationParameters))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenReplayDetectedException(
                        LogHelper.FormatInvariant(
                            LogMessages.IDX10228,
                            LogHelper.MarkAsUnsafeSecurityArtifact(securityToken, t => t.ToString()))));
                return;
            }

            if (!validationParameters.ValidateTokenReplay)
            {
                LogHelper.LogVerbose(LogMessages.IDX10246);
                return;
            }

            // check if token if replay cache is set, then there must be an expiration time.
            if (validationParameters.TokenReplayCache != null)
            {
                if (!expirationTime.HasValue)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenNoExpirationException(LogHelper.FormatInvariant(LogMessages.IDX10227, securityToken)));

                if (validationParameters.TokenReplayCache.TryFind(securityToken))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenReplayDetectedException(LogHelper.FormatInvariant(LogMessages.IDX10228, securityToken)));

                if (!validationParameters.TokenReplayCache.TryAdd(securityToken, expirationTime.Value))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenReplayAddFailedException(LogHelper.FormatInvariant(LogMessages.IDX10229, securityToken)));
            }

            // if it reaches here, that means no token replay is detected.
            LogHelper.LogInformation(LogMessages.IDX10240);
        }

        /// <summary>
        /// Validates if a token has been replayed.
        /// </summary>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="expirationTime">When does the security token expire.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <exception cref="ArgumentNullException">If 'securityToken' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">If 'validationParameters' is null or whitespace.</exception>
        /// <exception cref="SecurityTokenNoExpirationException">If <see cref="TokenValidationParameters.TokenReplayCache"/> is not null and expirationTime.HasValue is false. When a TokenReplayCache is set, tokens require an expiration time.</exception>
        /// <exception cref="SecurityTokenReplayDetectedException">If the 'securityToken' is found in the cache.</exception>
        /// <exception cref="SecurityTokenReplayAddFailedException">If the 'securityToken' could not be added to the <see cref="TokenValidationParameters.TokenReplayCache"/>.</exception>
        public static void ValidateTokenReplay(string securityToken, DateTime? expirationTime, TokenValidationParameters validationParameters)
        {
            ValidateTokenReplay(expirationTime, securityToken, validationParameters);
        }
    }
}
