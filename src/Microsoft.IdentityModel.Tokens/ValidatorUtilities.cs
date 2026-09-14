// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Abstractions;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Internal Validator Utilities
    /// </summary>
    internal static class ValidatorUtilities
    {
        /// <summary>
        /// Validates the lifetime of a <see cref="SecurityToken"/>.
        /// </summary>
        /// <param name="notBefore">The 'notBefore' time found in the <see cref="SecurityToken"/>.</param>
        /// <param name="expires">The 'expiration' time found in the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
        /// <exception cref="SecurityTokenNoExpirationException">If 'expires.HasValue' is false and <see cref="TokenValidationParameters.RequireExpirationTime"/> is true.</exception>
        /// <exception cref="SecurityTokenInvalidLifetimeException">If 'notBefore' is &gt; 'expires'.</exception>
        /// <exception cref="SecurityTokenNotYetValidException">If 'notBefore' is &gt; DateTime.UtcNow.</exception>
        /// <exception cref="SecurityTokenExpiredException">If 'expires' is &lt; DateTime.UtcNow.</exception>
        /// <remarks>All time comparisons apply <see cref="TokenValidationParameters.ClockSkew"/>.</remarks>
        internal static void ValidateLifetime(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (!expires.HasValue && validationParameters.RequireExpirationTime)
            {
                SecurityTokenNoExpirationException ex = new SecurityTokenNoExpirationException(LogHelper.FormatInvariant(LogMessages.IDX10225, LogHelper.MarkAsNonPII(securityToken == null ? "null" : securityToken.GetType().ToString())));

                if (!validationParameters.LogValidationExceptions)
                    throw ex;

                throw LogHelper.LogExceptionMessage(ex);
            }

            if (notBefore.HasValue && expires.HasValue && (notBefore.Value > expires.Value))
            {
                SecurityTokenInvalidLifetimeException ex = new SecurityTokenInvalidLifetimeException(LogHelper.FormatInvariant(LogMessages.IDX10224, LogHelper.MarkAsNonPII(notBefore.Value), LogHelper.MarkAsNonPII(expires.Value)))
                {
                    NotBefore = notBefore,
                    Expires = expires
                };

                if (!validationParameters.LogValidationExceptions)
                    throw ex;

                throw LogHelper.LogExceptionMessage(ex);
            }

            DateTime utcNow = validationParameters.TimeProvider.GetUtcNow().UtcDateTime;
            if (notBefore.HasValue && (notBefore.Value > DateTimeUtil.Add(utcNow, validationParameters.ClockSkew)))
            {
                SecurityTokenNotYetValidException ex = new SecurityTokenNotYetValidException(LogHelper.FormatInvariant(LogMessages.IDX10222, LogHelper.MarkAsNonPII(notBefore.Value), LogHelper.MarkAsNonPII(utcNow)))
                {
                    NotBefore = notBefore.Value
                };

                if (!validationParameters.LogValidationExceptions)
                    throw ex;

                throw LogHelper.LogExceptionMessage(ex);
            }

            if (expires.HasValue && (expires.Value < DateTimeUtil.Add(utcNow, validationParameters.ClockSkew.Negate())))
            {
                SecurityTokenExpiredException ex = new SecurityTokenExpiredException(LogHelper.FormatInvariant(LogMessages.IDX10223, LogHelper.MarkAsNonPII(expires.Value), LogHelper.MarkAsNonPII(utcNow)))
                {
                    Expires = expires.Value
                };

                if (!validationParameters.LogValidationExceptions)
                    throw ex;

                throw LogHelper.LogExceptionMessage(ex);
            }

            // if it reaches here, that means lifetime of the token is valid
            if (AppContextSwitches.SuccessValidationLogsAsInformation)
            {
                if (LogHelper.IsEnabled(EventLogLevel.Informational))
                    LogHelper.LogInformation(LogMessages.IDX10239);
            }
            else
            {
                if (LogHelper.IsEnabled(EventLogLevel.Verbose))
                    LogHelper.LogVerbose(LogMessages.IDX10239);
            }
        }
    }
}
