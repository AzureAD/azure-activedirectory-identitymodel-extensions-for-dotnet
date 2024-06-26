// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    public static partial class Validators
    {
        /// <summary>
        /// Validates the <see cref="SecurityKey"/> that signed a <see cref="SecurityToken"/>.
        /// </summary>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <exception cref="ArgumentNullException"> if 'securityKey' is null and ValidateIssuerSigningKey is true.</exception>
        /// <exception cref="ArgumentNullException"> if 'securityToken' is null and ValidateIssuerSigningKey is true.</exception>
        /// <exception cref="ArgumentNullException"> if 'validationParameters' is null.</exception>
        public static void ValidateIssuerSecurityKey(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            ValidateIssuerSecurityKey(securityKey, securityToken, validationParameters, null);
        }

        /// <summary>
        /// Validates the <see cref="SecurityKey"/> that signed a <see cref="SecurityToken"/>.
        /// </summary>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <param name="configuration">The <see cref="BaseConfiguration"/> required for issuer and signing key validation.</param>
        /// <exception cref="ArgumentNullException"> if 'securityKey' is null and ValidateIssuerSigningKey is true.</exception>
        /// <exception cref="ArgumentNullException"> if 'securityToken' is null and ValidateIssuerSigningKey is true.</exception>
        /// <exception cref="ArgumentNullException"> if 'validationParameters' is null.</exception>
        internal static void ValidateIssuerSecurityKey(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters, BaseConfiguration configuration)
        {
            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.IssuerSigningKeyValidatorUsingConfiguration != null)
            {
                if (!validationParameters.IssuerSigningKeyValidatorUsingConfiguration(securityKey, securityToken, validationParameters, configuration))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSigningKeyException(LogHelper.FormatInvariant(LogMessages.IDX10232, securityKey)) { SigningKey = securityKey });

                return;
            }

            if (validationParameters.IssuerSigningKeyValidator != null)
            {
                if (!validationParameters.IssuerSigningKeyValidator(securityKey, securityToken, validationParameters))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSigningKeyException(LogHelper.FormatInvariant(LogMessages.IDX10232, securityKey)) { SigningKey = securityKey });

                return;
            }

            if (!validationParameters.ValidateIssuerSigningKey)
            {
                LogHelper.LogVerbose(LogMessages.IDX10237);
                return;
            }

            if (!validationParameters.RequireSignedTokens && securityKey == null)
            {
                LogHelper.LogInformation(LogMessages.IDX10252);
                return;
            }
            else if (securityKey == null)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(securityKey), LogMessages.IDX10253));
            }

            if (securityToken == null)
                throw LogHelper.LogArgumentNullException(nameof(securityToken));

            ValidateIssuerSigningKeyLifeTime(securityKey, validationParameters);
        }

        /// <summary>
        /// Given a signing key, when it's derived from a certificate, validates that the certificate is already active and non-expired
        /// </summary>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> that are used to validate the token.</param>
        internal static void ValidateIssuerSigningKeyLifeTime(SecurityKey securityKey, TokenValidationParameters validationParameters)
        {
            X509SecurityKey x509SecurityKey = securityKey as X509SecurityKey;
            if (x509SecurityKey?.Certificate is X509Certificate2 cert)
            {
                DateTime utcNow = DateTime.UtcNow;
                var notBeforeUtc = cert.NotBefore.ToUniversalTime();
                var notAfterUtc = cert.NotAfter.ToUniversalTime();

                if (notBeforeUtc > DateTimeUtil.Add(utcNow, validationParameters.ClockSkew))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSigningKeyException(LogHelper.FormatInvariant(LogMessages.IDX10248, LogHelper.MarkAsNonPII(notBeforeUtc), LogHelper.MarkAsNonPII(utcNow))));

                if (LogHelper.IsEnabled(EventLogLevel.Informational))
                    LogHelper.LogInformation(LogMessages.IDX10250, LogHelper.MarkAsNonPII(notBeforeUtc), LogHelper.MarkAsNonPII(utcNow));

                if (notAfterUtc < DateTimeUtil.Add(utcNow, validationParameters.ClockSkew.Negate()))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSigningKeyException(LogHelper.FormatInvariant(LogMessages.IDX10249, LogHelper.MarkAsNonPII(notAfterUtc), LogHelper.MarkAsNonPII(utcNow))));

                if (LogHelper.IsEnabled(EventLogLevel.Informational))
                    LogHelper.LogInformation(LogMessages.IDX10251, LogHelper.MarkAsNonPII(notAfterUtc), LogHelper.MarkAsNonPII(utcNow));
            }
        }
    }
}
