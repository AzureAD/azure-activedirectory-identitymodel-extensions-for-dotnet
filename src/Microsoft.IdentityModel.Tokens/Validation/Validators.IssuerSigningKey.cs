// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Logging;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal record struct ValidatedSigningKeyLifetime(DateTime? ValidFrom, DateTime? ValidTo, DateTime? ValidationTime);

    /// <summary>
    /// Definition for delegate that will validate the <see cref="SecurityKey"/> that signed a <see cref="SecurityToken"/>.
    /// </summary>
    /// <param name="signingKey">The security key to validate.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
    /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
    /// <param name="configuration">The <see cref="BaseConfiguration"/> to be used for validation.</param>
    /// <param name="callContext">The <see cref="CallContext"/> to be used for logging.</param> 
    /// <returns>A <see cref="Result{TResult, TError}"/>that contains the results of validating the issuer.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
    internal delegate Result<ValidatedSigningKeyLifetime, ExceptionDetail> IssuerSigningKeyValidatorDelegate(
        SecurityKey signingKey,
        SecurityToken securityToken,
        ValidationParameters validationParameters,
        BaseConfiguration? configuration,
        CallContext? callContext);

    /// <summary>
    /// SigningKeyValidation
    /// </summary>

    public static partial class Validators
    {
        /// <summary>
        /// Validates the <see cref="SecurityKey"/> that signed a <see cref="SecurityToken"/>.
        /// </summary>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="configuration">The <see cref="BaseConfiguration"/> to be used for validation.</param>
        /// <param name="callContext">The <see cref="CallContext"/> to be used for logging.</param>
        /// <exception cref="ArgumentNullException"> if 'securityKey' is null and ValidateIssuerSigningKey is true.</exception>
        /// <exception cref="ArgumentNullException"> if 'securityToken' is null and ValidateIssuerSigningKey is true.</exception>
        /// <exception cref="ArgumentNullException"> if 'validationParameters' is null.</exception>
        internal static Result<ValidatedSigningKeyLifetime, ExceptionDetail> ValidateIssuerSigningKey(
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
#pragma warning disable CA1801 // Review unused parameters
            BaseConfiguration? configuration,
#pragma warning restore CA1801 // Review unused parameters
            CallContext? callContext)
        {
            if (validationParameters == null)
                return ExceptionDetail.NullParameter(
                    nameof(validationParameters),
                    new StackFrame(true));

            if (securityKey == null)
                return new ExceptionDetail(
                    new MessageDetail(LogMessages.IDX10253, nameof(securityKey)),
                    ValidationFailureType.SigningKeyValidationFailed,
                    ExceptionType.ArgumentNull,
                    new StackFrame(true));

            if (securityToken == null)
                return ExceptionDetail.NullParameter(
                    nameof(securityToken),
                    new StackFrame(true));

            return ValidateIssuerSigningKeyLifeTime(securityKey, validationParameters, callContext);
        }

        /// <summary>
        /// Given a signing key, when it's derived from a certificate, validates that the certificate is already active and non-expired
        /// </summary>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext"></param>
#pragma warning disable CA1801 // Review unused parameters
        internal static Result<ValidatedSigningKeyLifetime, ExceptionDetail> ValidateIssuerSigningKeyLifeTime(
            SecurityKey securityKey,
            ValidationParameters validationParameters,
            CallContext? callContext)
#pragma warning restore CA1801 // Review unused parameters
        {
            DateTime utcNow = DateTime.UtcNow;
            DateTime? notBeforeUtc = null;
            DateTime? notAfterUtc = null;
            X509SecurityKey? x509SecurityKey = securityKey as X509SecurityKey;

            if (x509SecurityKey?.Certificate is X509Certificate2 cert)
            {
                notBeforeUtc = cert.NotBefore.ToUniversalTime();
                notAfterUtc = cert.NotAfter.ToUniversalTime();

                if (notBeforeUtc > DateTimeUtil.Add(utcNow, validationParameters.ClockSkew))
                    return new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10248,
                            LogHelper.MarkAsNonPII(notBeforeUtc),
                            LogHelper.MarkAsNonPII(utcNow)),
                        ValidationFailureType.SigningKeyValidationFailed,
                        ExceptionType.SecurityTokenInvalidSigningKey,
                        new StackFrame(true));

                //TODO: Move to CallContext
                //if (LogHelper.IsEnabled(EventLogLevel.Informational))
                //    LogHelper.LogInformation(LogMessages.IDX10250, LogHelper.MarkAsNonPII(notBeforeUtc), LogHelper.MarkAsNonPII(utcNow));

                if (notAfterUtc < DateTimeUtil.Add(utcNow, validationParameters.ClockSkew.Negate()))
                    return new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10249,
                            LogHelper.MarkAsNonPII(notAfterUtc),
                            LogHelper.MarkAsNonPII(utcNow)),
                        ValidationFailureType.SigningKeyValidationFailed,
                        ExceptionType.SecurityTokenInvalidSigningKey,
                        new StackFrame(true));

                // TODO: Move to CallContext
                //if (LogHelper.IsEnabled(EventLogLevel.Informational))
                //   LogHelper.LogInformation(LogMessages.IDX10251, LogHelper.MarkAsNonPII(notAfterUtc), LogHelper.MarkAsNonPII(utcNow));
            }

            return new ValidatedSigningKeyLifetime(notBeforeUtc, notAfterUtc, utcNow);
        }
    }
}
#nullable restore
