// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Text;
using Microsoft.IdentityModel.Logging;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Validators meant to be kept internal
    /// </summary>
    internal static class InternalValidators
    {
        /// <summary>
        /// Called after signature validation has failed. Will always throw an exception.
        /// </summary>
        /// <exception cref="SecurityTokenSignatureKeyNotFoundException">
        /// If the lifetime and issuer are valid
        /// </exception>
        /// <exception cref="SecurityTokenUnableToValidateException">
        /// If the lifetime or issuer are invalid
        /// </exception>
        internal static void ValidateLifetimeAndIssuerAfterSignatureNotValidatedJwt(
            SecurityToken securityToken,
            DateTime? notBefore,
            DateTime? expires,
            string kid,
            TokenValidationParameters validationParameters,
            BaseConfiguration configuration,
            StringBuilder exceptionStrings,
            int numKeysInConfiguration,
            int numKeysInTokenValidationParameters)
        {
            bool validIssuer = false;
            bool validLifetime = false;

            try
            {
                Validators.ValidateLifetime(notBefore, expires, securityToken, validationParameters);
                validLifetime = true;
            }
            catch (Exception)
            {
                // validLifetime will remain false
            }

            try
            {
                Validators.ValidateIssuer(securityToken.Issuer, securityToken, validationParameters, configuration);
                validIssuer = true;
            }
            catch (Exception)
            {
                // validIssuer will remain false
            }

            if (validLifetime && validIssuer)
                throw LogHelper.LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(LogHelper.FormatInvariant(TokenLogMessages.IDX10501,
                    LogHelper.MarkAsNonPII(kid),
                    LogHelper.MarkAsNonPII(numKeysInTokenValidationParameters),
                    LogHelper.MarkAsNonPII(numKeysInConfiguration),
                    exceptionStrings,
                    securityToken)));
            else
            {
                var validationFailure = ValidationFailure.None;

                if (!validLifetime)
                    validationFailure |= ValidationFailure.InvalidLifetime;

                if (!validIssuer)
                    validationFailure |= ValidationFailure.InvalidIssuer;

                throw LogHelper.LogExceptionMessage(new SecurityTokenUnableToValidateException(
                    validationFailure,
                    LogHelper.FormatInvariant(TokenLogMessages.IDX10516,
                    LogHelper.MarkAsNonPII(kid),
                    LogHelper.MarkAsNonPII(numKeysInTokenValidationParameters),
                    LogHelper.MarkAsNonPII(numKeysInConfiguration),
                    exceptionStrings,
                    securityToken,
                    LogHelper.MarkAsNonPII(validLifetime),
                    LogHelper.MarkAsNonPII(validIssuer))));
            }
        }

        /// <summary>
        /// Called after signature validation has failed. Will always throw an exception.
        /// </summary>
        /// <exception cref="SecurityTokenSignatureKeyNotFoundException">
        /// If the lifetime and issuer are valid
        /// </exception>
        /// <exception cref="SecurityTokenUnableToValidateException">
        /// If the lifetime or issuer are invalid
        /// </exception>
        internal static void ValidateLifetimeAndIssuerAfterSignatureNotValidatedSaml(SecurityToken securityToken, DateTime? notBefore, DateTime? expires, string keyInfo, TokenValidationParameters validationParameters, StringBuilder exceptionStrings)
        {
            bool validIssuer = false;
            bool validLifetime = false;

            try
            {
                Validators.ValidateLifetime(notBefore, expires, securityToken, validationParameters);
                validLifetime = true;
            }
            catch (Exception)
            {
                // validLifetime will remain false
            }

            try
            {
                Validators.ValidateIssuer(securityToken.Issuer, securityToken, validationParameters);
                validIssuer = true;
            }
            catch (Exception)
            {
                // validIssuer will remain false
            }

            if (validLifetime && validIssuer)
                throw LogHelper.LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(LogHelper.FormatInvariant(TokenLogMessages.IDX10513, keyInfo, exceptionStrings, securityToken)));
            else
            {
                var validationFailure = ValidationFailure.None;

                if (!validLifetime)
                    validationFailure |= ValidationFailure.InvalidLifetime;

                if (!validIssuer)
                    validationFailure |= ValidationFailure.InvalidIssuer;

                throw LogHelper.LogExceptionMessage(new SecurityTokenUnableToValidateException(
                    validationFailure,
                    LogHelper.FormatInvariant(TokenLogMessages.IDX10515, keyInfo, exceptionStrings, securityToken, LogHelper.MarkAsNonPII(validLifetime), LogHelper.MarkAsNonPII(validIssuer))));
            }
        }
    }
}
