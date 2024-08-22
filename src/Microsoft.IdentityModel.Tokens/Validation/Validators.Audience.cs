// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Definition for delegate that will validate the audiences value in a token.
    /// </summary>
    /// <param name="audiences">The audiences to validate.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <param name="callContext"></param>
    /// <returns>A <see cref="Result{TResult, TError}"/>that contains the results of validating the issuer.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
    internal delegate Result<string, TokenValidationError> AudienceValidatorDelegate(
        IList<string> audiences,
        SecurityToken? securityToken,
        ValidationParameters validationParameters,
        CallContext callContext);

    /// <summary>
    /// Partial class for Audience Validation.
    /// </summary>
    public static partial class Validators
    {
        /// <summary>
        /// Determines if the audiences found in a <see cref="SecurityToken"/> are valid.
        /// </summary>
        /// <param name="tokenAudiences">The audiences found in the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext"></param>
        /// <exception cref="ArgumentNullException">If 'validationParameters' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'audiences' is null and <see cref="TokenValidationParameters.ValidateAudience"/> is true.</exception>
        /// <exception cref="SecurityTokenInvalidAudienceException">If <see cref="TokenValidationParameters.ValidAudience"/> is null or whitespace and <see cref="TokenValidationParameters.ValidAudiences"/> is null.</exception>
        /// <exception cref="SecurityTokenInvalidAudienceException">If none of the 'audiences' matched either <see cref="TokenValidationParameters.ValidAudience"/> or one of <see cref="TokenValidationParameters.ValidAudiences"/>.</exception>
        /// <remarks>An EXACT match is required.</remarks>
#pragma warning disable CA1801 // TODO: remove pragma disable once callContext is used for logging
        internal static Result<string, TokenValidationError> ValidateAudience(IList<string> tokenAudiences, SecurityToken? securityToken, ValidationParameters validationParameters, CallContext callContext)
#pragma warning restore CA1801
        {
            if (validationParameters == null)
                return TokenValidationErrorCommon.NullParameter(nameof(validationParameters));

            if (tokenAudiences == null)
                return TokenValidationErrorCommon.NullParameter(nameof(tokenAudiences));

            if (tokenAudiences.Count == 0)
                return new TokenValidationError(
                    ValidationErrorType.SecurityTokenInvalidAudience,
                    new MessageDetail(LogMessages.IDX10206),
                    null);

            string? validAudience = ValidTokenAudience(tokenAudiences, validationParameters.ValidAudiences, validationParameters.IgnoreTrailingSlashWhenValidatingAudience);
            if (validAudience != null)
                return validAudience;

            return new TokenValidationError(
                ValidationErrorType.SecurityTokenInvalidAudience,
                new MessageDetail(
                    LogMessages.IDX10215,
                    LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(tokenAudiences)),
                    LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidAudiences))),
                null);
        }

        private static string? ValidTokenAudience(IList<string> tokenAudiences, IList<string> validAudiences, bool ignoreTrailingSlashWhenValidatingAudience)
        {
            for (int i = 0; i < tokenAudiences.Count; i++)
            {
                string tokenAudience = tokenAudiences[i];
                if (string.IsNullOrEmpty(tokenAudience))
                    continue;

                for (int j = 0; j < validAudiences.Count; j++)
                {
                    if (string.IsNullOrEmpty(validAudiences[j]))
                        continue;


                    if (AudienceMatches(ignoreTrailingSlashWhenValidatingAudience, tokenAudience, validAudiences[j]))
                    {
                        if (LogHelper.IsEnabled(EventLogLevel.Informational))
                            LogHelper.LogInformation(LogMessages.IDX10234, LogHelper.MarkAsNonPII(tokenAudience));

                        return tokenAudience;
                    }
                }
            }

            return null;
        }

        private static bool AudienceMatches(bool ignoreTrailingSlashWhenValidatingAudience, string tokenAudience, string validAudience)
        {
            if (validAudience.Length == tokenAudience.Length)
                return string.Equals(validAudience, tokenAudience);
            else if (ignoreTrailingSlashWhenValidatingAudience && AudienceMatchesIgnoringTrailingSlash(tokenAudience, validAudience))
                return true;

            return false;
        }

        private static bool AudienceMatchesIgnoringTrailingSlash(string tokenAudience, string validAudience)
        {
            int length = -1;

            if (validAudience.Length == tokenAudience.Length + 1 && validAudience.EndsWith("/", StringComparison.InvariantCulture))
                length = validAudience.Length - 1;
            else if (tokenAudience.Length == validAudience.Length + 1 && tokenAudience.EndsWith("/", StringComparison.InvariantCulture))
                length = tokenAudience.Length - 1;

            // the length of the audiences is different by more than 1 and neither ends in a "/"
            if (length == -1)
                return false;

            if (string.CompareOrdinal(validAudience, 0, tokenAudience, 0, length) == 0)
            {
                if (LogHelper.IsEnabled(EventLogLevel.Informational))
                    LogHelper.LogInformation(LogMessages.IDX10234, LogHelper.MarkAsNonPII(tokenAudience));

                return true;
            }

            return false;
        }

    }
}
#nullable disable
