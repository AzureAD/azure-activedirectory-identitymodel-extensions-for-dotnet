// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Partial class for Audience Validation.
    /// </summary>
    public static partial class Validators
    {
        /// <summary>
        /// Determines if the audiences found in a <see cref="SecurityToken"/> are valid.
        /// </summary>
        /// <param name="audiences">The audiences found in the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">The <see cref="CallContext"/> that contains call information.</param>
        /// <remarks>An EXACT match is required.</remarks>
        internal static ValidationResult<string, ValidationError> ValidateAudienceInternal(
            IList<string> audiences,
#pragma warning disable CA1801
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
#pragma warning restore CA1801
        {
            if (validationParameters == null)
            {
                return ValidationError.NullParameter(
                        nameof(validationParameters),
                        ValidationError.GetCurrentStackFrame());
            }

            try
            {
                ValidationResult<string, ValidationError> result = validationParameters.AudienceValidator.ValidateAudience(
                    audiences,
                    securityToken,
                    validationParameters,
                    callContext);

                if (!result.Succeeded)
                    return result.Error!.AddCurrentStackFrame();

                return result;
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new AudienceValidationError(
                    new MessageDetail(Tokens.LogMessages.IDX10270),
                    AudienceValidationFailure.ValidatorThrew,
                    ValidationError.GetCurrentStackFrame(),
                    audiences,
                    validationParameters.ValidAudiences,
                    ex);
            }
        }

        /// <summary>
        /// Determines if the audiences found in a <see cref="SecurityToken"/> are valid.
        /// </summary>
        /// <param name="tokenAudiences">The audiences found in the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">The <see cref="CallContext"/> that contains call information.</param>
        /// <remarks>An EXACT match is required.</remarks>
        public static ValidationResult<string, ValidationError> ValidateAudience(
            IList<string> tokenAudiences,
#pragma warning disable CA1801
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
#pragma warning restore CA1801
        {
            if (validationParameters == null)
            {
                return ValidationError.NullParameter(
                        nameof(validationParameters),
                        ValidationError.GetCurrentStackFrame());
            }

            if (tokenAudiences == null)
            {
                return ValidationError.NullParameter(
                    nameof(tokenAudiences),
                    ValidationError.GetCurrentStackFrame());
            }

            if (tokenAudiences.Count == 0)
            {
                return new AudienceValidationError(
                    new MessageDetail(LogMessages.IDX10206),
                    AudienceValidationFailure.NoAudienceInToken,
                    ValidationError.GetCurrentStackFrame(),
                    tokenAudiences,
                    validationParameters.ValidAudiences);
            }

            if (validationParameters.ValidAudiences.Count == 0)
            {
                return new AudienceValidationError(
                    new MessageDetail(LogMessages.IDX10268),
                    AudienceValidationFailure.NoValidationParameterAudiencesProvided,
                    ValidationError.GetCurrentStackFrame(),
                    tokenAudiences,
                    validationParameters.ValidAudiences);
            }

            ILogger logger = callContext.GetLogger();
            string? validAudience = ValidTokenAudience(
                tokenAudiences,
                validationParameters.ValidAudiences,
                validationParameters.IgnoreTrailingSlashWhenValidatingAudience,
                validationParameters.IgnoreCaseWhenValidatingAudience,
                logger);

            if (validAudience != null)
                return validAudience;

            // TODO we shouldn't be serializing here.
            if (AppContextSwitches.DoNotScrubExceptions)
                return new AudienceValidationError(
                    new MessageDetail(
                        LogMessages.IDX10215,
                        LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(tokenAudiences)),
                        LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidAudiences))),
                    AudienceValidationFailure.AudienceDidNotMatch,
                    ValidationError.GetCurrentStackFrame(),
                    tokenAudiences,
                    validationParameters.ValidAudiences);
            else
                return new AudienceValidationError(
                    new MessageDetail(
                        LogMessages.IDX10215S),
                    AudienceValidationFailure.AudienceDidNotMatch,
                    ValidationError.GetCurrentStackFrame(),
                    null,
                    null);
        }

        private static string? ValidTokenAudience(
            IList<string> tokenAudiences,
            IList<string> validAudiences,
            bool ignoreTrailingSlashWhenValidatingAudience,
            bool ignoreCaseWhenValidatingAudience,
            ILogger logger)
        {
            StringComparison comparisonType = ignoreCaseWhenValidatingAudience
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;

            for (int i = 0; i < tokenAudiences.Count; i++)
            {
                if (string.IsNullOrEmpty(tokenAudiences[i]))
                    continue;

                for (int j = 0; j < validAudiences.Count; j++)
                {
                    if (string.IsNullOrEmpty(validAudiences[j]))
                        continue;

                    if (AudienceMatches(
                        ignoreTrailingSlashWhenValidatingAudience,
                        tokenAudiences[i],
                        validAudiences[j],
                        comparisonType,
                        logger))
                    {
                        logger.AudienceValidated(tokenAudiences[i]);

                        return tokenAudiences[i];
                    }
                }
            }

            return null;
        }

        private static bool AudienceMatches(
            bool ignoreTrailingSlashWhenValidatingAudience,
            string tokenAudience,
            string validAudience,
            StringComparison comparisonType,
            ILogger logger)
        {
            if (validAudience.Length == tokenAudience.Length)
                return string.Equals(validAudience, tokenAudience, comparisonType);
            else if (ignoreTrailingSlashWhenValidatingAudience &&
                AudienceMatchesIgnoringTrailingSlash(tokenAudience, validAudience, comparisonType, logger))
                return true;

            return false;
        }

        private static bool AudienceMatchesIgnoringTrailingSlash(
            string tokenAudience,
            string validAudience,
            StringComparison comparisonType,
            ILogger logger)
        {
            int length = -1;

            if (validAudience.Length == tokenAudience.Length + 1 && validAudience.EndsWith("/", StringComparison.InvariantCulture))
                length = validAudience.Length - 1;
            else if (tokenAudience.Length == validAudience.Length + 1 && tokenAudience.EndsWith("/", StringComparison.InvariantCulture))
                length = tokenAudience.Length - 1;

            // the length of the audiences is different by more than 1 and neither ends in a "/"
            if (length == -1)
                return false;

            if (string.Compare(validAudience, 0, tokenAudience, 0, length, comparisonType) == 0)
            {
                logger.AudienceValidated(tokenAudience);

                return true;
            }

            return false;
        }
    }
}
#nullable disable
