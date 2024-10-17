// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Definition for delegate that will validate the audiences value in a token.
    /// </summary>
    /// <param name="tokenAudiences">The audiences found in the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <param name="callContext"></param>
    /// <returns>A <see cref="ValidationResult{TResult}"/>that contains the results of validating the issuer.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
    internal delegate ValidationResult<string> AudienceValidationDelegate(
        IList<string> tokenAudiences,
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
        internal static ValidationResult<string> ValidateAudience(IList<string> tokenAudiences, SecurityToken? securityToken, ValidationParameters validationParameters, CallContext callContext)
#pragma warning restore CA1801
        {
            if (validationParameters == null)
            {
                AudienceValidationError.ValidationParametersNull ??= new StackFrame(true);
                return new AudienceValidationError(
                    MessageDetail.NullParameter(nameof(validationParameters)),
                    ValidationFailureType.NullArgument,
                    typeof(SecurityTokenArgumentNullException),
                    AudienceValidationError.ValidationParametersNull,
                    tokenAudiences,
                    null);
            }

            if (tokenAudiences == null)
            {
                AudienceValidationError.AudiencesNull ??= new StackFrame(true);
                return new AudienceValidationError(
                    MessageDetail.NullParameter(nameof(tokenAudiences)),
                    ValidationFailureType.NullArgument,
                    typeof(SecurityTokenArgumentNullException),
                    AudienceValidationError.AudiencesNull,
                    tokenAudiences,
                    validationParameters.ValidAudiences);
            }

            if (tokenAudiences.Count == 0)
            {
                AudienceValidationError.AudiencesCountZero ??= new StackFrame(true);
                return new AudienceValidationError(
                    new MessageDetail(LogMessages.IDX10206),
                    ValidationFailureType.NoTokenAudiencesProvided,
                    typeof(SecurityTokenInvalidAudienceException),
                    AudienceValidationError.AudiencesCountZero,
                    tokenAudiences,
                    validationParameters.ValidAudiences);
            }

            if (validationParameters.ValidAudiences.Count == 0)
            {
                AudienceValidationError.ValidationParametersAudiencesCountZero ??= new StackFrame(true);
                return new AudienceValidationError(
                        new MessageDetail(LogMessages.IDX10268),
                        ValidationFailureType.NoValidationParameterAudiencesProvided,
                        typeof(SecurityTokenInvalidAudienceException),
                        AudienceValidationError.ValidationParametersAudiencesCountZero,
                        tokenAudiences,
                        validationParameters.ValidAudiences);
            }

            string? validAudience = ValidTokenAudience(tokenAudiences, validationParameters.ValidAudiences, validationParameters.IgnoreTrailingSlashWhenValidatingAudience);
            if (validAudience != null)
                return validAudience;

            // TODO we shouldn't be serializing here.
            AudienceValidationError.ValidateAudienceFailed ??= new StackFrame(true);
            return new AudienceValidationError(
                new MessageDetail(
                    LogMessages.IDX10215,
                    LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(tokenAudiences)),
                    LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidAudiences))),
                ValidationFailureType.AudienceValidationFailed,
                typeof(SecurityTokenInvalidAudienceException),
                AudienceValidationError.ValidateAudienceFailed,
                tokenAudiences,
                validationParameters.ValidAudiences);
        }

        private static string? ValidTokenAudience(IList<string> tokenAudiences, IList<string> validAudiences, bool ignoreTrailingSlashWhenValidatingAudience)
        {
            for (int i = 0; i < tokenAudiences.Count; i++)
            {
                if (string.IsNullOrEmpty(tokenAudiences[i]))
                    continue;

                for (int j = 0; j < validAudiences.Count; j++)
                {
                    if (string.IsNullOrEmpty(validAudiences[j]))
                        continue;

                    if (AudienceMatches(ignoreTrailingSlashWhenValidatingAudience, tokenAudiences[i], validAudiences[j]))
                    {
                        if (LogHelper.IsEnabled(EventLogLevel.Informational))
                            LogHelper.LogInformation(LogMessages.IDX10234, LogHelper.MarkAsNonPII(tokenAudiences[i]));

                        return tokenAudiences[i];
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
