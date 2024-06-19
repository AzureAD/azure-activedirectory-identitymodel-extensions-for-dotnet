// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Definition for delegate that will validate the audiences value in a token.
    /// </summary>
    /// <param name="audiences">The audiences to validate.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
    /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
    /// <param name="callContext"></param>
    /// <returns>A <see cref="IssuerValidationResult"/>that contains the results of validating the issuer.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
    internal delegate AudienceValidationResult ValidateAudience(
        IEnumerable<string> audiences,
        SecurityToken securityToken,
        TokenValidationParameters validationParameters,
        CallContext callContext);

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
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <exception cref="ArgumentNullException">If 'validationParameters' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'audiences' is null and <see cref="TokenValidationParameters.ValidateAudience"/> is true.</exception>
        /// <exception cref="SecurityTokenInvalidAudienceException">If <see cref="TokenValidationParameters.ValidAudience"/> is null or whitespace and <see cref="TokenValidationParameters.ValidAudiences"/> is null.</exception>
        /// <exception cref="SecurityTokenInvalidAudienceException">If none of the 'audiences' matched either <see cref="TokenValidationParameters.ValidAudience"/> or one of <see cref="TokenValidationParameters.ValidAudiences"/>.</exception>
        /// <remarks>An EXACT match is required.</remarks>
        public static void ValidateAudience(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.AudienceValidator != null)
            {
                if (!validationParameters.AudienceValidator(audiences, securityToken, validationParameters))
                    throw LogHelper.LogExceptionMessage(
                        new SecurityTokenInvalidAudienceException(
                            LogHelper.FormatInvariant(
                                LogMessages.IDX10231,
                                LogHelper.MarkAsUnsafeSecurityArtifact(securityToken, t => t.ToString())))
                        {
                            InvalidAudience = Utility.SerializeAsSingleCommaDelimitedString(audiences)
                        });

                return;
            }

            if (!validationParameters.ValidateAudience)
            {
                LogHelper.LogWarning(LogMessages.IDX10233);
                return;
            }

            if (audiences == null)
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidAudienceException(LogMessages.IDX10207) { InvalidAudience = null });

            if (string.IsNullOrWhiteSpace(validationParameters.ValidAudience) && (validationParameters.ValidAudiences == null))
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidAudienceException(LogMessages.IDX10208) { InvalidAudience = Utility.SerializeAsSingleCommaDelimitedString(audiences) });

            if (!audiences.Any())
                throw LogHelper.LogExceptionMessage(
                    new SecurityTokenInvalidAudienceException(LogHelper.FormatInvariant(LogMessages.IDX10206))
                    { InvalidAudience = Utility.SerializeAsSingleCommaDelimitedString(audiences) });

            // create enumeration of all valid audiences from validationParameters
            IEnumerable<string> validationParametersAudiences;

            if (validationParameters.ValidAudiences == null)
                validationParametersAudiences = new[] { validationParameters.ValidAudience };
            else if (string.IsNullOrWhiteSpace(validationParameters.ValidAudience))
                validationParametersAudiences = validationParameters.ValidAudiences;
            else
                validationParametersAudiences = validationParameters.ValidAudiences.Concat(new[] { validationParameters.ValidAudience });

            if (AudienceIsValid(audiences, validationParameters, validationParametersAudiences))
                return;

            SecurityTokenInvalidAudienceException ex = new SecurityTokenInvalidAudienceException(
                LogHelper.FormatInvariant(LogMessages.IDX10214,
                    LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(audiences)),
                    LogHelper.MarkAsNonPII(validationParameters.ValidAudience ?? "null"),
                    LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidAudiences))))
            { InvalidAudience = Utility.SerializeAsSingleCommaDelimitedString(audiences) };

            if (!validationParameters.LogValidationExceptions)
                throw ex;

            throw LogHelper.LogExceptionMessage(ex);
        }


#nullable enable
        /// <summary>
        /// Determines if the audiences found in a <see cref="SecurityToken"/> are valid.
        /// </summary>
        /// <param name="audiences">The audiences found in the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <param name="callContext"></param>
        /// <exception cref="ArgumentNullException">If 'validationParameters' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'audiences' is null and <see cref="TokenValidationParameters.ValidateAudience"/> is true.</exception>
        /// <exception cref="SecurityTokenInvalidAudienceException">If <see cref="TokenValidationParameters.ValidAudience"/> is null or whitespace and <see cref="TokenValidationParameters.ValidAudiences"/> is null.</exception>
        /// <exception cref="SecurityTokenInvalidAudienceException">If none of the 'audiences' matched either <see cref="TokenValidationParameters.ValidAudience"/> or one of <see cref="TokenValidationParameters.ValidAudiences"/>.</exception>
        /// <remarks>An EXACT match is required.</remarks>
#pragma warning disable CA1801 // TODO: remove pragma disable once callContext is used for logging
        internal static AudienceValidationResult ValidateAudience(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters, CallContext callContext)
#pragma warning restore CA1801
        {
            if (validationParameters == null)
                return new AudienceValidationResult(
                    Utility.SerializeAsSingleCommaDelimitedString(audiences),
                    ValidationFailureType.NullArgument,
                    new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10000,
                            LogHelper.MarkAsNonPII(nameof(validationParameters))),
                        typeof(ArgumentNullException),
                        new StackFrame(true)));

            if (!validationParameters.ValidateAudience)
            {
                LogHelper.LogWarning(LogMessages.IDX10233);
                return new AudienceValidationResult(Utility.SerializeAsSingleCommaDelimitedString(audiences));
            }

            if (securityToken == null)
                return new AudienceValidationResult(
                    Utility.SerializeAsSingleCommaDelimitedString(audiences),
                    ValidationFailureType.NullArgument,
                    new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10000,
                            LogHelper.MarkAsNonPII(nameof(securityToken))),
                        typeof(ArgumentNullException),
                        new StackFrame(true),
                        null));

            if (audiences == null)
                return new AudienceValidationResult(
                    Utility.SerializeAsSingleCommaDelimitedString(audiences),
                    ValidationFailureType.NullArgument,
                    new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10207,
                            null),
                        typeof(SecurityTokenInvalidAudienceException),
                        new StackFrame(true)));

            if (string.IsNullOrWhiteSpace(validationParameters.ValidAudience) && (validationParameters.ValidAudiences == null))
                return new AudienceValidationResult(
                    Utility.SerializeAsSingleCommaDelimitedString(audiences),
                    ValidationFailureType.NullArgument,
                    new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10208,
                            null),
                        typeof(SecurityTokenInvalidAudienceException),
                        new StackFrame(true)));

            if (!audiences.Any())
                return new AudienceValidationResult(
                    Utility.SerializeAsSingleCommaDelimitedString(audiences),
                    ValidationFailureType.NullArgument,
                    new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10206,
                            null),
                        typeof(SecurityTokenInvalidAudienceException),
                        new StackFrame(true)));

            // create enumeration of all valid audiences from validationParameters
            IEnumerable<string> validationParametersAudiences;

            if (validationParameters.ValidAudiences == null)
                validationParametersAudiences = new[] { validationParameters.ValidAudience };
            else if (string.IsNullOrWhiteSpace(validationParameters.ValidAudience))
                validationParametersAudiences = validationParameters.ValidAudiences;
            else
                validationParametersAudiences = validationParameters.ValidAudiences.Concat(new[] { validationParameters.ValidAudience });

            string? validAudience = AudienceIsValidReturning(audiences, validationParameters, validationParametersAudiences);
            if (validAudience != null)
            {
                return new AudienceValidationResult(validAudience);
            }

            return new AudienceValidationResult(
                    Utility.SerializeAsSingleCommaDelimitedString(audiences),
                    ValidationFailureType.AudienceValidationFailed,
                    new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10214,
                            LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(audiences)),
                            LogHelper.MarkAsNonPII(validationParameters.ValidAudience ?? "null"),
                            LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidAudiences))),
                        typeof(SecurityTokenInvalidAudienceException),
                        new StackFrame(true)));
        }

        private static bool AudienceIsValid(IEnumerable<string> audiences, TokenValidationParameters validationParameters, IEnumerable<string> validationParametersAudiences)
        {
            return AudienceIsValidReturning(audiences, validationParameters, validationParametersAudiences) != null;
        }

        private static string? AudienceIsValidReturning(IEnumerable<string> audiences, TokenValidationParameters validationParameters, IEnumerable<string> validationParametersAudiences)
        {
            foreach (string tokenAudience in audiences)
            {
                if (string.IsNullOrWhiteSpace(tokenAudience))
                    continue;

                foreach (string validAudience in validationParametersAudiences)
                {
                    if (string.IsNullOrWhiteSpace(validAudience))
                        continue;

                    if (AudiencesMatch(validationParameters, tokenAudience, validAudience))
                    {
                        if (LogHelper.IsEnabled(EventLogLevel.Informational))
                            LogHelper.LogInformation(LogMessages.IDX10234, LogHelper.MarkAsNonPII(tokenAudience));

                        return validAudience;
                    }
                }
            }

            return null;
        }
#nullable disable

        private static bool AudiencesMatch(TokenValidationParameters validationParameters, string tokenAudience, string validAudience)
        {
            if (validAudience.Length == tokenAudience.Length)
            {
                if (string.Equals(validAudience, tokenAudience))
                    return true;
            }
            else if (validationParameters.IgnoreTrailingSlashWhenValidatingAudience && AudiencesMatchIgnoringTrailingSlash(tokenAudience, validAudience))
                return true;

            return false;
        }

        private static bool AudiencesMatchIgnoringTrailingSlash(string tokenAudience, string validAudience)
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