// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.Linq;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    public static partial class Validators
    {
        /// <summary>
        /// Validates the type of the token.
        /// </summary>
        /// <param name="type">The token type or <c>null</c> if it couldn't be resolved (e.g from the 'typ' header for a JWT).</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="validationParameters"/> is null.</exception>
        /// <exception cref="ArgumentNullException">If <paramref name="securityToken"/> is null.</exception>
        /// <exception cref="SecurityTokenInvalidTypeException">If <paramref name="type"/> is null or whitespace and <see cref="TokenValidationParameters.ValidTypes"/> is not null.</exception>
        /// <exception cref="SecurityTokenInvalidTypeException">If <paramref name="type"/> failed to match <see cref="TokenValidationParameters.ValidTypes"/>.</exception>
        /// <remarks>An EXACT match is required. <see cref="StringComparison.Ordinal"/> (case sensitive) is used for comparing <paramref name="type"/> against <see cref="TokenValidationParameters.ValidTypes"/>.</remarks>
        /// <returns>The actual token type, that may be the same as <paramref name="type"/> or a different value if the token type was resolved from a different location.</returns>
        public static string ValidateTokenType(string type, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (securityToken == null)
                throw new ArgumentNullException(nameof(securityToken));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.TypeValidator == null && (validationParameters.ValidTypes == null || !validationParameters.ValidTypes.Any()))
            {
                LogHelper.LogVerbose(LogMessages.IDX10255);
                return type;
            }

            if (validationParameters.TypeValidator != null)
                return validationParameters.TypeValidator(type, securityToken, validationParameters);

            // Note: don't throw an exception for a null or empty token type when a user-defined delegate is set
            // to allow it to extract the actual token type from a different location (e.g from the claims).
            if (string.IsNullOrEmpty(type))
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidTypeException(LogMessages.IDX10256) { InvalidType = null });

            if (!validationParameters.ValidTypes.Contains(type, StringComparer.Ordinal))
            {
                throw LogHelper.LogExceptionMessage(
                    new SecurityTokenInvalidTypeException(LogHelper.FormatInvariant(LogMessages.IDX10257, LogHelper.MarkAsNonPII(type), Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidTypes)))
                    { InvalidType = type });
            }

            // if it reaches here, token type was succcessfully validated.
            if (LogHelper.IsEnabled(EventLogLevel.Informational))
                LogHelper.LogInformation(LogMessages.IDX10258, LogHelper.MarkAsNonPII(type));

            return type;
        }

        /// <summary>
        /// Validates the type of the token.
        /// </summary>
        /// <param name="type">The token type or <c>null</c> if it couldn't be resolved (e.g from the 'typ' header for a JWT).</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <param name="callContext"></param>
        /// <exception cref="ArgumentNullException">If <paramref name="validationParameters"/> is null.</exception>
        /// <exception cref="ArgumentNullException">If <paramref name="securityToken"/> is null.</exception>
        /// <exception cref="SecurityTokenInvalidTypeException">If <paramref name="type"/> is null or whitespace and <see cref="TokenValidationParameters.ValidTypes"/> is not null.</exception>
        /// <exception cref="SecurityTokenInvalidTypeException">If <paramref name="type"/> failed to match <see cref="TokenValidationParameters.ValidTypes"/>.</exception>
        /// <remarks>An EXACT match is required. <see cref="StringComparison.Ordinal"/> (case sensitive) is used for comparing <paramref name="type"/> against <see cref="TokenValidationParameters.ValidTypes"/>.</remarks>
#pragma warning disable CA1801 // TODO: remove pragma disable once callContext is used for logging
        internal static TokenTypeValidationResult ValidateTokenType(string? type, SecurityToken? securityToken, TokenValidationParameters validationParameters, CallContext callContext)
#pragma warning restore CA1801 // TODO: remove pragma disable once callContext is used for logging
        {
            if (securityToken == null)
            {
                return new TokenTypeValidationResult(
                    type,
                    ValidationFailureType.NullArgument,
                    new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10000,
                            LogHelper.MarkAsNonPII(nameof(securityToken))),
                        typeof(ArgumentNullException),
                        new StackFrame(true)));
            }

            if (validationParameters == null)
            {
                return new TokenTypeValidationResult(
                    type,
                    ValidationFailureType.NullArgument,
                    new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10000,
                            LogHelper.MarkAsNonPII(nameof(validationParameters))),
                        typeof(ArgumentNullException),
                        new StackFrame(true)));
            }

            if (validationParameters.TypeValidator == null && (validationParameters.ValidTypes == null || !validationParameters.ValidTypes.Any()))
            {
                LogHelper.LogVerbose(LogMessages.IDX10255);
                return new TokenTypeValidationResult(type);
            }

            if (validationParameters.TypeValidator != null)
            {
                return ValidateTokenTypeUsingDelegate(type, securityToken, validationParameters);
            }

            // Note: don't return an invalid TokenTypeValidationResult for a null or empty token type when a user-defined delegate is set
            // to allow it to extract the actual token type from a different location (e.g from the claims).
            if (string.IsNullOrEmpty(type))
            {
                return new TokenTypeValidationResult(
                    type,
                    ValidationFailureType.TokenTypeValidationFailed,
                    new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10256,
                            LogHelper.MarkAsNonPII(nameof(type))),
                        typeof(SecurityTokenInvalidTypeException),
                        new StackFrame(true)));
            }

            if (!validationParameters.ValidTypes.Contains(type, StringComparer.Ordinal))
            {
                return new TokenTypeValidationResult(
                     type,
                     ValidationFailureType.TokenTypeValidationFailed,
                     new ExceptionDetail(
                         new MessageDetail(
                             LogMessages.IDX10257,
                             LogHelper.MarkAsNonPII(nameof(type)),
                             LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidTypes))),
                         typeof(SecurityTokenInvalidTypeException),
                         new StackFrame(true)));
            }

            if (LogHelper.IsEnabled(EventLogLevel.Informational))
            {
                LogHelper.LogInformation(LogMessages.IDX10258, LogHelper.MarkAsNonPII(type));
            }

            return new TokenTypeValidationResult(type);
        }

        private static TokenTypeValidationResult ValidateTokenTypeUsingDelegate(string? type, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            try
            {
                var validatedType = validationParameters.TypeValidator(type, securityToken, validationParameters);
                return new TokenTypeValidationResult(validatedType);
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new TokenTypeValidationResult(
                    type,
                    ValidationFailureType.TokenTypeValidationFailed,
                    new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10259,
                            LogHelper.MarkAsNonPII(nameof(validationParameters.TypeValidator)),
                            LogHelper.MarkAsNonPII(ex.Message)),
                        ex.GetType(),
                        new StackFrame(true),
                        ex));
            }
        }
    }
}
#nullable restore
