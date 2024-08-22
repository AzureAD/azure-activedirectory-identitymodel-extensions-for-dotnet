// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Linq;
using Microsoft.IdentityModel.Abstractions;

//using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal record struct ValidatedTokenType(string Type, int ValidTypeCount);
    /// <summary>
    /// Definition for delegate that will validate the token type of a token.
    /// </summary>
    /// <param name="type">The token type or <c>null</c> if it couldn't be resolved (e.g from the 'typ' header for a JWT).</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
    /// <param name="validationParameters"><see cref="ValidationParameters"/> required for validation.</param>
    /// <param name="callContext"></param>
    /// <returns> A <see cref="Result{TResult, TError}"/>that contains the results of validating the token type.</returns>
    /// <remarks>An EXACT match is required. <see cref="StringComparison.Ordinal"/> (case sensitive) is used for comparing <paramref name="type"/> against <see cref="ValidationParameters.ValidTypes"/>.</remarks>
    internal delegate Result<ValidatedTokenType, TokenValidationError> TypeValidatorDelegate(
        string? type,
        SecurityToken? securityToken,
        ValidationParameters validationParameters,
        CallContext callContext);

    public static partial class Validators
    {
        /// <summary>
        /// Validates the type of the token.
        /// </summary>
        /// <param name="type">The token type or <c>null</c> if it couldn't be resolved (e.g from the 'typ' header for a JWT).</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters"><see cref="ValidationParameters"/> required for validation.</param>
        /// <param name="callContext"></param>
        /// <returns> A <see cref="Result{TResult, TError}"/>that contains the results of validating the token type.</returns>
        /// <remarks>An EXACT match is required. <see cref="StringComparison.Ordinal"/> (case sensitive) is used for comparing <paramref name="type"/> against <see cref="ValidationParameters.ValidTypes"/>.</remarks>
#pragma warning disable CA1801 // TODO: remove pragma disable once callContext is used for logging
        internal static Result<ValidatedTokenType, TokenValidationError> ValidateTokenType(
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
#pragma warning restore CA1801 // TODO: remove pragma disable once callContext is used for logging
        {
            if (securityToken == null)
                return TokenValidationErrorCommon.NullParameter(nameof(securityToken));

            if (validationParameters == null)
                return TokenValidationErrorCommon.NullParameter(nameof(validationParameters));

            if (validationParameters.ValidTypes.Count == 0)
            {
                LogHelper.LogVerbose(LogMessages.IDX10255);
                return new ValidatedTokenType(type ?? "null", validationParameters.ValidTypes.Count);
            }

            if (string.IsNullOrEmpty(type))
                return new TokenValidationError(
                    ValidationErrorType.SecurityTokenInvalidType,
                    new MessageDetail(LogMessages.IDX10256),
                    null);

            if (!validationParameters.ValidTypes.Contains(type, StringComparer.Ordinal))
            {
                return new TokenValidationError(
                    ValidationErrorType.SecurityTokenInvalidType,
                    new MessageDetail(
                        LogMessages.IDX10257,
                        LogHelper.MarkAsNonPII(type),
                        LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidTypes))),
                    null);
            }

            // TODO: Move to CallContext
            //if (LogHelper.IsEnabled(EventLogLevel.Informational))
            //    LogHelper.LogInformation(LogMessages.IDX10258, LogHelper.MarkAsNonPII(type));

            return new ValidatedTokenType(type!, validationParameters.ValidTypes.Count);
        }
    }
}
#nullable restore
