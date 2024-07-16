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
        /// <param name="validationParameters"><see cref="ValidationParameters"/> required for validation.</param>
        /// <param name="callContext"></param>
        /// <exception cref="ArgumentNullException">If <paramref name="validationParameters"/> is null.</exception>
        /// <exception cref="ArgumentNullException">If <paramref name="securityToken"/> is null.</exception>
        /// <exception cref="SecurityTokenInvalidTypeException">If <paramref name="type"/> is null or whitespace and <see cref="ValidationParameters.ValidTypes"/> is not null.</exception>
        /// <exception cref="SecurityTokenInvalidTypeException">If <paramref name="type"/> failed to match <see cref="ValidationParameters.ValidTypes"/>.</exception>
        /// <remarks>An EXACT match is required. <see cref="StringComparison.Ordinal"/> (case sensitive) is used for comparing <paramref name="type"/> against <see cref="TokenValidationParameters.ValidTypes"/>.</remarks>
#pragma warning disable CA1801 // TODO: remove pragma disable once callContext is used for logging
        internal static TokenTypeValidationResult ValidateTokenType(
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
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

            if (validationParameters.ValidTypes == null || validationParameters.ValidTypes.Count == 0)
            {
                LogHelper.LogVerbose(LogMessages.IDX10255);
                return new TokenTypeValidationResult(type);
            }

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
    }
}
#nullable restore
