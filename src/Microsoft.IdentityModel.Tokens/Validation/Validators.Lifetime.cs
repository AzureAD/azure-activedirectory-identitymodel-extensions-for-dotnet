// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using Microsoft.IdentityModel.Logging;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    internal record struct ValidatedLifetime(DateTime? NotBefore, DateTime? Expires);

    /// <summary>
    /// Definition for delegate that will validate the lifetime of a <see cref="SecurityToken"/>.
    /// </summary>
    /// <param name="notBefore">The 'notBefore' time found in the <see cref="SecurityToken"/>.</param>
    /// <param name="expires">The 'expiration' time found in the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <param name="callContext"></param>
    /// <returns>A <see cref="ValidationResult{TResult}"/>that contains the results of validating the issuer.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
    internal delegate ValidationResult<ValidatedLifetime> LifetimeValidatorDelegate(
        DateTime? notBefore,
        DateTime? expires,
        SecurityToken? securityToken,
        ValidationParameters validationParameters,
        CallContext callContext);

    /// <summary>
    /// IssuerValidation
    /// </summary>
    public static partial class Validators
    {
        /// <summary>
        /// Validates the lifetime of a <see cref="SecurityToken"/>.
        /// </summary>
        /// <param name="notBefore">The 'notBefore' time found in the <see cref="SecurityToken"/>.</param>
        /// <param name="expires">The 'expiration' time found in the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext"></param>
        /// <returns>A <see cref="ValidationResult{TResult}"/> indicating whether validation was successful, and providing a <see cref="SecurityTokenInvalidLifetimeException"/> if it was not.</returns>
        /// <exception cref="ArgumentNullException">If 'validationParameters' is null.</exception>
        /// <exception cref="SecurityTokenNoExpirationException">If 'expires.HasValue' is false.</exception>
        /// <exception cref="SecurityTokenInvalidLifetimeException">If 'notBefore' is &gt; 'expires'.</exception>
        /// <exception cref="SecurityTokenNotYetValidException">If 'notBefore' is &gt; DateTime.UtcNow.</exception>
        /// <exception cref="SecurityTokenExpiredException">If 'expires' is &lt; DateTime.UtcNow.</exception>
        /// <remarks>All time comparisons apply <see cref="ValidationParameters.ClockSkew"/>.</remarks>
#pragma warning disable CA1801 // TODO: remove pragma disable once callContext is used for logging
        internal static ValidationResult<ValidatedLifetime> ValidateLifetime(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
#pragma warning restore CA1801
        {
            if (validationParameters == null)
                return ValidationError.NullParameter(
                    nameof(validationParameters),
                    new StackFrame(true));

            if (!expires.HasValue)
                return new LifetimeValidationError(
                    new MessageDetail(
                        LogMessages.IDX10225,
                        LogHelper.MarkAsNonPII(securityToken == null ? "null" : securityToken.GetType().ToString())),
                    typeof(SecurityTokenNoExpirationException),
                    new StackFrame(true));

            if (notBefore.HasValue && expires.HasValue && (notBefore.Value > expires.Value))
                return new LifetimeValidationError(
                    new MessageDetail(
                        LogMessages.IDX10224,
                        LogHelper.MarkAsNonPII(notBefore.Value),
                        LogHelper.MarkAsNonPII(expires.Value)),
                    typeof(SecurityTokenInvalidLifetimeException),
                    new StackFrame(true),
                    new(NotBeforeDate: notBefore, ExpirationDate: expires));

            DateTime utcNow = validationParameters.TimeProvider.GetUtcNow().UtcDateTime;
            if (notBefore.HasValue && (notBefore.Value > DateTimeUtil.Add(utcNow, validationParameters.ClockSkew)))
                return new LifetimeValidationError(
                    new MessageDetail(
                        LogMessages.IDX10222,
                        LogHelper.MarkAsNonPII(notBefore.Value),
                        LogHelper.MarkAsNonPII(utcNow)),
                    typeof(SecurityTokenNotYetValidException),
                    new StackFrame(true),
                    new(NotBeforeDate: notBefore, ExpirationDate: expires));

            if (expires.HasValue && (expires.Value < DateTimeUtil.Add(utcNow, validationParameters.ClockSkew.Negate())))
                return new LifetimeValidationError(
                    new MessageDetail(
                        LogMessages.IDX10223,
                        LogHelper.MarkAsNonPII(expires.Value),
                        LogHelper.MarkAsNonPII(utcNow)),
                    typeof(SecurityTokenExpiredException),
                    new StackFrame(true),
                    new(NotBeforeDate: null, ExpirationDate: expires));

            // if it reaches here, that means lifetime of the token is valid
            return new ValidatedLifetime(notBefore, expires);
        }
    }
}
#nullable restore
