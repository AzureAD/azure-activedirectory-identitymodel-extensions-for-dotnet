// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Partial class for Token Replay validation.
    /// </summary>
    public static partial class Validators
    {
        /// <summary>
        /// Validates if a token has been replayed.
        /// </summary>
        /// <param name="expirationTime">When does the security token expire.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">The <see cref="CallContext"/> that contains call information.</param>
#pragma warning disable CA1801 // Review unused parameters
        public static ValidationResult<DateTime?, TokenReplayValidationError> ValidateTokenReplay(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
#pragma warning restore CA1801 // Review unused parameters
        {
            if (string.IsNullOrWhiteSpace(securityToken))
                return TokenReplayValidationError.NullParameter(
                    nameof(securityToken),
                    ValidationError.GetCurrentStackFrame());

            if (validationParameters == null)
                return TokenReplayValidationError.NullParameter(
                    nameof(validationParameters),
                    ValidationError.GetCurrentStackFrame());

            // check if token if replay cache is set, then there must be an expiration time.
            if (validationParameters.TokenReplayCache != null)
            {
                if (expirationTime == null)
                    return new TokenReplayValidationError(
                        new MessageDetail(
                            LogMessages.IDX10227,
                            securityToken),
                        ValidationFailureType.TokenReplayValidationFailed,
                        typeof(SecurityTokenNoExpirationException),
                        ValidationError.GetCurrentStackFrame(),
                        expirationTime);

                if (validationParameters.TokenReplayCache.TryFind(securityToken))
                    return new TokenReplayValidationError(
                        new MessageDetail(
                            LogMessages.IDX10228,
                            securityToken),
                        ValidationFailureType.TokenReplayValidationFailed,
                        typeof(SecurityTokenReplayDetectedException),
                        ValidationError.GetCurrentStackFrame(),
                        expirationTime);

                if (!validationParameters.TokenReplayCache.TryAdd(securityToken, expirationTime.Value))
                    return new TokenReplayValidationError(
                        new MessageDetail(
                            LogMessages.IDX10229,
                            securityToken),
                        ValidationFailureType.TokenReplayValidationFailed,
                        typeof(SecurityTokenReplayAddFailedException),
                        ValidationError.GetCurrentStackFrame(),
                        expirationTime);
            }

            // if it reaches here, that means no token replay is detected.
            // TODO: Move to CallContext
            //LogHelper.LogInformation(LogMessages.IDX10240);
            return expirationTime;
        }
    }
}
#nullable restore
