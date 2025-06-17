// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.Identity.Abstractions;
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
        /// <param name="expires">The <see cref="DateTime"/> when the security token expires.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">The <see cref="CallContext"/> that contains call information.</param>
#pragma warning disable CA1801 // Review unused parameters
#pragma warning disable RS0016 // Add public types and members to the declared API
        public static OperationResult<DateTime?, ValidationError> ValidateTokenReplay(
#pragma warning restore RS0016 // Add public types and members to the declared API
            DateTime? expires,
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
                if (expires == null)
                    return new TokenReplayValidationError(
                        new MessageDetail(
                            LogMessages.IDX10227,
                            securityToken),
                        ValidationFailureType.TokenReplayNoExpiration,
                        ValidationError.GetCurrentStackFrame(),
                        expires);

                if (validationParameters.TokenReplayCache.TryFind(securityToken))
                    return new TokenReplayValidationError(
                        new MessageDetail(
                            LogMessages.IDX10228,
                            securityToken),
                        ValidationFailureType.TokenReplayTokenFound,
                        ValidationError.GetCurrentStackFrame(),
                        expires);

                if (!validationParameters.TokenReplayCache.TryAdd(securityToken, expires.Value))
                    return new TokenReplayValidationError(
                        new MessageDetail(
                            LogMessages.IDX10229,
                            securityToken),
                        ValidationFailureType.TokenReplayAddToCacheFailed,
                        ValidationError.GetCurrentStackFrame(),
                        expires);
            }

            // if it reaches here, that means no token replay is detected.
            // TODO: Move to CallContext
            //LogHelper.LogInformation(LogMessages.IDX10240);
            return expires;
        }
    }
}
#nullable restore
