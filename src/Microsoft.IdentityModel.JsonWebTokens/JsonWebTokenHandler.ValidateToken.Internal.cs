// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

#nullable enable
namespace Microsoft.IdentityModel.JsonWebTokens
{
    public partial class JsonWebTokenHandler : TokenHandler
    {
        /// <summary>
        /// Validates a token.
        /// On validation failure no exception will be thrown. 'see cref="ValidationError"' will contain information pertaining to the error.
        /// </summary>
        /// <param name="token">The token to be validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">A <see cref="CallContext"/> that contains call information.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> that can be used to request cancellation of the asynchronous operation.</param>
        /// <returns>A <see cref="ValidationResult{TResult}"/> with either a <see cref="ValidatedToken"/> if the token was validated or an <see cref="ValidationError"/> with the failure information and exception otherwise.</returns>
        internal override async Task<ValidationResult<ValidatedToken>> ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(token))
            {
                return ValidationError.NullParameter(
                        nameof(token),
                        ValidationError.GetCurrentStackFrame());
            }

            if (validationParameters is null)
            {
                return ValidationError.NullParameter(
                        nameof(validationParameters),
                        ValidationError.GetCurrentStackFrame());
            }

            if (token.Length > MaximumTokenSizeInBytes)
            {
                return new ValidationError(
                        new MessageDetail(
                            TokenLogMessages.IDX10209,
                            LogHelper.MarkAsNonPII(token.Length),
                            LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes)),
                        ValidationFailureType.InvalidSecurityToken,
                        typeof(ArgumentException),
                        ValidationError.GetCurrentStackFrame());
            }

            ValidationResult<SecurityToken> readResult = ReadToken(token, callContext);
            if (readResult.IsValid)
            {
                ValidationResult<ValidatedToken> validationResult = await ValidateTokenAsync(
                    readResult.UnwrapResult(),
                    validationParameters,
                    callContext,
                    cancellationToken)
                    .ConfigureAwait(false);

                if (validationResult.IsValid)
                    return validationResult; // No need to unwrap and re-wrap the result.

                return validationResult.UnwrapError().AddCurrentStackFrame();
            }

            return readResult.UnwrapError().AddCurrentStackFrame();
        }

        /// <inheritdoc/>
        internal override async Task<ValidationResult<ValidatedToken>> ValidateTokenAsync(
            SecurityToken token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken = default)
        {
            if (token is null)
            {
                return ValidationError.NullParameter(
                    nameof(token),
                    ValidationError.GetCurrentStackFrame());
            }

            if (validationParameters is null)
            {
                return ValidationError.NullParameter(
                    nameof(validationParameters),
                    ValidationError.GetCurrentStackFrame());
            }

            if (token is not JsonWebToken jsonWebToken)
            {
                return new ValidationError(
                    new MessageDetail(TokenLogMessages.IDX10001, nameof(token), nameof(JsonWebToken)),
                    ValidationFailureType.InvalidSecurityToken,
                    typeof(ArgumentException),
                    ValidationError.GetCurrentStackFrame());
            }

            BaseConfiguration? currentConfiguration =
                await GetCurrentConfigurationAsync(validationParameters).ConfigureAwait(false);

            ValidationResult<ValidatedToken> result = jsonWebToken.IsEncrypted ?
                await ValidateJWEAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false) :
                await ValidateJWSAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false);

            if (validationParameters.ConfigurationManager is null)
            {
                if (result.IsValid)
                    return result;

                return result.UnwrapError().AddStackFrame(ValidationError.GetCurrentStackFrame());
            }

            if (result.IsValid)
            {
                // Set current configuration as LKG if it exists.
                if (currentConfiguration is not null)
                    validationParameters.ConfigurationManager.LastKnownGoodConfiguration = currentConfiguration;

                return result;
            }

            if (TokenUtilities.IsRecoverableExceptionType(result.UnwrapError().ExceptionType))
            {
                // If we were still unable to validate, attempt to refresh the configuration and validate using it
                // but ONLY if the currentConfiguration is not null. We want to avoid refreshing the configuration on
                // retrieval error as this case should have already been hit before. This refresh handles the case
                // where a new valid configuration was somehow published during validation time.
                if (currentConfiguration is not null)
                {
                    validationParameters.ConfigurationManager.RequestRefresh();
                    validationParameters.RefreshBeforeValidation = true;
                    BaseConfiguration lastConfig = currentConfiguration;
                    currentConfiguration = await validationParameters.ConfigurationManager.GetBaseConfigurationAsync(CancellationToken.None).ConfigureAwait(false);

                    // Only try to re-validate using the newly obtained config if it doesn't reference equal the previously used configuration.
                    if (lastConfig != currentConfiguration)
                    {
                        result = jsonWebToken.IsEncrypted ?
                            await ValidateJWEAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false) :
                            await ValidateJWSAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false);

                        if (result.IsValid)
                        {
                            validationParameters.ConfigurationManager.LastKnownGoodConfiguration = currentConfiguration;
                            return result;
                        }
                    }
                }

                if (validationParameters.ConfigurationManager.UseLastKnownGoodConfiguration)
                {
                    validationParameters.RefreshBeforeValidation = false;
                    validationParameters.ValidateWithLKG = true;
                    Type recoverableExceptionType = result.UnwrapError().ExceptionType;

                    BaseConfiguration[] validConfigurations = validationParameters.ConfigurationManager.GetValidLkgConfigurations();
                    for (int i = 0; i < validConfigurations.Length; i++)
                    {
                        BaseConfiguration lkgConfiguration = validConfigurations[i];
                        if (TokenUtilities.IsRecoverableConfigurationAndExceptionType(
                            jsonWebToken.Kid, currentConfiguration, lkgConfiguration, recoverableExceptionType))
                        {
                            result = jsonWebToken.IsEncrypted ?
                                await ValidateJWEAsync(jsonWebToken, validationParameters, lkgConfiguration, callContext, cancellationToken).ConfigureAwait(false) :
                                await ValidateJWSAsync(jsonWebToken, validationParameters, lkgConfiguration, callContext, cancellationToken).ConfigureAwait(false);

                            if (result.IsValid)
                                return result;
                        }
                    }
                }
            }

            // If we reach this point, the token validation failed and we should return the error.
            return result.UnwrapError().AddCurrentStackFrame();
        }

        private async ValueTask<ValidationResult<ValidatedToken>> ValidateJWEAsync(
            JsonWebToken jwtToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            ValidationResult<string> decryptionResult = DecryptToken(
                jwtToken, validationParameters, configuration, callContext);
            if (!decryptionResult.IsValid)
            {
                return decryptionResult.UnwrapError().AddCurrentStackFrame();
            }

            ValidationResult<SecurityToken> readResult = ReadToken(decryptionResult.UnwrapResult(), callContext);
            if (!readResult.IsValid)
            {
                return readResult.UnwrapError().AddCurrentStackFrame();
            }

            JsonWebToken decryptedToken = (readResult.UnwrapResult() as JsonWebToken)!;
            ValidationResult<ValidatedToken> validationResult =
                await ValidateJWSAsync(decryptedToken!, validationParameters, configuration, callContext, cancellationToken)
                .ConfigureAwait(false);

            if (!validationResult.IsValid)
            {
                return validationResult.UnwrapError().AddCurrentStackFrame();
            }

            JsonWebToken jsonWebToken = (validationResult.UnwrapResult().SecurityToken as JsonWebToken)!;

            jwtToken.InnerToken = jsonWebToken;
            jwtToken.Payload = jsonWebToken.Payload;

            return validationResult;
        }

        private async ValueTask<ValidationResult<ValidatedToken>> ValidateJWSAsync(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            DateTime? expires = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Exp) ? jsonWebToken.ValidTo : null;
            DateTime? notBefore = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Nbf) ? jsonWebToken.ValidFrom : null;

            ValidationResult<ValidatedLifetime> lifetimeValidationResult;

            try
            {
                lifetimeValidationResult = validationParameters.LifetimeValidator(
                    notBefore, expires, jsonWebToken, validationParameters, callContext);

                if (!lifetimeValidationResult.IsValid)
                    return lifetimeValidationResult.UnwrapError().AddCurrentStackFrame();
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new LifetimeValidationError(
                    new MessageDetail(TokenLogMessages.IDX10271),
                    ValidationFailureType.LifetimeValidatorThrew,
                    typeof(SecurityTokenInvalidLifetimeException),
                    ValidationError.GetCurrentStackFrame(),
                    notBefore,
                    expires,
                    ex);
            }

            if (jsonWebToken.Audiences is not IList<string> tokenAudiences)
                tokenAudiences = jsonWebToken.Audiences.ToList();

            ValidationResult<string> audienceValidationResult;
            try
            {
                audienceValidationResult = validationParameters.AudienceValidator(
                    tokenAudiences, jsonWebToken, validationParameters, callContext);

                if (!audienceValidationResult.IsValid)
                    return audienceValidationResult.UnwrapError().AddCurrentStackFrame();
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new AudienceValidationError(
                    new MessageDetail(TokenLogMessages.IDX10270),
                    ValidationFailureType.AudienceValidatorThrew,
                    typeof(SecurityTokenInvalidAudienceException),
                    ValidationError.GetCurrentStackFrame(),
                    tokenAudiences,
                    null,
                    ex);
            }

            ValidationResult<ValidatedIssuer> issuerValidationResult;
            try
            {
                issuerValidationResult = await validationParameters.IssuerValidatorAsync(
                    jsonWebToken.Issuer, jsonWebToken, validationParameters, callContext, cancellationToken)
                    .ConfigureAwait(false);

                if (!issuerValidationResult.IsValid)
                {
                    return issuerValidationResult.UnwrapError().AddCurrentStackFrame();
                }
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new IssuerValidationError(
                    new MessageDetail(TokenLogMessages.IDX10269),
                    ValidationFailureType.IssuerValidatorThrew,
                    typeof(SecurityTokenInvalidIssuerException),
                    ValidationError.GetCurrentStackFrame(),
                    jsonWebToken.Issuer,
                    ex);
            }

            ValidationResult<DateTime?> replayValidationResult;

            try
            {
                replayValidationResult = validationParameters.TokenReplayValidator(
                    expires, jsonWebToken.EncodedToken, validationParameters, callContext);

                if (!replayValidationResult.IsValid)
                    return replayValidationResult.UnwrapError().AddCurrentStackFrame();
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new TokenReplayValidationError(
                    new MessageDetail(TokenLogMessages.IDX10276),
                    ValidationFailureType.TokenReplayValidatorThrew,
                    typeof(SecurityTokenReplayDetectedException),
                    ValidationError.GetCurrentStackFrame(),
                    expires,
                    ex);
            }

            ValidationResult<ValidatedToken>? actorValidationResult = null;
            // actor validation
            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jsonWebToken.Actor))
            {
                ValidationResult<SecurityToken> actorReadingResult = ReadToken(jsonWebToken.Actor, callContext);
                if (!actorReadingResult.IsValid)
                    return actorReadingResult.UnwrapError().AddCurrentStackFrame();

                if (validationParameters.ActorValidationParameters is null)
                    return ValidationError.NullParameter(
                        nameof(validationParameters.ActorValidationParameters),
                        ValidationError.GetCurrentStackFrame());

                JsonWebToken actorToken = (actorReadingResult.UnwrapResult() as JsonWebToken)!;
                ValidationParameters actorParameters = validationParameters.ActorValidationParameters;
                ValidationResult<ValidatedToken> innerActorValidationResult =
                    await ValidateJWSAsync(actorToken, actorParameters, configuration, callContext, cancellationToken)
                    .ConfigureAwait(false);

                if (!innerActorValidationResult.IsValid)
                    return innerActorValidationResult.UnwrapError().AddCurrentStackFrame();

                actorValidationResult = innerActorValidationResult;
            }

            ValidationResult<ValidatedTokenType> typeValidationResult;

            try
            {
                typeValidationResult = validationParameters.TokenTypeValidator(
                    jsonWebToken.Typ, jsonWebToken, validationParameters, callContext);

                if (!typeValidationResult.IsValid)
                    return typeValidationResult.UnwrapError().AddCurrentStackFrame();
            }

#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new TokenTypeValidationError(
                    new MessageDetail(TokenLogMessages.IDX10275),
                    ValidationFailureType.TokenTypeValidatorThrew,
                    typeof(SecurityTokenInvalidTypeException),
                    ValidationError.GetCurrentStackFrame(),
                    jsonWebToken.Typ,
                    ex);
            }

            // The signature validation delegate is yet to be migrated to ValidationParameters.
            ValidationResult<SecurityKey> signatureValidationResult = ValidateSignature(
                jsonWebToken, validationParameters, configuration, callContext);
            if (!signatureValidationResult.IsValid)
                return signatureValidationResult.UnwrapError().AddCurrentStackFrame();

            ValidationResult<ValidatedSigningKeyLifetime> issuerSigningKeyValidationResult;

            try
            {
                issuerSigningKeyValidationResult = validationParameters.IssuerSigningKeyValidator(
                    jsonWebToken.SigningKey, jsonWebToken, validationParameters, callContext);

                if (!issuerSigningKeyValidationResult.IsValid)
                    return issuerSigningKeyValidationResult.UnwrapError().AddCurrentStackFrame();
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new IssuerSigningKeyValidationError(
                    new MessageDetail(TokenLogMessages.IDX10274),
                    ValidationFailureType.IssuerSigningKeyValidatorThrew,
                    typeof(SecurityTokenInvalidSigningKeyException),
                    ValidationError.GetCurrentStackFrame(),
                    jsonWebToken.SigningKey,
                    ex);
            }

            return new ValidatedToken(jsonWebToken, this, validationParameters)
            {
                ValidatedLifetime = lifetimeValidationResult.UnwrapResult(),
                ValidatedAudience = audienceValidationResult.UnwrapResult(),
                ValidatedIssuer = issuerValidationResult.UnwrapResult(),
                ValidatedTokenReplayExpirationTime = replayValidationResult.UnwrapResult(),
                ActorValidationResult = actorValidationResult?.UnwrapResult(),
                ValidatedTokenType = typeValidationResult.UnwrapResult(),
                ValidatedSigningKey = signatureValidationResult.UnwrapResult(),
                ValidatedSigningKeyLifetime = issuerSigningKeyValidationResult.UnwrapResult()
            };
        }

        private static async Task<BaseConfiguration?> GetCurrentConfigurationAsync(ValidationParameters validationParameters)
        {
            BaseConfiguration? currentConfiguration = null;
            if (validationParameters.ConfigurationManager is not null)
            {
                try
                {
                    currentConfiguration = await validationParameters.ConfigurationManager.GetBaseConfigurationAsync(CancellationToken.None).ConfigureAwait(false);
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch
#pragma warning restore CA1031 // Do not catch general exception types
                {
                    // The exception is tracked and dismissed as the ValidationParameters may have the issuer
                    // and signing key set directly on them, allowing the library to continue with token validation.
                    // TODO: Move to CallContext.
                    //if (LogHelper.IsEnabled(EventLogLevel.Warning))
                    //    LogHelper.LogWarning(LogHelper.FormatInvariant(TokenLogMessages.IDX10261, validationParameters.ConfigurationManager.MetadataAddress, ex.ToString()));
                }
            }

            return currentConfiguration;
        }
    }
}
#nullable restore
