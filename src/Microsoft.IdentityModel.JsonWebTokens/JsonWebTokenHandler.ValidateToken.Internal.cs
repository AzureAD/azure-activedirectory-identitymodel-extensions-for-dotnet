// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    public partial class JsonWebTokenHandler : TokenHandler
    {
        /// <summary>
        /// Validates a token.
        /// On a validation failure, no exception will be thrown; instead, the exception will be set in the returned TokenValidationResult.Exception property.
        /// Callers should always check the TokenValidationResult.IsValid property to verify the validity of the result.
        /// </summary>
        /// <param name="token">The token to be validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">A <see cref="CallContext"/> that contains useful information for logging.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> that can be used to request cancellation of the asynchronous operation.</param>
        /// <returns>A <see cref="TokenValidationResult"/>.</returns>
        /// <remarks>
        /// <para>TokenValidationResult.Exception will be set to one of the following exceptions if the <paramref name="token"/> is invalid.</para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">Returned if <paramref name="token"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException">Returned if <paramref name="validationParameters"/> is null.</exception>
        /// <exception cref="ArgumentException">Returned if 'token.Length' is greater than <see cref="TokenHandler.MaximumTokenSizeInBytes"/>.</exception>
        /// <exception cref="SecurityTokenMalformedException">Returned if <paramref name="token"/> is not a valid <see cref="JsonWebToken"/>, <see cref="ReadToken(string, CallContext)"/></exception>
        /// <exception cref="SecurityTokenMalformedException">Returned if the validationParameters.TokenReader delegate is not able to parse/read the token as a valid <see cref="JsonWebToken"/>, <see cref="ReadToken(string, CallContext)"/></exception>
        internal async Task<ValidationResult> ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken? cancellationToken)
        {
            // These exceptions will be removed once we add ExceptionDetails to TokenValidationResult.
            if (string.IsNullOrEmpty(token))
                return new ValidationResult(
                    null,
                    this,
                    validationParameters,
                    TokenValidationErrorCommon.NullParameter(nameof(token), tag: 0x121211));

            if (validationParameters is null)
                return new ValidationResult(
                    null,
                    this,
                    validationParameters,
                    TokenValidationErrorCommon.NullParameter(nameof(validationParameters), tag: 0x121212));

            if (token.Length > MaximumTokenSizeInBytes)
                return new ValidationResult(
                    null,
                    this,
                    validationParameters,
                    new TokenValidationError(
                        ValidationErrorType.InvalidArgument,
                        new MessageDetail(TokenLogMessages.IDX10209, LogHelper.MarkAsNonPII(token.Length), LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes)),
                        Tag: 0x121213,
                        null));

            Result<SecurityToken, ITokenValidationError> result = ReadToken(token, callContext);
            if (result.IsSuccess)
                return await ValidateTokenAsync(
                    result.Unwrap(),
                    validationParameters,
                    callContext,
                    cancellationToken)
                    .ConfigureAwait(false);

            return new ValidationResult(
                null,
                this,
                validationParameters,
                result.UnwrapError());
        }

        /// <inheritdoc/>
        internal async Task<ValidationResult> ValidateTokenAsync(
            SecurityToken token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken? cancellationToken)
        {
            if (token is null)
                return new ValidationResult(
                    token,
                    this,
                    validationParameters,
                    TokenValidationErrorCommon.NullParameter(nameof(token), tag: 0x121211));

            if (validationParameters is null)
                return new ValidationResult(
                    token,
                    this,
                    validationParameters,
                    TokenValidationErrorCommon.NullParameter(nameof(validationParameters), tag: 0x121212));

            if (token is not JsonWebToken jwt)
                return new ValidationResult(
                    token,
                    this,
                    validationParameters,
                    new TokenValidationError(
                        ValidationErrorType.InvalidArgument,
                        new MessageDetail(TokenLogMessages.IDX10001, nameof(token), nameof(JsonWebToken)),
                        Tag: 0x121214,
                        null));

            return await InternalValidateTokenAsync(
                jwt,
                validationParameters,
                callContext,
                cancellationToken)
                .ConfigureAwait(false);
        }

        /// <summary>
        ///  Internal method for token validation, responsible for:
        ///  (1) Obtaining a configuration from the <see cref="ValidationParameters.ConfigurationManager"/>.
        ///  (2) Revalidating using the Last Known Good Configuration (if present), and obtaining a refreshed configuration (if necessary) and revalidating using it.
        /// </summary>
        /// <param name="jsonWebToken">The JWT token.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">A <see cref="CallContext"/> that contains useful information for logging.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> that can be used to request cancellation of the asynchronous operation.</param>
        /// <returns></returns>
        private async ValueTask<ValidationResult> InternalValidateTokenAsync(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken? cancellationToken)
        {
            BaseConfiguration currentConfiguration =
                await GetCurrentConfigurationAsync(validationParameters)
                .ConfigureAwait(false);

            ValidationResult result = jsonWebToken.IsEncrypted ?
                await ValidateJWEAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false) :
                await ValidateJWSAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false);

            if (validationParameters.ConfigurationManager is null)
                return result;

            if (result.IsValid)
            {
                // Set current configuration as LKG if it exists.
                if (currentConfiguration is not null)
                    validationParameters.ConfigurationManager.LastKnownGoodConfiguration = currentConfiguration;

                return result;
            }

            if (TokenUtilities.IsRecoverableErrorType(result.TokenValidationError?.ErrorType))
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
                    ValidationErrorType recoverableExceptionType = result.TokenValidationError?.ErrorType ?? ValidationErrorType.Unknown;

                    BaseConfiguration[] validConfigurations = validationParameters.ConfigurationManager.GetValidLkgConfigurations();
                    for (int i = 0; i < validConfigurations.Length; i++)
                    {
                        BaseConfiguration lkgConfiguration = validConfigurations[i];
                        if (TokenUtilities.IsRecoverableConfigurationAndExceptionType(
                            jsonWebToken.Kid, currentConfiguration, lkgConfiguration, recoverableExceptionType))
                        {
                            result = jsonWebToken.IsEncrypted ?
                                await ValidateJWEAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false) :
                                await ValidateJWSAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false);

                            if (result.IsValid)
                                return result;
                        }
                    }
                }
            }

            return result;
        }

        private async ValueTask<ValidationResult> ValidateJWEAsync(
            JsonWebToken jwtToken,
            ValidationParameters validationParameters,
            BaseConfiguration configuration,
            CallContext callContext,
            CancellationToken? cancellationToken)
        {
            Result<string, ITokenValidationError> decryptionResult = DecryptToken(
                jwtToken, validationParameters, configuration, callContext);

            if (!decryptionResult.IsSuccess)
                return new ValidationResult(jwtToken, this, validationParameters, decryptionResult.UnwrapError());

            Result<SecurityToken, ITokenValidationError> readResult = ReadToken(decryptionResult.Unwrap(), callContext);

            if (!readResult.IsSuccess)
                return new ValidationResult(jwtToken, this, validationParameters, readResult.UnwrapError());

            JsonWebToken decryptedToken = readResult.Unwrap() as JsonWebToken;

            ValidationResult validationResult =
                await ValidateJWSAsync(decryptedToken, validationParameters, configuration, callContext, cancellationToken)
                .ConfigureAwait(false);

            if (!validationResult.IsValid)
                return validationResult;

            jwtToken.InnerToken = validationResult.SecurityToken as JsonWebToken;
            jwtToken.Payload = (validationResult.SecurityToken as JsonWebToken).Payload;

            return validationResult;
        }

        private async ValueTask<ValidationResult> ValidateJWSAsync(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            BaseConfiguration configuration,
            CallContext callContext,
            CancellationToken? cancellationToken)
        {
            DateTime? expires = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Exp) ? jsonWebToken.ValidTo : null;
            DateTime? notBefore = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Nbf) ? jsonWebToken.ValidFrom : null;

            Result<ValidatedLifetime, ITokenValidationError> lifetimeValidationResult = validationParameters.LifetimeValidator(
                notBefore, expires, jsonWebToken, validationParameters, callContext);

            if (!lifetimeValidationResult.IsSuccess)
                return new ValidationResult(jsonWebToken, this, validationParameters, lifetimeValidationResult.UnwrapError());

            if (jsonWebToken.Audiences is not IList<string> tokenAudiences)
                tokenAudiences = jsonWebToken.Audiences.ToList();

            Result<string, ITokenValidationError> audienceValidationResult = validationParameters.AudienceValidator(
                tokenAudiences, jsonWebToken, validationParameters, callContext);

            if (!audienceValidationResult.IsSuccess)
                return new ValidationResult(jsonWebToken, this, validationParameters, audienceValidationResult.UnwrapError())
                {
                    ValidatedLifetime = lifetimeValidationResult.Unwrap()
                };

            Result<ValidatedIssuer, ITokenValidationError> issuerValidationResult = await validationParameters.IssuerValidatorAsync(
                jsonWebToken.Issuer, jsonWebToken, validationParameters, callContext, cancellationToken)
                .ConfigureAwait(false);

            if (!issuerValidationResult.IsSuccess)
                return new ValidationResult(jsonWebToken, this, validationParameters, issuerValidationResult.UnwrapError())
                {
                    ValidatedLifetime = lifetimeValidationResult.Unwrap(),
                    ValidatedAudience = audienceValidationResult.Unwrap()
                };

            Result<DateTime?, ITokenValidationError> replayValidationResult = validationParameters.TokenReplayValidator(
                expires, jsonWebToken.EncodedToken, validationParameters, callContext);

            if (!replayValidationResult.IsSuccess)
                return new ValidationResult(jsonWebToken, this, validationParameters, replayValidationResult.UnwrapError())
                {
                    ValidatedLifetime = lifetimeValidationResult.Unwrap(),
                    ValidatedAudience = audienceValidationResult.Unwrap(),
                    ValidatedIssuer = issuerValidationResult.Unwrap()
                };

            ValidationResult actorValidationResult = null;
            // actor validation
            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jsonWebToken.Actor))
            {
                Result<SecurityToken, ITokenValidationError> actorReadingResult = ReadToken(jsonWebToken.Actor, callContext);
                if (!actorReadingResult.IsSuccess)
                    return new ValidationResult(jsonWebToken, this, validationParameters, actorReadingResult.UnwrapError())
                    {
                        ValidatedLifetime = lifetimeValidationResult.Unwrap(),
                        ValidatedAudience = audienceValidationResult.Unwrap(),
                        ValidatedIssuer = issuerValidationResult.Unwrap(),
                        ValidatedTokenReplayExpirationTime = replayValidationResult.Unwrap()
                    };

                JsonWebToken actorToken = actorReadingResult.Unwrap() as JsonWebToken;
                ValidationParameters actorParameters = validationParameters.ActorValidationParameters;
                actorValidationResult =
                    await ValidateJWSAsync(actorToken, actorParameters, configuration, callContext, cancellationToken)
                    .ConfigureAwait(false);

                // Consider adding a new ValidationResult type for actor validation
                // that wraps the actorValidationResult.ValidationResults
                if (!actorValidationResult.IsValid)
                    return new ValidationResult(jsonWebToken, this, validationParameters, actorValidationResult.TokenValidationError)
                    {
                        ValidatedLifetime = lifetimeValidationResult.Unwrap(),
                        ValidatedAudience = audienceValidationResult.Unwrap(),
                        ValidatedIssuer = issuerValidationResult.Unwrap(),
                        ValidatedTokenReplayExpirationTime = replayValidationResult.Unwrap(),
                        ActorValidationResult = actorValidationResult
                    };
            }

            Result<ValidatedTokenType, ITokenValidationError> typeValidationResult = validationParameters.TypeValidator(
                jsonWebToken.Typ, jsonWebToken, validationParameters, callContext);

            if (!typeValidationResult.IsSuccess)
                return new ValidationResult(jsonWebToken, this, validationParameters, typeValidationResult.UnwrapError())
                {
                    ValidatedLifetime = lifetimeValidationResult.Unwrap(),
                    ValidatedAudience = audienceValidationResult.Unwrap(),
                    ValidatedIssuer = issuerValidationResult.Unwrap(),
                    ValidatedTokenReplayExpirationTime = replayValidationResult.Unwrap(),
                    ActorValidationResult = actorValidationResult
                };

            // The signature validation delegate is yet to be migrated to ValidationParameters.
            Result<SecurityKey, ITokenValidationError> signatureValidationResult = ValidateSignature(
                jsonWebToken, validationParameters, configuration, callContext);

            if (!signatureValidationResult.IsSuccess)
                return new ValidationResult(jsonWebToken, this, validationParameters, signatureValidationResult.UnwrapError())
                {
                    ValidatedLifetime = lifetimeValidationResult.Unwrap(),
                    ValidatedAudience = audienceValidationResult.Unwrap(),
                    ValidatedIssuer = issuerValidationResult.Unwrap(),
                    ValidatedTokenReplayExpirationTime = replayValidationResult.Unwrap(),
                    ActorValidationResult = actorValidationResult,
                    ValidatedTokenType = typeValidationResult.Unwrap()
                };

            Result<ValidatedSigningKeyLifetime, ITokenValidationError> issuerSigningKeyValidationResult = validationParameters.IssuerSigningKeyValidator(
                signatureValidationResult.Unwrap(), jsonWebToken, validationParameters, configuration, callContext);

            if (!issuerSigningKeyValidationResult.IsSuccess)
                return new ValidationResult(jsonWebToken, this, validationParameters, issuerSigningKeyValidationResult.UnwrapError())
                {
                    ValidatedLifetime = lifetimeValidationResult.Unwrap(),
                    ValidatedAudience = audienceValidationResult.Unwrap(),
                    ValidatedIssuer = issuerValidationResult.Unwrap(),
                    ValidatedTokenReplayExpirationTime = replayValidationResult.Unwrap(),
                    ActorValidationResult = actorValidationResult,
                    ValidatedTokenType = typeValidationResult.Unwrap(),
                    ValidatedSigningKey = signatureValidationResult.Unwrap()
                };

            return new(jsonWebToken, this, validationParameters)
            {
                ValidatedLifetime = lifetimeValidationResult.Unwrap(),
                ValidatedAudience = audienceValidationResult.Unwrap(),
                ValidatedIssuer = issuerValidationResult.Unwrap(),
                ValidatedTokenReplayExpirationTime = replayValidationResult.Unwrap(),
                ActorValidationResult = actorValidationResult,
                ValidatedTokenType = typeValidationResult.Unwrap(),
                ValidatedSigningKey = signatureValidationResult.Unwrap(),
                ValidatedSigningKeyLifetime = issuerSigningKeyValidationResult.Unwrap()
            };
        }

        private static async Task<BaseConfiguration> GetCurrentConfigurationAsync(ValidationParameters validationParameters)
        {
            BaseConfiguration currentConfiguration = null;
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
