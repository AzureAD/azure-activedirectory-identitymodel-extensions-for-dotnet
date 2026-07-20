// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

#nullable enable
namespace Microsoft.IdentityModel.JsonWebTokens
{
    public partial class JsonWebTokenHandler : TokenHandler, IResultBasedValidation
    {
        /// <inheritdoc/>
        public override async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
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
                    ValidationFailureType.SecurityTokenTooLarge,
                    ValidationError.GetCurrentStackFrame());
            }

            ValidationResult<SecurityToken, ValidationError> readResult = ReadToken(token, callContext);
            if (readResult.Succeeded)
            {
                ValidationResult<ValidatedToken, ValidationError> validationResult = await ValidateTokenAsync(
                    readResult.Result!,
                    validationParameters,
                    callContext,
                    cancellationToken)
                    .ConfigureAwait(false);

                if (validationResult.Succeeded)
                    return validationResult; // No need to unwrap and re-wrap the result.

                return validationResult.Error!.AddStackFrame(ValidationError.GetCurrentStackFrame());
            }

            return readResult.Error!.AddCurrentStackFrame();
        }

        /// <inheritdoc/>
        public override async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
            SecurityToken token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
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
                    ValidationFailureType.SecurityTokenNotExpectedType,
                    ValidationError.GetCurrentStackFrame());
            }

            BaseConfiguration? currentConfiguration =
                await GetCurrentConfigurationAsync(validationParameters, cancellationToken).ConfigureAwait(false);

            ValidationResult<ValidatedToken, ValidationError> result = jsonWebToken.IsEncrypted ?
                await ValidateJWEAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false) :
                await ValidateJWSAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false);

            if (validationParameters.ConfigurationManager is null)
            {
                if (result.Succeeded)
                    return result;

                return result.Error!.AddStackFrame(ValidationError.GetCurrentStackFrame());
            }

            if (result.Succeeded)
            {
                // Set current configuration as LKG if it exists.
                if (currentConfiguration is not null)
                    validationParameters.ConfigurationManager.LastKnownGoodConfiguration = currentConfiguration;

                return result;
            }

            if (TokenUtilities.IsRecoverableFailureType(result.Error!.FailureType, (currentConfiguration != null && currentConfiguration.TokenDecryptionKeys.Count > 0)))
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

                        if (result.Succeeded)
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
                    ValidationFailureType failureType = result.Error!.FailureType;

                    BaseConfiguration[] validConfigurations = validationParameters.ConfigurationManager.GetValidLkgConfigurations();
                    for (int i = 0; i < validConfigurations.Length; i++)
                    {
                        BaseConfiguration lkgConfiguration = validConfigurations[i];
                        if (TokenUtilities.IsRecoverableConfigurationAndExceptionType(
                            jsonWebToken.Kid, currentConfiguration, lkgConfiguration, failureType))
                        {
                            result = jsonWebToken.IsEncrypted ?
                                await ValidateJWEAsync(jsonWebToken, validationParameters, lkgConfiguration, callContext, cancellationToken).ConfigureAwait(false) :
                                await ValidateJWSAsync(jsonWebToken, validationParameters, lkgConfiguration, callContext, cancellationToken).ConfigureAwait(false);

                            if (result.Succeeded)
                                return result;
                        }
                    }
                }
            }

            // If we reach this point, the token validation failed and we should return the error.
            return result.Error!.AddCurrentStackFrame();
        }

        private async ValueTask<ValidationResult<ValidatedToken, ValidationError>> ValidateJWEAsync(
            JsonWebToken jwtToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            ValidationResult<string, ValidationError> decryptionResult = DecryptToken(
                jwtToken, validationParameters, configuration, callContext);
            if (!decryptionResult.Succeeded)
            {
                return decryptionResult.Error!.AddCurrentStackFrame();
            }

            ValidationResult<SecurityToken, ValidationError> readResult = ReadToken(decryptionResult.Result!, callContext);
            if (!readResult.Succeeded)
            {
                return readResult.Error!.AddCurrentStackFrame();
            }

            JsonWebToken decryptedToken = (readResult.Result as JsonWebToken)!;
            ValidationResult<ValidatedToken, ValidationError> validationResult =
                await ValidateJWSAsync(decryptedToken!, validationParameters, configuration, callContext, cancellationToken)
                .ConfigureAwait(false);

            if (!validationResult.Succeeded)
            {
                return validationResult.Error!.AddCurrentStackFrame();
            }

            JsonWebToken jsonWebToken = (validationResult.Result!.SecurityToken as JsonWebToken)!;

            jwtToken.InnerToken = jsonWebToken;
            jwtToken.Payload = jsonWebToken.Payload;

            return validationResult;
        }

        private async ValueTask<ValidationResult<ValidatedToken, ValidationError>> ValidateJWSAsync(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            DateTime? expires = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Exp) ? jsonWebToken.ValidTo : null;
            DateTime? notBefore = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Nbf) ? jsonWebToken.ValidFrom : null;

            ValidationResult<ValidatedLifetime, ValidationError> lifetimeResult =
                Validators.ValidateLifetimeInternal(
                    notBefore,
                    expires,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!lifetimeResult.Succeeded)
                return lifetimeResult.Error!.AddCurrentStackFrame();

            if (jsonWebToken.Audiences is not IList<string> tokenAudiences)
                tokenAudiences = [.. jsonWebToken.Audiences];

            ValidationResult<string, ValidationError> audienceResult =
                Validators.ValidateAudienceInternal(
                    tokenAudiences,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!audienceResult.Succeeded)
                return audienceResult.Error!.AddCurrentStackFrame();

            ValidationResult<ValidatedIssuer, ValidationError> issuerResult =
                await Validators.ValidateIssuerInternalAsync(
                    jsonWebToken.Issuer,
                    jsonWebToken,
                    validationParameters,
                    callContext,
                    cancellationToken).ConfigureAwait(false);

            if (!issuerResult.Succeeded)
                return issuerResult.Error!.AddCurrentStackFrame();

            ValidationResult<DateTime?, ValidationError>? tokenReplayResult =
                Validators.ValidateTokenReplayInternal(
                    expires,
                    jsonWebToken.EncodedToken,
                    validationParameters,
                    callContext);

            if (!tokenReplayResult.Value.Succeeded)
                return tokenReplayResult.Value.Error!.AddCurrentStackFrame();

            ValidationResult<ValidatedTokenType, ValidationError> tokenTypeResult =
                Validators.ValidateTokenTypeInternal(
                    jsonWebToken.Typ,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!tokenTypeResult.Succeeded)
                return tokenTypeResult.Error!.AddCurrentStackFrame();

            ValidationResult<string, ValidationError> algorithmResult =
                Validators.ValidateAlgorithmInternal(
                    jsonWebToken.Alg,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!algorithmResult.Succeeded)
                return algorithmResult.Error!.AddCurrentStackFrame();

            // The signature validation delegate is yet to be migrated to ValidationParameters.
            ValidationResult<SecurityKey, ValidationError> signatureResult =
                ValidateSignature(
                    jsonWebToken,
                    validationParameters,
                    configuration,
                    callContext);

            if (!signatureResult.Succeeded)
                return signatureResult.Error!.AddCurrentStackFrame();

            ValidationResult<ValidatedSignatureKey, ValidationError> signatureKeyResult =
                Validators.ValidateSignatureKeyInternal(
                    jsonWebToken.SigningKey,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!signatureKeyResult.Succeeded)
                return signatureKeyResult.Error!.AddCurrentStackFrame();

            // actor validation
            ValidationResult<ValidatedToken, ValidationError>? actorResult = null;
            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jsonWebToken.Actor))
            {
                ValidationResult<SecurityToken, ValidationError> readResult = ReadToken(jsonWebToken.Actor, callContext);
                if (!readResult.Succeeded)
                    return readResult.Error!.AddCurrentStackFrame();

                if (validationParameters.ActorValidationParameters is null)
                    return ValidationError.NullParameter(
                        nameof(validationParameters.ActorValidationParameters),
                        ValidationError.GetCurrentStackFrame());

                // TODO - what if actor token is encrypted?
                JsonWebToken actorToken = (readResult.Result as JsonWebToken)!;
                actorResult = await ValidateJWSAsync(
                    actorToken,
                    validationParameters.ActorValidationParameters,
                    configuration,
                    callContext,
                    cancellationToken).ConfigureAwait(false);

                if (!actorResult.Value.Succeeded)
                    return actorResult.Value.Error!.AddCurrentStackFrame();
            }

            return new ValidatedToken(jsonWebToken, this, validationParameters)
            {
                ValidatedLifetime = lifetimeResult.Result,
                ValidatedAlgorithm = algorithmResult.Result,
                ValidatedAudience = audienceResult.Result,
                ValidatedIssuer = issuerResult.Result,
                ActorValidationResult = actorResult?.Result,
                ValidatedTokenType = tokenTypeResult.Result,
                ValidatedSignatureKey = signatureResult.Result
            };
        }

        private static async Task<BaseConfiguration?> GetCurrentConfigurationAsync(ValidationParameters validationParameters, CancellationToken cancellationToken)
        {
            BaseConfiguration? currentConfiguration = null;
            if (validationParameters.ConfigurationManager is not null)
            {
                try
                {
                    currentConfiguration = await validationParameters.ConfigurationManager.GetBaseConfigurationAsync(cancellationToken).ConfigureAwait(false);
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

        #region Synchronous validation
        /// <summary>
        /// Synchronously validates a token, using the cached configuration when available and falling back to
        /// <see cref="ValidateTokenAsync(string, ValidationParameters, CallContext, CancellationToken)"/> on a configuration
        /// cache miss or a recoverable failure. This is the synchronous counterpart of the result-based
        /// <c>ValidateTokenAsync</c> overloads.
        /// </summary>
        /// <param name="token">The token to be validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">A <see cref="CallContext"/> that contains call information.</param>
        /// <returns>A <see cref="ValidationResult{TResult, TError}"/> with either a <see cref="ValidatedToken"/> or a <see cref="ValidationError"/>.</returns>
        /// <remarks>
        /// This method can block. On a configuration cache miss, a recoverable failure (for example a signing key that
        /// rotated within the cached-but-fresh window), or when a token replay cache is configured, it delegates to
        /// <see cref="ValidateTokenAsync(string, ValidationParameters, CallContext, CancellationToken)"/> and blocks on
        /// the result. Callers on latency-sensitive threads should account for this fallback.
        /// </remarks>
        public ValidationResult<ValidatedToken, ValidationError> ValidateToken(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            if (string.IsNullOrEmpty(token))
                return ValidationError.NullParameter(nameof(token), ValidationError.GetCurrentStackFrame());

            if (validationParameters is null)
                return ValidationError.NullParameter(nameof(validationParameters), ValidationError.GetCurrentStackFrame());

            if (token.Length > MaximumTokenSizeInBytes)
            {
                return new ValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10209,
                        LogHelper.MarkAsNonPII(token.Length),
                        LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes)),
                    ValidationFailureType.SecurityTokenTooLarge,
                    ValidationError.GetCurrentStackFrame());
            }

            ValidationResult<SecurityToken, ValidationError> readResult = ReadToken(token, callContext);
            if (readResult.Succeeded)
            {
                ValidationResult<ValidatedToken, ValidationError> validationResult = ValidateToken(
                    readResult.Result!,
                    validationParameters,
                    callContext);

                if (validationResult.Succeeded)
                    return validationResult;

                return validationResult.Error!.AddStackFrame(ValidationError.GetCurrentStackFrame());
            }

            return readResult.Error!.AddCurrentStackFrame();
        }

        /// <summary>
        /// Synchronously validates a token, using the cached configuration when available and falling back to
        /// <see cref="ValidateTokenAsync(SecurityToken, ValidationParameters, CallContext, CancellationToken)"/> on a
        /// configuration cache miss or a recoverable failure.
        /// </summary>
        /// <param name="token">The <see cref="SecurityToken"/> to be validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">A <see cref="CallContext"/> that contains call information.</param>
        /// <returns>A <see cref="ValidationResult{TResult, TError}"/> with either a <see cref="ValidatedToken"/> or a <see cref="ValidationError"/>.</returns>
        /// <remarks>
        /// This method can block. On a configuration cache miss, a recoverable failure (for example a signing key that
        /// rotated within the cached-but-fresh window), or when a token replay cache is configured, it delegates to
        /// <see cref="ValidateTokenAsync(SecurityToken, ValidationParameters, CallContext, CancellationToken)"/> and blocks
        /// on the result. Callers on latency-sensitive threads should account for this fallback.
        /// </remarks>
        public ValidationResult<ValidatedToken, ValidationError> ValidateToken(
            SecurityToken token,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            if (token is null)
                return ValidationError.NullParameter(nameof(token), ValidationError.GetCurrentStackFrame());

            if (validationParameters is null)
                return ValidationError.NullParameter(nameof(validationParameters), ValidationError.GetCurrentStackFrame());

            if (token is not JsonWebToken jsonWebToken)
            {
                return new ValidationError(
                    new MessageDetail(TokenLogMessages.IDX10001, nameof(token), nameof(JsonWebToken)),
                    ValidationFailureType.SecurityTokenNotExpectedType,
                    ValidationError.GetCurrentStackFrame());
            }

            // Token replay validation has a side effect: it records the token in the replay cache (ITokenReplayCache.TryAdd).
            // The synchronous fast path may validate speculatively and then fall back to the asynchronous path on a
            // recoverable failure (e.g. a rotated signing key), which would run replay validation a second time and cause
            // the token to be spuriously reported as replayed. When a replay cache is configured, route straight to the
            // asynchronous path so replay validation runs exactly once.
            if (validationParameters.TokenReplayCache is not null)
            {
                return ValidateTokenAsync(token, validationParameters, callContext, CancellationToken.None)
                    .ConfigureAwait(false).GetAwaiter().GetResult();
            }

            BaseConfigurationManager? configurationManager = validationParameters.ConfigurationManager;

            // The synchronous fast path is available only when configuration is not needed (no ConfigurationManager)
            // or is already cached and fresh (peek hit). On a peek miss the configuration must be fetched, which is
            // asynchronous; route those (rare) calls to the untouched async path so miss/refresh/LKG behavior is preserved.
            BaseConfiguration? currentConfiguration = null;
            if (configurationManager is not null && !configurationManager.TryGetCurrentConfiguration(out currentConfiguration))
            {
                return ValidateTokenAsync(token, validationParameters, callContext, CancellationToken.None)
                    .ConfigureAwait(false).GetAwaiter().GetResult();
            }

            ValidationResult<ValidatedToken, ValidationError> result = jsonWebToken.IsEncrypted ?
                ValidateJWE(jsonWebToken, validationParameters, currentConfiguration, callContext) :
                ValidateJWS(jsonWebToken, validationParameters, currentConfiguration, callContext);

            if (configurationManager is null)
            {
                if (result.Succeeded)
                    return result;

                return result.Error!.AddStackFrame(ValidationError.GetCurrentStackFrame());
            }

            if (result.Succeeded)
            {
                // Set current configuration as LKG if it exists.
                if (currentConfiguration is not null)
                    configurationManager.LastKnownGoodConfiguration = currentConfiguration;

                return result;
            }

            // On a recoverable failure (e.g. a signing key rotated within the cached-but-fresh window) route to the
            // asynchronous path so its refresh-and-retry + last-known-good recovery runs; that recovery is never duplicated here.
            if (TokenUtilities.IsRecoverableFailureType(result.Error!.FailureType, (currentConfiguration != null && currentConfiguration.TokenDecryptionKeys.Count > 0)))
            {
                return ValidateTokenAsync(token, validationParameters, callContext, CancellationToken.None)
                    .ConfigureAwait(false).GetAwaiter().GetResult();
            }

            return result.Error!.AddCurrentStackFrame();
        }

        private ValidationResult<ValidatedToken, ValidationError> ValidateJWE(
            JsonWebToken jwtToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            ValidationResult<string, ValidationError> decryptionResult = DecryptToken(
                jwtToken, validationParameters, configuration, callContext);
            if (!decryptionResult.Succeeded)
            {
                return decryptionResult.Error!.AddCurrentStackFrame();
            }

            ValidationResult<SecurityToken, ValidationError> readResult = ReadToken(decryptionResult.Result!, callContext);
            if (!readResult.Succeeded)
            {
                return readResult.Error!.AddCurrentStackFrame();
            }

            JsonWebToken decryptedToken = (readResult.Result as JsonWebToken)!;
            ValidationResult<ValidatedToken, ValidationError> validationResult =
                ValidateJWS(decryptedToken!, validationParameters, configuration, callContext);

            if (!validationResult.Succeeded)
            {
                return validationResult.Error!.AddCurrentStackFrame();
            }

            JsonWebToken jsonWebToken = (validationResult.Result!.SecurityToken as JsonWebToken)!;

            jwtToken.InnerToken = jsonWebToken;
            jwtToken.Payload = jsonWebToken.Payload;

            return validationResult;
        }

        private ValidationResult<ValidatedToken, ValidationError> ValidateJWS(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            DateTime? expires = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Exp) ? jsonWebToken.ValidTo : null;
            DateTime? notBefore = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Nbf) ? jsonWebToken.ValidFrom : null;

            ValidationResult<ValidatedLifetime, ValidationError> lifetimeResult =
                Validators.ValidateLifetimeInternal(
                    notBefore,
                    expires,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!lifetimeResult.Succeeded)
                return lifetimeResult.Error!.AddCurrentStackFrame();

            if (jsonWebToken.Audiences is not IList<string> tokenAudiences)
                tokenAudiences = [.. jsonWebToken.Audiences];

            ValidationResult<string, ValidationError> audienceResult =
                Validators.ValidateAudienceInternal(
                    tokenAudiences,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!audienceResult.Succeeded)
                return audienceResult.Error!.AddCurrentStackFrame();

            ValidationResult<ValidatedIssuer, ValidationError> issuerResult =
                Validators.ValidateIssuerInternal(
                    jsonWebToken.Issuer,
                    jsonWebToken,
                    validationParameters,
                    configuration,
                    callContext);

            if (!issuerResult.Succeeded)
                return issuerResult.Error!.AddCurrentStackFrame();

            ValidationResult<DateTime?, ValidationError>? tokenReplayResult =
                Validators.ValidateTokenReplayInternal(
                    expires,
                    jsonWebToken.EncodedToken,
                    validationParameters,
                    callContext);

            if (!tokenReplayResult.Value.Succeeded)
                return tokenReplayResult.Value.Error!.AddCurrentStackFrame();

            ValidationResult<ValidatedTokenType, ValidationError> tokenTypeResult =
                Validators.ValidateTokenTypeInternal(
                    jsonWebToken.Typ,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!tokenTypeResult.Succeeded)
                return tokenTypeResult.Error!.AddCurrentStackFrame();

            ValidationResult<string, ValidationError> algorithmResult =
                Validators.ValidateAlgorithmInternal(
                    jsonWebToken.Alg,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!algorithmResult.Succeeded)
                return algorithmResult.Error!.AddCurrentStackFrame();

            // The signature validation delegate is yet to be migrated to ValidationParameters.
            ValidationResult<SecurityKey, ValidationError> signatureResult =
                ValidateSignature(
                    jsonWebToken,
                    validationParameters,
                    configuration,
                    callContext);

            if (!signatureResult.Succeeded)
                return signatureResult.Error!.AddCurrentStackFrame();

            ValidationResult<ValidatedSignatureKey, ValidationError> signatureKeyResult =
                Validators.ValidateSignatureKeyInternal(
                    jsonWebToken.SigningKey,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!signatureKeyResult.Succeeded)
                return signatureKeyResult.Error!.AddCurrentStackFrame();

            // actor validation
            ValidationResult<ValidatedToken, ValidationError>? actorResult = null;
            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jsonWebToken.Actor))
            {
                ValidationResult<SecurityToken, ValidationError> readResult = ReadToken(jsonWebToken.Actor, callContext);
                if (!readResult.Succeeded)
                    return readResult.Error!.AddCurrentStackFrame();

                if (validationParameters.ActorValidationParameters is null)
                    return ValidationError.NullParameter(
                        nameof(validationParameters.ActorValidationParameters),
                        ValidationError.GetCurrentStackFrame());

                // TODO - what if actor token is encrypted?
                JsonWebToken actorToken = (readResult.Result as JsonWebToken)!;
                actorResult = ValidateJWS(
                    actorToken,
                    validationParameters.ActorValidationParameters,
                    configuration,
                    callContext);

                if (!actorResult.Value.Succeeded)
                    return actorResult.Value.Error!.AddCurrentStackFrame();
            }

            return new ValidatedToken(jsonWebToken, this, validationParameters)
            {
                ValidatedLifetime = lifetimeResult.Result,
                ValidatedAlgorithm = algorithmResult.Result,
                ValidatedAudience = audienceResult.Result,
                ValidatedIssuer = issuerResult.Result,
                ActorValidationResult = actorResult?.Result,
                ValidatedTokenType = tokenTypeResult.Result,
                ValidatedSignatureKey = signatureResult.Result
            };
        }
        #endregion

        #region Explicit Interface Implementations
        async Task<ValidationResult<ValidatedToken, ValidationError>> IResultBasedValidation.ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return await ValidateTokenAsync(
                token,
                validationParameters,
                callContext,
                default).ConfigureAwait(false);
        }

        async Task<ValidationResult<ValidatedToken, ValidationError>> IResultBasedValidation.ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await ValidateTokenAsync(
                token,
                validationParameters,
                callContext,
                cancellationToken).ConfigureAwait(false);
        }

        async Task<ValidationResult<ValidatedToken, ValidationError>> IResultBasedValidation.ValidateTokenAsync(
            SecurityToken token,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return await ValidateTokenAsync(
                token,
                validationParameters,
                callContext,
                default).ConfigureAwait(false);
        }

        async Task<ValidationResult<ValidatedToken, ValidationError>> IResultBasedValidation.ValidateTokenAsync(
            SecurityToken token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await ValidateTokenAsync(
                token,
                validationParameters,
                callContext,
                cancellationToken).ConfigureAwait(false);
        }
        #endregion
    }
}
#nullable restore
