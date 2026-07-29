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
        /// <remarks>
        /// This method is intentionally not declared <see langword="async"/>. When validation can complete without
        /// obtaining configuration, it runs synchronously and returns an already-completed task, so no async state
        /// machine is generated for the caller's request.
        /// </remarks>
        public override Task<ValidationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(token))
            {
                return Task.FromResult<ValidationResult<ValidatedToken, ValidationError>>(
                    ValidationError.NullParameter(
                        nameof(token),
                        ValidationError.GetCurrentStackFrame()));
            }

            if (validationParameters is null)
            {
                return Task.FromResult<ValidationResult<ValidatedToken, ValidationError>>(
                    ValidationError.NullParameter(
                        nameof(validationParameters),
                        ValidationError.GetCurrentStackFrame()));
            }

            if (token.Length > MaximumTokenSizeInBytes)
            {
                return Task.FromResult<ValidationResult<ValidatedToken, ValidationError>>(
                    new ValidationError(
                        new MessageDetail(
                            TokenLogMessages.IDX10209,
                            LogHelper.MarkAsNonPII(token.Length),
                            LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes)),
                        ValidationFailureType.SecurityTokenTooLarge,
                        ValidationError.GetCurrentStackFrame()));
            }

            ValidationResult<SecurityToken, ValidationError> readResult = ReadToken(token, callContext);
            if (!readResult.Succeeded)
            {
                return Task.FromResult<ValidationResult<ValidatedToken, ValidationError>>(
                    readResult.Error!.AddCurrentStackFrame());
            }

            Task<ValidationResult<ValidatedToken, ValidationError>> validationTask = ValidateTokenAsync(
                readResult.Result!,
                validationParameters,
                callContext,
                cancellationToken);

            // The overwhelming majority of calls complete synchronously (no configuration needed, or a configuration
            // cache hit), so unwrap the completed task inline rather than awaiting it and forcing a state machine.
            if (validationTask.Status == TaskStatus.RanToCompletion)
            {
                // The task is already in the RanToCompletion state, so reading Result cannot block or throw.
#pragma warning disable VSTHRD103 // Call async methods when in an async method
                ValidationResult<ValidatedToken, ValidationError> validationResult = validationTask.Result;
#pragma warning restore VSTHRD103
                if (validationResult.Succeeded)
                    return validationTask; // No need to unwrap and re-wrap the result.

                return Task.FromResult<ValidationResult<ValidatedToken, ValidationError>>(
                    validationResult.Error!.AddStackFrame(ValidationError.GetCurrentStackFrame()));
            }

            return AddStackFrameOnFailureAsync(validationTask);
        }

        // The task passed here was created by this type on the calling context; the threading analyzer cannot see that.
#pragma warning disable VSTHRD003 // Avoid awaiting foreign Tasks
        private static async Task<ValidationResult<ValidatedToken, ValidationError>> AddStackFrameOnFailureAsync(
            Task<ValidationResult<ValidatedToken, ValidationError>> validationTask)
        {
            ValidationResult<ValidatedToken, ValidationError> validationResult =
                await validationTask.ConfigureAwait(false);
#pragma warning restore VSTHRD003

            if (validationResult.Succeeded)
                return validationResult;

            return validationResult.Error!.AddStackFrame(ValidationError.GetCurrentStackFrame());
        }

        /// <inheritdoc/>
        /// <remarks>
        /// This method is intentionally not declared <see langword="async"/>. When configuration is not required (no
        /// <see cref="BaseConfigurationManager"/> is set) or is already cached and fresh, the whole validation pipeline
        /// runs synchronously and an already-completed task is returned; no async state machine, awaiter, or
        /// per-await continuation is allocated. The asynchronous path is entered only when configuration must actually
        /// be obtained (cache miss), when a recoverable failure requires refresh / last-known-good recovery, or when a
        /// token replay cache is configured.
        /// </remarks>
        public override Task<ValidationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
            SecurityToken token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            if (token is null)
            {
                return Task.FromResult<ValidationResult<ValidatedToken, ValidationError>>(
                    ValidationError.NullParameter(
                        nameof(token),
                        ValidationError.GetCurrentStackFrame()));
            }

            if (validationParameters is null)
            {
                return Task.FromResult<ValidationResult<ValidatedToken, ValidationError>>(
                    ValidationError.NullParameter(
                        nameof(validationParameters),
                        ValidationError.GetCurrentStackFrame()));
            }

            if (token is not JsonWebToken jsonWebToken)
            {
                return Task.FromResult<ValidationResult<ValidatedToken, ValidationError>>(
                    new ValidationError(
                        new MessageDetail(TokenLogMessages.IDX10001, nameof(token), nameof(JsonWebToken)),
                        ValidationFailureType.SecurityTokenNotExpectedType,
                        ValidationError.GetCurrentStackFrame()));
            }

            if (TryValidateTokenSynchronously(
                    jsonWebToken,
                    validationParameters,
                    callContext,
                    out ValidationResult<ValidatedToken, ValidationError> result))
            {
                return Task.FromResult(result);
            }

            return ValidateTokenCoreAsync(jsonWebToken, validationParameters, callContext, cancellationToken);
        }

        private async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateTokenCoreAsync(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
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

            if (TryValidateTokenSynchronously(
                    jsonWebToken,
                    validationParameters,
                    callContext,
                    out ValidationResult<ValidatedToken, ValidationError> result))
            {
                return result;
            }

            // Configuration must be obtained, or refresh / last-known-good recovery is required. Both are asynchronous
            // today, so this is the one place the synchronous contract blocks. True synchronous configuration retrieval
            // is tracked separately; see the #3459 scope notes.
            return ValidateTokenAsync(token, validationParameters, callContext, CancellationToken.None)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Runs the validation pipeline synchronously when it can complete without obtaining configuration.
        /// </summary>
        /// <param name="jsonWebToken">The token to validate.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">A <see cref="CallContext"/> that contains call information.</param>
        /// <param name="result">When this method returns <see langword="true"/>, the final validation result.</param>
        /// <returns>
        /// <see langword="true"/> when <paramref name="result"/> is final; <see langword="false"/> when the caller must
        /// use the asynchronous path because configuration has to be obtained, a recoverable failure needs
        /// refresh / last-known-good recovery, or a token replay cache is configured.
        /// </returns>
        /// <remarks>
        /// This is the single implementation of the cache-hit fast path. Both
        /// <see cref="ValidateTokenAsync(SecurityToken, ValidationParameters, CallContext, CancellationToken)"/> and
        /// <see cref="ValidateToken(SecurityToken, ValidationParameters, CallContext)"/> call it so the two entry points
        /// cannot drift. It never blocks, fetches, or refreshes.
        /// </remarks>
        private bool TryValidateTokenSynchronously(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            out ValidationResult<ValidatedToken, ValidationError> result)
        {
            result = default;

            // Token replay validation has a side effect: it records the token in the replay cache (ITokenReplayCache.TryAdd).
            // The synchronous fast path may validate speculatively and then hand off to the asynchronous path on a
            // recoverable failure, which would run replay validation a second time and cause the token to be spuriously
            // reported as replayed. When a replay cache is configured, defer to the asynchronous path so replay
            // validation runs exactly once.
            if (validationParameters.TokenReplayCache is not null)
                return false;

            // The fast path is available only when configuration is not needed (no ConfigurationManager) or is already
            // cached and fresh (peek hit). On a peek miss the configuration must be fetched, which is asynchronous.
            BaseConfigurationManager? configurationManager = validationParameters.ConfigurationManager;
            BaseConfiguration? currentConfiguration = null;
            if (configurationManager is not null && !configurationManager.TryGetCurrentConfiguration(out currentConfiguration))
                return false;

            ValidationResult<ValidatedToken, ValidationError> validationResult = jsonWebToken.IsEncrypted ?
                ValidateJWE(jsonWebToken, validationParameters, currentConfiguration, callContext) :
                ValidateJWS(jsonWebToken, validationParameters, currentConfiguration, callContext);

            if (configurationManager is null)
            {
                result = validationResult.Succeeded ?
                    validationResult :
                    validationResult.Error!.AddStackFrame(ValidationError.GetCurrentStackFrame());

                return true;
            }

            if (validationResult.Succeeded)
            {
                // Set current configuration as LKG if it exists.
                if (currentConfiguration is not null)
                    configurationManager.LastKnownGoodConfiguration = currentConfiguration;

                result = validationResult;
                return true;
            }

            // A recoverable failure (for example a signing key that rotated within the cached-but-fresh window) needs the
            // asynchronous refresh-and-retry plus last-known-good recovery; that recovery is never duplicated here.
            if (TokenUtilities.IsRecoverableFailureType(
                    validationResult.Error!.FailureType,
                    currentConfiguration is not null && currentConfiguration.TokenDecryptionKeys.Count > 0))
            {
                return false;
            }

            result = validationResult.Error!.AddCurrentStackFrame();
            return true;
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
