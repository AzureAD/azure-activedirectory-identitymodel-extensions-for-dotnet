// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
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
        /// On a validation failure, no exception will be thrown; instead, the exception will be set in the returned TokenValidationResult.Exception property.
        /// Callers should always check the TokenValidationResult.IsValid property to verify the validity of the result.
        /// </summary>
        /// <param name="token">The token to be validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">A <see cref="CallContext"/> that contains useful information for logging.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> that can be used to request cancellation of the asynchronous operation.</param>
        /// <returns>A <see cref="Result{TResult, TError}"/> with either a <see cref="ValidationResult"/> if the token was validated or an <see cref="ExceptionDetail"/> with the failure information and exception otherwise.</returns>
        /// <remarks>
        /// <para>ExceptionDetail.GetException() will return one of the following exceptions if the <paramref name="token"/> is invalid.</para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">Returned if <paramref name="token"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException">Returned if <paramref name="validationParameters"/> is null.</exception>
        /// <exception cref="ArgumentException">Returned if 'token.Length' is greater than <see cref="TokenHandler.MaximumTokenSizeInBytes"/>.</exception>
        /// <exception cref="SecurityTokenMalformedException">Returned if <paramref name="token"/> is not a valid <see cref="JsonWebToken"/>, <see cref="ReadToken(string, CallContext)"/></exception>
        /// <exception cref="SecurityTokenMalformedException">Returned if the validationParameters.TokenReader delegate is not able to parse/read the token as a valid <see cref="JsonWebToken"/>, <see cref="ReadToken(string, CallContext)"/></exception>
        internal async Task<Result<ValidationResult, ExceptionDetail>> ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            // These exceptions will be removed once we add ExceptionDetails to TokenValidationResult.
            if (string.IsNullOrEmpty(token))
            {
                StackFrame nullTokenStackFrame = StackFrames.TokenStringNull ??= new StackFrame(true);
                return ExceptionDetail.NullParameter(
                        nameof(token),
                        nullTokenStackFrame);
            }

            if (validationParameters is null)
            {
                StackFrame nullValidationParametersStackFrame = StackFrames.TokenStringValidationParametersNull ??= new StackFrame(true);
                return ExceptionDetail.NullParameter(
                        nameof(validationParameters),
                        nullValidationParametersStackFrame);
            }

            if (token.Length > MaximumTokenSizeInBytes)
            {
                StackFrame invalidTokenLengthStackFrame = StackFrames.InvalidTokenLength ??= new StackFrame(true);
                return new ExceptionDetail(
                        new MessageDetail(
                            TokenLogMessages.IDX10209,
                            LogHelper.MarkAsNonPII(token.Length),
                            LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes)),
                        ValidationFailureType.InvalidSecurityToken,
                        typeof(ArgumentException),
                        invalidTokenLengthStackFrame);
            }

            Result<SecurityToken, ExceptionDetail> readResult = ReadToken(token, callContext);
            if (readResult.IsSuccess)
            {
                Result<ValidationResult, ExceptionDetail> validationResult = await ValidateTokenAsync(
                    readResult.UnwrapResult(),
                    validationParameters,
                    callContext,
                    cancellationToken)
                    .ConfigureAwait(false);

                if (validationResult.IsSuccess)
                    return validationResult; // No need to unwrap and re-wrap the result.

                StackFrame validationFailureStackFrame = StackFrames.TokenStringValidationFailed ??= new StackFrame(true);
                return validationResult.UnwrapError().AddStackFrame(validationFailureStackFrame);
            }

            StackFrame readFailureStackFrame = StackFrames.TokenStringReadFailed ??= new StackFrame(true);
            return readResult.UnwrapError().AddStackFrame(readFailureStackFrame);
        }

        /// <inheritdoc/>
        internal async Task<Result<ValidationResult, ExceptionDetail>> ValidateTokenAsync(
            SecurityToken token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            if (token is null)
            {
                StackFrame nullTokenStackFrame = StackFrames.TokenNull ??= new StackFrame(true);
                return ExceptionDetail.NullParameter(
                    nameof(token),
                    nullTokenStackFrame);
            }

            if (validationParameters is null)
            {
                StackFrame nullValidationParametersStackFrame = StackFrames.TokenValidationParametersNull ??= new StackFrame(true);
                return ExceptionDetail.NullParameter(
                    nameof(validationParameters),
                    nullValidationParametersStackFrame);
            }

            if (token is not JsonWebToken jsonWebToken)
            {
                StackFrame notJwtStackFrame = StackFrames.TokenNotJWT ??= new StackFrame(true);
                return new ExceptionDetail(
                    new MessageDetail(TokenLogMessages.IDX10001, nameof(token), nameof(JsonWebToken)),
                    ValidationFailureType.InvalidSecurityToken,
                    typeof(ArgumentException),
                    notJwtStackFrame);
            }

            BaseConfiguration? currentConfiguration =
                await GetCurrentConfigurationAsync(validationParameters)
                .ConfigureAwait(false);

            Result<ValidationResult, ExceptionDetail> result = jsonWebToken.IsEncrypted ?
                await ValidateJWEAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false) :
                await ValidateJWSAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false);

            if (validationParameters.ConfigurationManager is null)
            {
                if (result.IsSuccess)
                    return result;

                StackFrame tokenValidationStackFrame = StackFrames.TokenValidationFailedNullConfigurationManager ??= new StackFrame(true);
                return result.UnwrapError().AddStackFrame(tokenValidationStackFrame);
            }

            if (result.IsSuccess)
            {
                // Set current configuration as LKG if it exists.
                if (currentConfiguration is not null)
                    validationParameters.ConfigurationManager.LastKnownGoodConfiguration = currentConfiguration;

                return result;
            }

            if (TokenUtilities.IsRecoverableException(result.UnwrapError().GetException()))
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

                        if (result.IsSuccess)
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
                    Exception recoverableExceptionType = result.UnwrapError().GetException();

                    BaseConfiguration[] validConfigurations = validationParameters.ConfigurationManager.GetValidLkgConfigurations();
                    for (int i = 0; i < validConfigurations.Length; i++)
                    {
                        BaseConfiguration lkgConfiguration = validConfigurations[i];
                        if (TokenUtilities.IsRecoverableConfiguration(
                            jsonWebToken.Kid, currentConfiguration, lkgConfiguration, recoverableExceptionType))
                        {
                            result = jsonWebToken.IsEncrypted ?
                                await ValidateJWEAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false) :
                                await ValidateJWSAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false);

                            if (result.IsSuccess)
                                return result;
                        }
                    }
                }
            }

            // If we reach this point, the token validation failed and we should return the error.
            StackFrame stackFrame = StackFrames.TokenValidationFailed ??= new StackFrame(true);
            return result.UnwrapError().AddStackFrame(stackFrame);
        }

        private async ValueTask<Result<ValidationResult, ExceptionDetail>> ValidateJWEAsync(
            JsonWebToken jwtToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            Result<string, ExceptionDetail> decryptionResult = DecryptToken(
                jwtToken, validationParameters, configuration, callContext);
            if (!decryptionResult.IsSuccess)
            {
                StackFrame decryptionFailureStackFrame = StackFrames.DecryptionFailed ??= new StackFrame(true);
                return decryptionResult.UnwrapError().AddStackFrame(decryptionFailureStackFrame);
            }

            Result<SecurityToken, ExceptionDetail> readResult = ReadToken(decryptionResult.UnwrapResult(), callContext);
            if (!readResult.IsSuccess)
            {
                StackFrame readFailureStackFrame = StackFrames.DecryptedReadFailed ??= new StackFrame(true);
                return readResult.UnwrapError().AddStackFrame(readFailureStackFrame);
            }

            JsonWebToken decryptedToken = (readResult.UnwrapResult() as JsonWebToken)!;
            Result<ValidationResult, ExceptionDetail> validationResult =
                await ValidateJWSAsync(decryptedToken!, validationParameters, configuration, callContext, cancellationToken)
                .ConfigureAwait(false);

            if (!validationResult.IsSuccess)
            {
                StackFrame validationFailureStackFrame = StackFrames.JWEValidationFailed ??= new StackFrame(true);
                return validationResult.UnwrapError().AddStackFrame(validationFailureStackFrame);
            }

            JsonWebToken jsonWebToken = (validationResult.UnwrapResult().SecurityToken as JsonWebToken)!;

            jwtToken.InnerToken = jsonWebToken;
            jwtToken.Payload = jsonWebToken.Payload;

            return validationResult;
        }

        private async ValueTask<Result<ValidationResult, ExceptionDetail>> ValidateJWSAsync(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            DateTime? expires = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Exp) ? jsonWebToken.ValidTo : null;
            DateTime? notBefore = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Nbf) ? jsonWebToken.ValidFrom : null;

            Result<ValidatedLifetime, ExceptionDetail> lifetimeValidationResult = validationParameters.LifetimeValidator(
                notBefore, expires, jsonWebToken, validationParameters, callContext);

            if (!lifetimeValidationResult.IsSuccess)
            {
                StackFrame lifetimeValidationFailureStackFrame = StackFrames.LifetimeValidationFailed ??= new StackFrame(true);
                return lifetimeValidationResult.UnwrapError().AddStackFrame(lifetimeValidationFailureStackFrame);
            }

            if (jsonWebToken.Audiences is not IList<string> tokenAudiences)
                tokenAudiences = jsonWebToken.Audiences.ToList();

            Result<string, ExceptionDetail> audienceValidationResult = validationParameters.AudienceValidator(
                tokenAudiences, jsonWebToken, validationParameters, callContext);

            if (!audienceValidationResult.IsSuccess)
            {
                StackFrame audienceValidationFailureStackFrame = StackFrames.AudienceValidationFailed ??= new StackFrame(true);
                return audienceValidationResult.UnwrapError().AddStackFrame(audienceValidationFailureStackFrame);
            }

            Result<ValidatedIssuer, ExceptionDetail> issuerValidationResult = await validationParameters.IssuerValidatorAsync(
                jsonWebToken.Issuer, jsonWebToken, validationParameters, callContext, cancellationToken)
                .ConfigureAwait(false);

            if (!issuerValidationResult.IsSuccess)
            {
                StackFrame issuerValidationFailureStackFrame = StackFrames.IssuerValidationFailed ??= new StackFrame(true);
                return issuerValidationResult.UnwrapError().AddStackFrame(issuerValidationFailureStackFrame);
            }

            Result<DateTime?, ExceptionDetail> replayValidationResult = validationParameters.TokenReplayValidator(
                expires, jsonWebToken.EncodedToken, validationParameters, callContext);

            if (!replayValidationResult.IsSuccess)
            {
                StackFrame replayValidationFailureStackFrame = StackFrames.ReplayValidationFailed ??= new StackFrame(true);
                return replayValidationResult.UnwrapError().AddStackFrame(replayValidationFailureStackFrame);
            }

            Result<ValidationResult, ExceptionDetail>? actorValidationResult = null;
            // actor validation
            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jsonWebToken.Actor))
            {
                Result<SecurityToken, ExceptionDetail> actorReadingResult = ReadToken(jsonWebToken.Actor, callContext);
                if (!actorReadingResult.IsSuccess)
                {
                    StackFrame actorReadingFailureStackFrame = StackFrames.ActorReadFailed ??= new StackFrame(true);
                    return actorReadingResult.UnwrapError().AddStackFrame(actorReadingFailureStackFrame);
                }

                JsonWebToken actorToken = (actorReadingResult.UnwrapResult() as JsonWebToken)!;
                ValidationParameters actorParameters = validationParameters.ActorValidationParameters;
                Result<ValidationResult, ExceptionDetail> innerActorValidationResult =
                    await ValidateJWSAsync(actorToken, actorParameters, configuration, callContext, cancellationToken)
                    .ConfigureAwait(false);

                if (!innerActorValidationResult.IsSuccess)
                {
                    StackFrame actorValidationFailureStackFrame = StackFrames.ActorValidationFailed ??= new StackFrame(true);
                    return innerActorValidationResult.UnwrapError().AddStackFrame(actorValidationFailureStackFrame);
                }

                actorValidationResult = innerActorValidationResult;
            }

            Result<ValidatedTokenType, ExceptionDetail> typeValidationResult = validationParameters.TypeValidator(
                jsonWebToken.Typ, jsonWebToken, validationParameters, callContext);
            if (!typeValidationResult.IsSuccess)
            {
                StackFrame typeValidationFailureStackFrame = StackFrames.TypeValidationFailed ??= new StackFrame(true);
                return typeValidationResult.UnwrapError().AddStackFrame(typeValidationFailureStackFrame);
            }

            // The signature validation delegate is yet to be migrated to ValidationParameters.
            Result<SecurityKey, ExceptionDetail> signatureValidationResult = ValidateSignature(
                jsonWebToken, validationParameters, configuration, callContext);
            if (!signatureValidationResult.IsSuccess)
            {
                StackFrame signatureValidationFailureStackFrame = StackFrames.SignatureValidationFailed ??= new StackFrame(true);
                return signatureValidationResult.UnwrapError().AddStackFrame(signatureValidationFailureStackFrame);
            }

            Result<ValidatedSigningKeyLifetime, ExceptionDetail> issuerSigningKeyValidationResult =
                validationParameters.IssuerSigningKeyValidator(
                    signatureValidationResult.UnwrapResult(), jsonWebToken, validationParameters, configuration, callContext);
            if (!issuerSigningKeyValidationResult.IsSuccess)
            {
                StackFrame issuerSigningKeyValidationFailureStackFrame = StackFrames.IssuerSigningKeyValidationFailed ??= new StackFrame(true);
                return issuerSigningKeyValidationResult.UnwrapError().AddStackFrame(issuerSigningKeyValidationFailureStackFrame);
            }

            return new ValidationResult(jsonWebToken, this, validationParameters)
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
