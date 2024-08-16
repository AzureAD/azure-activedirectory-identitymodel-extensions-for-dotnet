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
        internal async Task<TokenValidationResult> ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken? cancellationToken)
        {
            // These exceptions will be removed once we add ExceptionDetails to TokenValidationResult.
            if (string.IsNullOrEmpty(token))
                return new TokenValidationResult { Exception = LogHelper.LogArgumentNullException(nameof(token)), IsValid = false };

            if (validationParameters is null)
                return new TokenValidationResult { Exception = LogHelper.LogArgumentNullException(nameof(validationParameters)), IsValid = false };

            if (token.Length > MaximumTokenSizeInBytes)
                return new TokenValidationResult { Exception = LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(TokenLogMessages.IDX10209, LogHelper.MarkAsNonPII(token.Length), LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes)))), IsValid = false };

            Result<SecurityToken, TokenValidationError> result = ReadToken(token, callContext);
            if (result.IsSuccess)
                return await ValidateTokenAsync(
                    result.Unwrap(),
                    validationParameters,
                    callContext,
                    cancellationToken)
                    .ConfigureAwait(false);

            ExceptionDetail exceptionDetail = new ExceptionDetail(result.UnwrapError().MessageDetail, result.UnwrapError().ErrorType);

            return new TokenValidationResult
            {
                Exception = exceptionDetail.GetException(),
                IsValid = false
            };
        }

        /// <inheritdoc/>
        internal async Task<TokenValidationResult> ValidateTokenAsync(
            SecurityToken token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken? cancellationToken)
        {
            // These exceptions will be removed once we add ExceptionDetails to TokenValidationResult.
            if (token is null)
                throw LogHelper.LogArgumentNullException(nameof(token));

            if (validationParameters is null)
                return new TokenValidationResult { Exception = LogHelper.LogArgumentNullException(nameof(validationParameters)), IsValid = false };

            if (token is not JsonWebToken jwt)
                return new TokenValidationResult { Exception = LogHelper.LogArgumentException<ArgumentException>(nameof(token), $"{nameof(token)} must be a {nameof(JsonWebToken)}."), IsValid = false };

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
        private async ValueTask<TokenValidationResult> InternalValidateTokenAsync(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken? cancellationToken)
        {
            BaseConfiguration currentConfiguration =
                await GetCurrentConfigurationAsync(validationParameters)
                .ConfigureAwait(false);

            InternalTokenValidationResult result = jsonWebToken.IsEncrypted ?
                await ValidateJWEAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false) :
                await ValidateJWSAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false);

            if (validationParameters.ConfigurationManager is null)
                return result.ToTokenValidationResult();

            if (result.IsValid)
            {
                // Set current configuration as LKG if it exists.
                if (currentConfiguration is not null)
                    validationParameters.ConfigurationManager.LastKnownGoodConfiguration = currentConfiguration;

                return result.ToTokenValidationResult();
            }

            if (TokenUtilities.IsRecoverableExceptionType(result.ExceptionDetail.Type))
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
                            return result.ToTokenValidationResult();
                        }
                    }
                }

                if (validationParameters.ConfigurationManager.UseLastKnownGoodConfiguration)
                {
                    validationParameters.RefreshBeforeValidation = false;
                    validationParameters.ValidateWithLKG = true;
                    ValidationErrorType recoverableExceptionType = result.ExceptionDetail.Type;

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
                                return result.ToTokenValidationResult();
                        }
                    }
                }
            }

            return result.ToTokenValidationResult();
        }

        private async ValueTask<InternalTokenValidationResult> ValidateJWEAsync(
            JsonWebToken jwtToken,
            ValidationParameters validationParameters,
            BaseConfiguration configuration,
            CallContext callContext,
            CancellationToken? cancellationToken)
        {
            InternalTokenValidationResult internalResult = new InternalTokenValidationResult(jwtToken, this);

            TokenDecryptionResult decryptionResult = DecryptToken(jwtToken, validationParameters, configuration, callContext);
            if (!internalResult.AddResult(decryptionResult))
                return internalResult;

            Result<SecurityToken, TokenValidationError> result = ReadToken(decryptionResult.DecryptedToken(), callContext);
            if (!result.IsSuccess)
                return internalResult;
            //TokenReadingResult readingResult = ReadToken(decryptionResult.DecryptedToken(), callContext);
            //if (!internalResult.AddResult(readingResult))
            //    return internalResult;

            JsonWebToken decryptedToken = result.Unwrap() as JsonWebToken;

            InternalTokenValidationResult jwsResult =
                await ValidateJWSAsync(decryptedToken, validationParameters, configuration, callContext, cancellationToken)
                .ConfigureAwait(false);

            if (!internalResult.Merge(jwsResult))
                return internalResult;

            jwtToken.InnerToken = internalResult.SecurityToken as JsonWebToken;
            jwtToken.Payload = (internalResult.SecurityToken as JsonWebToken).Payload;

            return internalResult;
        }

        private async ValueTask<InternalTokenValidationResult> ValidateJWSAsync(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            BaseConfiguration configuration,
            CallContext callContext,
            CancellationToken? cancellationToken)
        {
            if (validationParameters.TransformBeforeSignatureValidation is not null)
                jsonWebToken = validationParameters.TransformBeforeSignatureValidation(jsonWebToken, validationParameters) as JsonWebToken;

            InternalTokenValidationResult internalResult = new InternalTokenValidationResult(jsonWebToken, this);

            DateTime? expires = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Exp) ? jsonWebToken.ValidTo : null;
            DateTime? notBefore = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Nbf) ? jsonWebToken.ValidFrom : null;

            if (!internalResult.AddResult(validationParameters.LifetimeValidator(
                notBefore, expires, jsonWebToken, validationParameters, callContext)))
                return internalResult;

            if (jsonWebToken.Audiences is not IList<string> tokenAudiences)
                tokenAudiences = jsonWebToken.Audiences.ToList();

            if (!internalResult.AddResult(validationParameters.AudienceValidator(
                tokenAudiences, jsonWebToken, validationParameters, callContext)))
                return internalResult;

            if (!internalResult.AddResult(await validationParameters.IssuerValidatorAsync(
                jsonWebToken.Issuer, jsonWebToken, validationParameters, callContext, cancellationToken)
                .ConfigureAwait(false)))
                return internalResult;

            if (!internalResult.AddResult(validationParameters.TokenReplayValidator(
                expires, jsonWebToken.EncodedToken, validationParameters, callContext)))
                return internalResult;

            // actor validation
            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jsonWebToken.Actor))
            {
                Result<SecurityToken, TokenValidationError> actorReadingResult = ReadToken(jsonWebToken.Actor, callContext);
                if (!actorReadingResult.IsSuccess)
                    return internalResult;

                JsonWebToken actorToken = actorReadingResult.Unwrap() as JsonWebToken;
                ValidationParameters actorParameters = validationParameters.ActorValidationParameters;
                InternalTokenValidationResult actorValidationResult =
                    await ValidateJWSAsync(actorToken, actorParameters, configuration, callContext, cancellationToken)
                    .ConfigureAwait(false);

                // Consider adding a new ValidationResult type for actor validation
                // that wraps the actorValidationResult.ValidationResults
                if (!internalResult.AddResults(actorValidationResult.ValidationResults))
                    return internalResult;
            }

            if (!internalResult.AddResult(validationParameters.TypeValidator(
                jsonWebToken.Typ, jsonWebToken, validationParameters, callContext)))
                return internalResult;

            // The signature validation delegate is yet to be migrated to ValidationParameters.
            if (!internalResult.AddResult(ValidateSignature(
                jsonWebToken, validationParameters, configuration, callContext)))
                return internalResult;

            if (!internalResult.AddResult(validationParameters.IssuerSigningKeyValidator(
                jsonWebToken.SigningKey, jsonWebToken, validationParameters, configuration, callContext)))
                return internalResult;

            return internalResult;
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
