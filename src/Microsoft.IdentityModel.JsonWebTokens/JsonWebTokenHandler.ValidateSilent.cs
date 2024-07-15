// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <remarks>This partial class contains methods and logic related to the validation of tokens.</remarks>
    public partial class JsonWebTokenHandler : TokenHandler
    {
        /// <summary>
        /// Validates the JWT signature.
        /// </summary>
        private static SignatureValidationResult ValidateSignature(JsonWebToken jwtToken, ValidationParameters validationParameters)
        {
            bool kidMatched = false;
            SecurityKey key = null;

            if (!jwtToken.IsSigned)
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10504, jwtToken)));

            if (validationParameters.IssuerSigningKeyResolver != null)
            {
                key = validationParameters.IssuerSigningKeyResolver(jwtToken.EncodedToken, jwtToken, jwtToken.Kid, validationParameters);
            }
            else
            {
                key = JwtTokenUtilities.ResolveTokenSigningKey(jwtToken.Kid, jwtToken.X5t, validationParameters);
            }

            // keep track of exceptions thrown, keys that were tried
            StringBuilder exceptionStrings = null;
            StringBuilder keysAttempted = null;
            var kidExists = !string.IsNullOrEmpty(jwtToken.Kid);

            if (keys != null)
            {
                foreach (var key in keys)
                {
#pragma warning disable CA1031 // Do not catch general exception types
                    try
                    {
                        if (ValidateSignature(jwtToken, key, validationParameters))
                        {
                            if (LogHelper.IsEnabled(EventLogLevel.Informational))
                                LogHelper.LogInformation(TokenLogMessages.IDX10242, jwtToken);

                            jwtToken.SigningKey = key;
                            return jwtToken;
                        }
                    }
                    catch (Exception ex)
                    {
                        (exceptionStrings ??= new StringBuilder()).AppendLine(ex.ToString());
                    }
#pragma warning restore CA1031 // Do not catch general exception types

                    if (key != null)
                    {
                        (keysAttempted ??= new StringBuilder()).Append(key.ToString()).Append(" , KeyId: ").AppendLine(key.KeyId);
                        if (kidExists && !kidMatched && key.KeyId != null)
                            kidMatched = jwtToken.Kid.Equals(key.KeyId, key is X509SecurityKey ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
                    }
                }
            }

            // Get information on where keys used during token validation came from for debugging purposes.
            var keysInTokenValidationParameters = TokenUtilities.GetAllSigningKeys(validationParameters: validationParameters);

            var keysInConfiguration = TokenUtilities.GetAllSigningKeys(configuration);
            var numKeysInTokenValidationParameters = keysInTokenValidationParameters.Count();
            var numKeysInConfiguration = keysInConfiguration.Count();

            if (kidExists)
            {
                if (kidMatched)
                {
                    JsonWebToken localJwtToken = jwtToken; // avoid closure on non-exceptional path
                    var isKidInTVP = keysInTokenValidationParameters.Any(x => x.KeyId.Equals(localJwtToken.Kid));
                    var keyLocation = isKidInTVP ? "TokenValidationParameters" : "Configuration";
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10511,
                        LogHelper.MarkAsNonPII((object)keysAttempted ?? ""),
                        LogHelper.MarkAsNonPII(numKeysInTokenValidationParameters),
                        LogHelper.MarkAsNonPII(numKeysInConfiguration),
                        LogHelper.MarkAsNonPII(keyLocation),
                        LogHelper.MarkAsNonPII(jwtToken.Kid),
                        (object)exceptionStrings ?? "",
                        jwtToken)));
                }

                if (!validationParameters.ValidateSignatureLast)
                {
                    InternalValidators.ValidateAfterSignatureFailed(
                        jwtToken,
                        jwtToken.ValidFromNullable,
                        jwtToken.ValidToNullable,
                        jwtToken.Audiences,
                        validationParameters,
                        configuration);
                }
            }

            if (keysAttempted is not null)
            {
                if (kidExists)
                {
                    throw LogHelper.LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(LogHelper.FormatInvariant(TokenLogMessages.IDX10503,
                        LogHelper.MarkAsNonPII(jwtToken.Kid),
                        LogHelper.MarkAsNonPII((object)keysAttempted ?? ""),
                        LogHelper.MarkAsNonPII(numKeysInTokenValidationParameters),
                        LogHelper.MarkAsNonPII(numKeysInConfiguration),
                        (object)exceptionStrings ?? "",
                        jwtToken)));
                }
                else
                {
                    throw LogHelper.LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(LogHelper.FormatInvariant(TokenLogMessages.IDX10517,
                        LogHelper.MarkAsNonPII((object)keysAttempted ?? ""),
                        LogHelper.MarkAsNonPII(numKeysInTokenValidationParameters),
                        LogHelper.MarkAsNonPII(numKeysInConfiguration),
                        (object)exceptionStrings ?? "",
                        jwtToken)));
                }
            }

            throw LogHelper.LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(TokenLogMessages.IDX10500));
        }

        internal async ValueTask<TokenValidationResult> ValidateJWEAsync(
            JsonWebToken jwtToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            try
            {
                TokenValidationResult tokenValidationResult = ReadToken(DecryptToken(jwtToken, validationParameters), validationParameters);
                if (!tokenValidationResult.IsValid)
                    return tokenValidationResult;

                tokenValidationResult = await ValidateJWSAsync(
                    tokenValidationResult.SecurityToken as JsonWebToken,
                    validationParameters,
                    callContext,
                    cancellationToken).ConfigureAwait(false);

                if (!tokenValidationResult.IsValid)
                    return tokenValidationResult;

                jwtToken.InnerToken = tokenValidationResult.SecurityToken as JsonWebToken;
                jwtToken.Payload = (tokenValidationResult.SecurityToken as JsonWebToken).Payload;
                return new TokenValidationResult
                {
                    SecurityToken = jwtToken,
                    ClaimsIdentityNoLocking = tokenValidationResult.ClaimsIdentityNoLocking,
                    IsValid = true,
                    TokenType = tokenValidationResult.TokenType
                };
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new TokenValidationResult
                {
                    Exception = ex,
                    IsValid = false,
                    TokenOnFailedValidation = validationParameters.IncludeTokenOnFailedValidation ? jwtToken : null
                };
            }
        }

        internal async ValueTask<TokenValidationResult> ValidateJWSAsync(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            try
            {
                BaseConfiguration currentConfiguration = null;
                if (validationParameters.ConfigurationManager != null)
                {
                    try
                    {
                        currentConfiguration = await validationParameters.ConfigurationManager.GetBaseConfigurationAsync(CancellationToken.None).ConfigureAwait(false);
                    }
#pragma warning disable CA1031 // Do not catch general exception types
                    catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
                    {
                        // The exception is not re-thrown as the TokenValidationParameters may have the issuer and signing key set
                        // directly on them, allowing the library to continue with token validation.
                        if (LogHelper.IsEnabled(EventLogLevel.Warning))
                            LogHelper.LogWarning(LogHelper.FormatInvariant(TokenLogMessages.IDX10261, validationParameters.ConfigurationManager.MetadataAddress, ex.ToString()));
                    }
                }

                // TODO - can we remove the need for the transform by using a signature validator and placing the transormation there?
                //TokenValidationResult tokenValidationResult;
                //if (validationParameters.TransformBeforeSignatureValidation != null)
                //    jsonWebToken = validationParameters.TransformBeforeSignatureValidation(jsonWebToken, validationParameters) as JsonWebToken;

                if (validationParameters.SignatureValidator != null)
                {
                    SignatureValidationResult signatureValidationResult = validationParameters.SignatureValidator(jsonWebToken.EncodedToken, validationParameters, callContext);
                    TokenValidationResult tokenValidationResult = await ValidateTokenPayloadAsync(
                        signatureValidationResult.SecurityToken as JsonWebToken,
                        validationParameters,
                        callContext,
                        cancellationToken).ConfigureAwait(false);

                    Validators.ValidateIssuerSecurityKey(validatedToken.SigningKey, validatedToken, validationParameters);
                }
                else
                {
                    if (validationParameters.ValidateSignatureLast)
                    {
                        tokenValidationResult = await ValidateTokenPayloadAsync(
                            jsonWebToken,
                            validationParameters,
                            callContext,
                            cancellationToken).ConfigureAwait(false);

                        if (tokenValidationResult.IsValid)
                            tokenValidationResult.SecurityToken = ValidateSignatureAndIssuerSecurityKey(jsonWebToken, validationParameters, currentConfiguration);
                    }
                    else
                    {
                        var validatedToken = ValidateSignatureAndIssuerSecurityKey(jsonWebToken, validationParameters, currentConfiguration);
                        tokenValidationResult = await ValidateTokenPayloadAsync(
                            validatedToken,
                            validationParameters,
                            callContext,
                            cancellationToken).ConfigureAwait(false);
                    }
                }

                return tokenValidationResult;
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new TokenValidationResult
                {
                    Exception = ex,
                    IsValid = false,
                    TokenOnFailedValidation = validationParameters.IncludeTokenOnFailedValidation ? jsonWebToken : null
                };
            }
        }

        /// <summary>
        ///  Internal method for token validation, responsible for:
        ///  (1) Obtaining a configuration from the <see cref="TokenValidationParameters.ConfigurationManager"/>.
        ///  (2) Revalidating using the Last Known Good Configuration (if present), and obtaining a refreshed configuration (if necessary) and revalidating using it.
        /// </summary>
        /// <param name="jsonWebToken">The JWT token.</param>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
        /// <returns></returns>
        internal async ValueTask<TokenValidationResult> ValidateTokenAsync(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters)
        {
            BaseConfiguration currentConfiguration = null;
            if (validationParameters.ConfigurationManager != null)
            {
                try
                {
                    currentConfiguration = await validationParameters.ConfigurationManager.GetBaseConfigurationAsync(CancellationToken.None).ConfigureAwait(false);
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
                {
                    // The exception is not re-thrown as the TokenValidationParameters may have the issuer and signing key set
                    // directly on them, allowing the library to continue with token validation.
                    if (LogHelper.IsEnabled(EventLogLevel.Warning))
                        LogHelper.LogWarning(LogHelper.FormatInvariant(TokenLogMessages.IDX10261, validationParameters.ConfigurationManager.MetadataAddress, ex.ToString()));
                }
            }

            TokenValidationResult tokenValidationResult =  jsonWebToken.IsEncrypted ?
                await ValidateJWEAsync(jsonWebToken, validationParameters, currentConfiguration).ConfigureAwait(false) :
                await ValidateJWSAsync(jsonWebToken, validationParameters, currentConfiguration).ConfigureAwait(false);

            if (validationParameters.ConfigurationManager != null)
            {
                if (tokenValidationResult.IsValid)
                {
                    // Set current configuration as LKG if it exists.
                    if (currentConfiguration != null)
                        validationParameters.ConfigurationManager.LastKnownGoodConfiguration = currentConfiguration;

                    return tokenValidationResult;
                }
                else if (TokenUtilities.IsRecoverableException(tokenValidationResult.Exception))
                {
                    // If we were still unable to validate, attempt to refresh the configuration and validate using it
                    // but ONLY if the currentConfiguration is not null. We want to avoid refreshing the configuration on
                    // retrieval error as this case should have already been hit before. This refresh handles the case
                    // where a new valid configuration was somehow published during validation time.
                    if (currentConfiguration != null)
                    {
                        validationParameters.ConfigurationManager.RequestRefresh();
                        validationParameters.RefreshBeforeValidation = true;
                        var lastConfig = currentConfiguration;
                        currentConfiguration = await validationParameters.ConfigurationManager.GetBaseConfigurationAsync(CancellationToken.None).ConfigureAwait(false);

                        // Only try to re-validate using the newly obtained config if it doesn't reference equal the previously used configuration.
                        if (lastConfig != currentConfiguration)
                        {
                            tokenValidationResult = jsonWebToken.IsEncrypted ?
                                await ValidateJWEAsync(jsonWebToken, validationParameters, currentConfiguration).ConfigureAwait(false) :
                                await ValidateJWSAsync(jsonWebToken, validationParameters, currentConfiguration).ConfigureAwait(false);

                            if (tokenValidationResult.IsValid)
                            {
                                validationParameters.ConfigurationManager.LastKnownGoodConfiguration = currentConfiguration;
                                return tokenValidationResult;
                            }
                        }
                    }

                    if (validationParameters.ConfigurationManager.UseLastKnownGoodConfiguration)
                    {
                        validationParameters.RefreshBeforeValidation = false;
                        validationParameters.ValidateWithLKG = true;
                        var recoverableException = tokenValidationResult.Exception;

                        foreach (BaseConfiguration lkgConfiguration in validationParameters.ConfigurationManager.GetValidLkgConfigurations())
                        {
                            if (!lkgConfiguration.Equals(currentConfiguration) && TokenUtilities.IsRecoverableConfiguration(jsonWebToken.Kid, currentConfiguration, lkgConfiguration, recoverableException))
                            {
                                tokenValidationResult = jsonWebToken.IsEncrypted ?
                                    await ValidateJWEAsync(jsonWebToken, validationParameters, lkgConfiguration).ConfigureAwait(false) :
                                    await ValidateJWSAsync(jsonWebToken, validationParameters, lkgConfiguration).ConfigureAwait(false);

                                if (tokenValidationResult.IsValid)
                                    return tokenValidationResult;
                            }
                        }
                    }
                }
            }

            return tokenValidationResult;
        }

        internal async ValueTask<TokenValidationResult> ValidateTokenPayloadAsync(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            var expires = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Exp) ? (DateTime?)jsonWebToken.ValidTo : null;
            var notBefore = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Nbf) ? (DateTime?)jsonWebToken.ValidFrom : null;

            // TODO: use validationParameters.AudienceValidatorDelegate and validationParameters.AudienceValidatorDelegate
            //Validators.ValidateLifetime(notBefore, expires, jsonWebToken, validationParameters);
            //Validators.ValidateAudience(jsonWebToken.Audiences, jsonWebToken, validationParameters);

            IssuerValidationResult issuerValidationResult = await validationParameters.IssuerValidatorAsync(
                jsonWebToken,
                validationParameters,
                callContext,
                cancellationToken).ConfigureAwait(false);

            if (!issuerValidationResult.IsValid)
            {
                return new TokenValidationResult(jsonWebToken, this, validationParameters, issuerValidationResult.Issuer)
                {
                    IsValid = false,
                    Exception = issuerValidationResult.Exception
                };
            }

            //Validators.ValidateTokenReplay(expires, jsonWebToken.EncodedToken, validationParameters);
            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jsonWebToken.Actor))
            {
                // Infinite recursion should not occur here, as the JsonWebToken passed into this method is (1) constructed from a string
                // AND (2) the signature is successfully validated on it. (1) implies that even if there are nested actor tokens,
                // they must end at some point since they cannot reference one another. (2) means that the token has a valid signature
                // and (since issuer validation occurs first) came from a trusted authority.
                // NOTE: More than one nested actor token should not be considered a valid token, but if we somehow encounter one,
                // this code will still work properly.
                TokenValidationResult tokenValidationResult =
                    await ValidateTokenAsync(jsonWebToken.Actor, validationParameters.ActorValidationParameters ?? validationParameters).ConfigureAwait(false);

                if (!tokenValidationResult.IsValid)
                    return tokenValidationResult;
            }

            string tokenType = Validators.ValidateTokenType(jsonWebToken.Typ, jsonWebToken, validationParameters);
            return new TokenValidationResult(jsonWebToken, this, validationParameters.Clone(), issuerValidationResult.Issuer)
            {
                IsValid = true,
                TokenType = tokenType
            };
        }
    }
}
