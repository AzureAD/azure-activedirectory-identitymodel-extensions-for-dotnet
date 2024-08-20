﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens
{
#nullable enable
    public partial class JsonWebTokenHandler : TokenHandler
    {
        /// <summary>
        /// Decrypts a JWE and returns the clear text.
        /// </summary>
        /// <param name="jwtToken">The JWE that contains the cypher text.</param>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
        /// <param name="configuration">The <see cref="BaseConfiguration"/> to be used for validating the token.</param>
        /// <param name="callContext"></param>
        /// <returns>The decoded / cleartext contents of the JWE.</returns>
        internal Result<string, ITokenValidationError> DecryptToken(
            JsonWebToken jwtToken,
            ValidationParameters validationParameters,
            BaseConfiguration configuration,
            CallContext? callContext)
        {
            if (jwtToken == null)
                return new(TokenValidationErrorCommon.NullParameter(nameof(jwtToken), 0x123123));

            if (validationParameters == null)
                return new(TokenValidationErrorCommon.NullParameter(nameof(validationParameters), 0x123124));

            if (string.IsNullOrEmpty(jwtToken.Enc))
                return new(new TokenValidationError(
                    ValidationErrorType.SecurityTokenDecryptionFailed,
                    new MessageDetail(TokenLogMessages.IDX10612),
                    Tag: 0x123125,
                    null));

            var keysOrExceptionDetail = GetContentEncryptionKeys(jwtToken, validationParameters, configuration, callContext);
            if (keysOrExceptionDetail.Item2 != null) // TokenValidationError returned
                return new(keysOrExceptionDetail.Item2);

            var keys = keysOrExceptionDetail.Item1;
            if (keys == null)
                return new(new TokenValidationError(
                    ValidationErrorType.SecurityTokenKeyWrap,
                    new MessageDetail(
                        TokenLogMessages.IDX10609,
                        LogHelper.MarkAsSecurityArtifact(jwtToken, JwtTokenUtilities.SafeLogJwtToken)),
                    Tag: 0x123126,
                    null));

            return JwtTokenUtilities.DecryptJwtToken(
                jwtToken,
                validationParameters,
                new JwtTokenDecryptionParameters
                {
                    DecompressionFunction = JwtTokenUtilities.DecompressToken,
                    Keys = keys,
                    MaximumDeflateSize = MaximumTokenSizeInBytes
                },
                callContext);
        }

        internal (IList<SecurityKey>?, TokenValidationError?) GetContentEncryptionKeys(JsonWebToken jwtToken, ValidationParameters validationParameters, BaseConfiguration configuration, CallContext? callContext)
        {
            IList<SecurityKey>? keys = null;

            // First we check to see if the caller has set a custom decryption resolver on VP for the call, if so any keys set on VP and keys in Configuration are ignored.
            // If no custom decryption resolver is set, we'll check to see if they've set some static decryption keys on VP. If a key is found, we ignore configuration.
            // If no key found in VP, we'll check the configuration.
            if (validationParameters.TokenDecryptionKeyResolver != null)
            {
                keys = validationParameters.TokenDecryptionKeyResolver(jwtToken.EncodedToken, jwtToken, jwtToken.Kid, validationParameters, callContext);
            }
            else
            {
                var key = ResolveTokenDecryptionKey(jwtToken.EncodedToken, jwtToken, validationParameters, callContext);
                if (key != null)
                {
                    // TODO: Move to CallContext
                    //if (LogHelper.IsEnabled(EventLogLevel.Informational))
                    //    LogHelper.LogInformation(TokenLogMessages.IDX10904, key);
                }
                else if (configuration != null)
                {
                    key = ResolveTokenDecryptionKeyFromConfig(jwtToken, configuration);
                    // TODO: Move to CallContext
                    //if (key != null && LogHelper.IsEnabled(EventLogLevel.Informational))
                    //    LogHelper.LogInformation(TokenLogMessages.IDX10905, key);
                }

                if (key != null)
                    keys = [key];
            }

            // on decryption for ECDH-ES, we get the public key from the EPK value see: https://datatracker.ietf.org/doc/html/rfc7518#appendix-C
            // we need the ECDSASecurityKey for the receiver, use TokenValidationParameters.TokenDecryptionKey

            // control gets here if:
            // 1. User specified delegate: TokenDecryptionKeyResolver returned null
            // 2. ResolveTokenDecryptionKey returned null
            // 3. ResolveTokenDecryptionKeyFromConfig returned null
            // Try all the keys. This is the degenerate case, not concerned about perf.
            if (keys == null)
            {
                keys = validationParameters.TokenDecryptionKeys;
                if (configuration != null)
                {
                    if (configuration.TokenDecryptionKeys is not List<SecurityKey> configurationKeys)
                        configurationKeys = configuration.TokenDecryptionKeys.ToList();

                    if (keys != null)
                    {
                        if (keys is List<SecurityKey> keysList)
                            keysList.AddRange(configurationKeys);
                        else
                            keys = keys.Concat(configurationKeys).ToList();
                    }
                    else
                        keys = configurationKeys;
                }

            }

            if (jwtToken.Alg.Equals(JwtConstants.DirectKeyUseAlg, StringComparison.Ordinal)
                || jwtToken.Alg.Equals(SecurityAlgorithms.EcdhEs, StringComparison.Ordinal))
                return (keys, null);

            if (keys is null)
                return (keys, null); // Cannot iterate over null.

            var unwrappedKeys = new List<SecurityKey>();
            // keep track of exceptions thrown, keys that were tried
            StringBuilder? exceptionStrings = null;
            StringBuilder? keysAttempted = null;
            for (int i = 0; i < keys.Count; i++)
            {
                var key = keys[i];

                try
                {
#if NET472 || NET6_0_OR_GREATER
                    if (SupportedAlgorithms.EcdsaWrapAlgorithms.Contains(jwtToken.Alg))
                    {
                        // on decryption we get the public key from the EPK value see: https://datatracker.ietf.org/doc/html/rfc7518#appendix-C
                        var ecdhKeyExchangeProvider = new EcdhKeyExchangeProvider(
                            key as ECDsaSecurityKey,
                            validationParameters.EphemeralDecryptionKey as ECDsaSecurityKey,
                            jwtToken.Alg,
                            jwtToken.Enc);
                        jwtToken.TryGetHeaderValue(JwtHeaderParameterNames.Apu, out string apu);
                        jwtToken.TryGetHeaderValue(JwtHeaderParameterNames.Apv, out string apv);
                        SecurityKey kdf = ecdhKeyExchangeProvider.GenerateKdf(apu, apv);
                        var kwp = key.CryptoProviderFactory.CreateKeyWrapProviderForUnwrap(kdf, ecdhKeyExchangeProvider.GetEncryptionAlgorithm());
                        var unwrappedKey = kwp.UnwrapKey(Base64UrlEncoder.DecodeBytes(jwtToken.EncryptedKey));
                        unwrappedKeys.Add(new SymmetricSecurityKey(unwrappedKey));
                    }
                    else
#endif
                    if (key.CryptoProviderFactory.IsSupportedAlgorithm(jwtToken.Alg, key))
                    {
                        var kwp = key.CryptoProviderFactory.CreateKeyWrapProviderForUnwrap(key, jwtToken.Alg);
                        var unwrappedKey = kwp.UnwrapKey(jwtToken.EncryptedKeyBytes);
                        unwrappedKeys.Add(new SymmetricSecurityKey(unwrappedKey));
                    }
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
                {
                    (exceptionStrings ??= new StringBuilder()).AppendLine(ex.ToString());
                }

                (keysAttempted ??= new StringBuilder()).AppendLine(key.ToString());
            }

            if (unwrappedKeys.Count > 0 && exceptionStrings is null)
                return (unwrappedKeys, null);
            else
            {
                TokenValidationError tokenValidationError = new(
                    ValidationErrorType.SecurityTokenKeyWrap,
                    new MessageDetail(
                        TokenLogMessages.IDX10618,
                        keysAttempted?.ToString() ?? "",
                        exceptionStrings?.ToString() ?? "",
                        LogHelper.MarkAsSecurityArtifact(jwtToken, JwtTokenUtilities.SafeLogJwtToken)),
                    Tag: 0x123126,
                    null);

                return (null, tokenValidationError);
            }
        }

        /// <summary>
        /// Returns a <see cref="SecurityKey"/> to use when decrypting a JWE.
        /// </summary>
        /// <param name="token">The <see cref="string"/> the token that is being decrypted.</param>
        /// <param name="jwtToken">The <see cref="JsonWebToken"/> that is being decrypted.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">The call context used for logging.</param>
        /// <returns>A <see cref="SecurityKey"/> to use for signature validation.</returns>
        /// <remarks>If key fails to resolve, then null is returned.</remarks>
        internal virtual SecurityKey? ResolveTokenDecryptionKey(string token, JsonWebToken jwtToken, ValidationParameters validationParameters, CallContext? callContext)
        {
            if (jwtToken == null || validationParameters == null)
                return null;

            if (!string.IsNullOrEmpty(jwtToken.Kid) && validationParameters.TokenDecryptionKeys != null)
            {
                for (int i = 0; i < validationParameters.TokenDecryptionKeys.Count; i++)
                {
                    var key = validationParameters.TokenDecryptionKeys[i];
                    if (key != null && string.Equals(key.KeyId, jwtToken.Kid, GetStringComparisonRuleIf509OrECDsa(key)))
                        return key;
                }
            }

            if (!string.IsNullOrEmpty(jwtToken.X5t) && validationParameters.TokenDecryptionKeys != null)
            {
                for (int i = 0; i < validationParameters.TokenDecryptionKeys.Count; i++)
                {
                    var key = validationParameters.TokenDecryptionKeys[i];

                    if (key != null && string.Equals(key.KeyId, jwtToken.X5t, GetStringComparisonRuleIf509(key)))
                        return key;

                    var x509Key = key as X509SecurityKey;
                    if (x509Key != null && string.Equals(x509Key.X5t, jwtToken.X5t, StringComparison.OrdinalIgnoreCase))
                        return key;
                }
            }

            return null;
        }
#nullable restore
    }
}
