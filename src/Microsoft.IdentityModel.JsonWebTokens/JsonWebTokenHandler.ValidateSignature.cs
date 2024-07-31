// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens.Results;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens
{
#nullable enable
    /// <remarks>This partial class contains methods and logic related to the validation of tokens' signatures.</remarks>
    public partial class JsonWebTokenHandler : TokenHandler
    {
        /// <summary>
        /// Validates the JWT signature.
        /// </summary>
        /// <param name="jwtToken">The JWT token to validate.</param>
        /// <param name="validationParameters">The parameters used for validation.</param>
        /// <param name="configuration">The optional configuration used for validation.</param>
        /// <param name="callContext">The context in which the method is called.</param>
        /// <exception cref="ArgumentNullException">Returned if <paramref name="jwtToken"/> or <paramref name="validationParameters"/> is null.</exception>"
        /// <exception cref="SecurityTokenInvalidSignatureException">Returned by the default implementation if the token is not signed, or if the validation fails.</exception>
        /// <exception cref="SecurityTokenInvalidAlgorithmException">Returned if the algorithm is not supported by the key.</exception>
        /// <exception cref="SecurityTokenSignatureKeyNotFoundException">Returned if the key cannot be resolved.</exception>
        internal static SignatureValidationResult ValidateSignature(
            JsonWebToken jwtToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            if (jwtToken is null)
                return SignatureValidationResult.NullParameterFailure(nameof(jwtToken));

            if (validationParameters is null)
                return SignatureValidationResult.NullParameterFailure(nameof(validationParameters));

            // Delegate is set by the user, we call it and return the result.
            if (validationParameters.SignatureValidator is not null)
                return validationParameters.SignatureValidator(jwtToken, validationParameters, configuration, callContext);

            // If the user wants to accept unsigned tokens, they must implement the delegate.
            if (!jwtToken.IsSigned)
                return new SignatureValidationResult(
                    ValidationFailureType.SignatureValidationFailed,
                    new ExceptionDetail(
                        new MessageDetail(
                            TokenLogMessages.IDX10504,
                            LogHelper.MarkAsSecurityArtifact(
                                jwtToken.EncodedToken,
                                JwtTokenUtilities.SafeLogJwtToken)
                            ),
                        typeof(SecurityTokenInvalidSignatureException),
                        new StackFrame()));

            SecurityKey? key = null;
            if (validationParameters.IssuerSigningKeyResolver is not null)
            {
                key = validationParameters.IssuerSigningKeyResolver(
                    jwtToken.EncodedToken,
                    jwtToken,
                    jwtToken.Kid,
                    validationParameters,
                    configuration,
                    callContext);
            }
            else
            {
                // Resolve the key using the token's 'kid' and 'x5t' headers.
                // Fall back to the validation parameters' keys if configuration keys are not set.
                key = JwtTokenUtilities.ResolveTokenSigningKey(jwtToken.Kid, jwtToken.X5t, configuration?.SigningKeys)
                    ?? JwtTokenUtilities.ResolveTokenSigningKey(jwtToken.Kid, jwtToken.X5t, validationParameters.IssuerSigningKeys);
            }

            if (key is not null)
            {
                jwtToken.SigningKey = key;

                // If the key is found, validate the signature.
                return ValidateSignatureWithKey(jwtToken, key, validationParameters, callContext);
            }

            // Key could not be resolved. Depending on the configuration, try all keys or return an error.
            if (validationParameters.TryAllIssuerSigningKeys)
                return ValidateSignatureUsingAllKeys(jwtToken, validationParameters, configuration, callContext);
            else
                return new SignatureValidationResult(
                    ValidationFailureType.SignatureValidationFailed,
                    new ExceptionDetail(
                        new MessageDetail(TokenLogMessages.IDX10500),
                        typeof(SecurityTokenSignatureKeyNotFoundException),
                        new StackFrame()));
        }

        private static SignatureValidationResult ValidateSignatureUsingAllKeys(
            JsonWebToken jwtToken,
            ValidationParameters
            validationParameters, BaseConfiguration? configuration,
            CallContext callContext)
        {
            // control gets here if:
            // 1. User specified delegate: IssuerSigningKeyResolver returned null
            // 2. ResolveIssuerSigningKey returned null
            // Try all the keys. This is the degenerate case, not concerned about perf.
            ICollection<SecurityKey> keys = configuration?.SigningKeys ?? new List<SecurityKey>();
            if (!(keys is List<SecurityKey> keysList))
                keysList = keys.ToList();

            if (!validationParameters.IssuerSigningKeys.IsNullOrEmpty())
                keysList.AddRange(validationParameters.IssuerSigningKeys);

            // keep track of exceptions thrown, keys that were tried
            StringBuilder? exceptionStrings = null;
            StringBuilder? keysAttempted = null;
            var kidExists = !string.IsNullOrEmpty(jwtToken.Kid);
            var kidMatched = false;

            for (int i = 0; i < keysList.Count; i++)
            {
                SecurityKey key = keysList[i];
                SignatureValidationResult result = ValidateSignatureWithKey(
                    jwtToken,
                    key,
                    validationParameters,
                    callContext);

                if (result.IsValid)
                {
                    if (LogHelper.IsEnabled(EventLogLevel.Informational))
                        LogHelper.LogInformation(TokenLogMessages.IDX10242, jwtToken);

                    jwtToken.SigningKey = key;
                    return result; // return the first valid signature.
                }
                else
                    (exceptionStrings ??= new StringBuilder()).AppendLine(result.ExceptionDetail?.MessageDetail.Message ?? "Null");

                if (key != null)
                {
                    (keysAttempted ??= new StringBuilder()).Append(key.ToString()).Append(" , KeyId: ").AppendLine(key.KeyId);
                    if (kidExists && !kidMatched && key.KeyId != null)
                        kidMatched = jwtToken.Kid.Equals(key.KeyId, key is X509SecurityKey ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
                }
            }

            // No valid signature found. Return the exception details.
            return new SignatureValidationResult(
                ValidationFailureType.SignatureValidationFailed,
                GetSignatureValidationFailureExceptionDetails(
                    jwtToken,
                    validationParameters,
                    configuration,
                    exceptionStrings,
                    keysAttempted,
                    kidExists,
                    kidMatched));
        }

        private static SignatureValidationResult ValidateSignatureWithKey(
            JsonWebToken jsonWebToken,
            SecurityKey key,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            var cryptoProviderFactory = validationParameters.CryptoProviderFactory ?? key.CryptoProviderFactory;
            if (!cryptoProviderFactory.IsSupportedAlgorithm(jsonWebToken.Alg, key))
            {
                return new SignatureValidationResult(
                    ValidationFailureType.SignatureValidationFailed,
                    new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX14000,
                            LogHelper.MarkAsNonPII(jsonWebToken.Alg),
                            key),
                        typeof(SecurityTokenInvalidAlgorithmException),
                        new StackFrame()));
            }

            AlgorithmValidationResult result = validationParameters.AlgorithmValidator(
                jsonWebToken.Alg,
                key,
                jsonWebToken,
                validationParameters,
                callContext);
            if (!result.IsValid)
                return new SignatureValidationResult(
                    ValidationFailureType.SignatureValidationFailed,
                    result.ExceptionDetail);

            var signatureProvider = cryptoProviderFactory.CreateForVerifying(key, jsonWebToken.Alg);
            try
            {
                if (signatureProvider == null)
                    return new SignatureValidationResult(
                        ValidationFailureType.SignatureValidationFailed,
                        new ExceptionDetail(
                            new MessageDetail(TokenLogMessages.IDX10636,
                                key?.ToString() ?? "Null",
                                LogHelper.MarkAsNonPII(jsonWebToken.Alg)),
                            typeof(InvalidOperationException),
                            new StackFrame()));

                bool valid = EncodingUtils.PerformEncodingDependentOperation<bool, string, int, SignatureProvider>(
                    jsonWebToken.EncodedToken,
                    0,
                    jsonWebToken.Dot2,
                    Encoding.UTF8,
                    jsonWebToken.EncodedToken,
                    jsonWebToken.Dot2,
                    signatureProvider,
                    ValidateSignature);

                if (valid)
                    return new SignatureValidationResult();
                else
                    return new SignatureValidationResult(
                        ValidationFailureType.SignatureValidationFailed,
                        new ExceptionDetail(
                            new MessageDetail(TokenLogMessages.IDX10504),
                            typeof(SecurityTokenInvalidSignatureException),
                            new StackFrame()));
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new SignatureValidationResult(
                    ValidationFailureType.SignatureValidationFailed,
                    new ExceptionDetail(
                        new MessageDetail(TokenLogMessages.IDX10504, ex.ToString()),
                        ex.GetType(),
                        new StackFrame(),
                        ex));
            }
            finally
            {
                cryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

        private static ExceptionDetail GetSignatureValidationFailureExceptionDetails(
            JsonWebToken jwtToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            StringBuilder? exceptionStrings,
            StringBuilder? keysAttempted,
            bool kidExists,
            bool kidMatched)
        {
            // Get information on where keys used during token validation came from for debugging purposes.
            var keysInTokenValidationParameters = validationParameters.IssuerSigningKeys;
            var keysInConfiguration = configuration?.SigningKeys;
            var numKeysInTokenValidationParameters = keysInTokenValidationParameters.Count;
            var numKeysInConfiguration = keysInConfiguration?.Count ?? 0;

            if (kidExists && kidMatched)
            {
                JsonWebToken localJwtToken = jwtToken; // avoid closure on non-exceptional path
                var isKidInTVP = keysInTokenValidationParameters.Any(x => x.KeyId.Equals(localJwtToken.Kid));
                var keyLocation = isKidInTVP ? "TokenValidationParameters" : "Configuration";
                return new ExceptionDetail(
                    new MessageDetail(
                        TokenLogMessages.IDX10511,
                        LogHelper.MarkAsNonPII(keysAttempted?.ToString() ?? ""),
                        LogHelper.MarkAsNonPII(numKeysInTokenValidationParameters),
                        LogHelper.MarkAsNonPII(numKeysInConfiguration),
                        LogHelper.MarkAsNonPII(keyLocation),
                        LogHelper.MarkAsNonPII(jwtToken.Kid),
                        exceptionStrings?.ToString() ?? "",
                        LogHelper.MarkAsSecurityArtifact(jwtToken.EncodedToken, JwtTokenUtilities.SafeLogJwtToken)),
                    typeof(SecurityTokenSignatureKeyNotFoundException),
                    new StackFrame());
            }

            if (keysAttempted is null)
                return new ExceptionDetail(
                    new MessageDetail(
                        TokenLogMessages.IDX10500), // No keys found.
                    typeof(SecurityTokenSignatureKeyNotFoundException),
                    new StackFrame());

            if (kidExists)
                return new ExceptionDetail(
                    new MessageDetail(
                        TokenLogMessages.IDX10503, // No match for kid found among the keys provided.
                        LogHelper.MarkAsNonPII(jwtToken.Kid),
                        LogHelper.MarkAsNonPII(keysAttempted?.ToString() ?? ""),
                        LogHelper.MarkAsNonPII(numKeysInTokenValidationParameters),
                        LogHelper.MarkAsNonPII(numKeysInConfiguration),
                        exceptionStrings?.ToString() ?? "",
                        LogHelper.MarkAsSecurityArtifact(jwtToken.EncodedToken, JwtTokenUtilities.SafeLogJwtToken)),
                    typeof(SecurityTokenSignatureKeyNotFoundException),
                    new StackFrame());

            return new ExceptionDetail(
                new MessageDetail(
                    TokenLogMessages.IDX10517, // Kid is missing and no keys match.
                    LogHelper.MarkAsNonPII(keysAttempted?.ToString() ?? ""),
                    LogHelper.MarkAsNonPII(numKeysInTokenValidationParameters),
                    LogHelper.MarkAsNonPII(numKeysInConfiguration),
                    exceptionStrings?.ToString() ?? "",
                    LogHelper.MarkAsSecurityArtifact(jwtToken.EncodedToken, JwtTokenUtilities.SafeLogJwtToken)),
                typeof(SecurityTokenSignatureKeyNotFoundException),
                new StackFrame());
        }
    }
#nullable restore
}
