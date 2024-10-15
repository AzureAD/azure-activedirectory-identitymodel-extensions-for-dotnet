﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

#nullable enable
namespace Microsoft.IdentityModel.JsonWebTokens
{
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
        internal static ValidationResult<TokenValidationUnit> ValidateSignature(
            JsonWebToken jwtToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            if (jwtToken is null)
                return ValidationError.NullParameter(
                    nameof(jwtToken),
                    new StackFrame(true));

            if (validationParameters is null)
                return ValidationError.NullParameter(
                    nameof(validationParameters),
                    new StackFrame(true));

            // Delegate is set by the user, we call it and return the result.
            if (validationParameters.SignatureValidator is not null)
                return validationParameters.SignatureValidator(jwtToken, validationParameters, configuration, callContext);

            // If the user wants to accept unsigned tokens, they must implement the delegate.
            if (!jwtToken.IsSigned)
                return new ValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10504,
                        LogHelper.MarkAsSecurityArtifact(
                            jwtToken.EncodedToken,
                            JwtTokenUtilities.SafeLogJwtToken)),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenInvalidSignatureException),
                    new StackFrame(true));

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
            {
                if (!string.IsNullOrEmpty(jwtToken.Kid))
                {
                    StackFrame kidNotMatchedNoTryAllStackFrame = StackFrames.KidNotMatchedNoTryAll ??= new StackFrame(true);
                    return new ValidationError(
                        new MessageDetail(
                            TokenLogMessages.IDX10502,
                            LogHelper.MarkAsNonPII(jwtToken.Kid),
                            LogHelper.MarkAsNonPII(validationParameters.IssuerSigningKeys.Count),
                            LogHelper.MarkAsNonPII(configuration?.SigningKeys.Count ?? 0),
                            LogHelper.MarkAsSecurityArtifact(jwtToken.EncodedToken, JwtTokenUtilities.SafeLogJwtToken)),
                        ValidationFailureType.SignatureValidationFailed,
                        typeof(SecurityTokenSignatureKeyNotFoundException),
                        kidNotMatchedNoTryAllStackFrame);
                }

                StackFrame noKeysProvidedStackFrame = StackFrames.NoKeysProvided ??= new StackFrame(true);
                return new ValidationError(
                    new MessageDetail(TokenLogMessages.IDX10500),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenSignatureKeyNotFoundException),
                    noKeysProvidedStackFrame);
            }
        }

        private static ValidationResult<TokenValidationUnit> ValidateSignatureUsingAllKeys(
            JsonWebToken jwtToken,
            ValidationParameters
            validationParameters, BaseConfiguration? configuration,
            CallContext callContext)
        {
            // control gets here if:
            // 1. User specified delegate: IssuerSigningKeyResolver returned null
            // 2. ResolveIssuerSigningKey returned null
            // Try all the keys. This is the degenerate case, not concerned about perf.
            (ValidationResult<TokenValidationUnit>? configResult, bool configKidMatched, KeyMatchFailedResult? configFailedResult) = ValidateUsingKeys(
                jwtToken,
                validationParameters,
                configuration?.SigningKeys,
                callContext);

            if (configResult is ValidationResult<TokenValidationUnit> unwrappedConfigResult)
                return unwrappedConfigResult;

            (ValidationResult<TokenValidationUnit>? vpResult, bool vpKidMatched, KeyMatchFailedResult? vpFailedResult) = ValidateUsingKeys(
                jwtToken,
                validationParameters,
                validationParameters.IssuerSigningKeys,
                callContext);

            if (vpResult is ValidationResult<TokenValidationUnit> unwrappedVpResult)
                return unwrappedVpResult;

            if (vpFailedResult is null && configFailedResult is null) // No keys were attempted
                return new ValidationError(
                    new MessageDetail(TokenLogMessages.IDX10500),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenSignatureKeyNotFoundException),
                    new StackFrame(true));

            StringBuilder exceptionStrings = new();
            StringBuilder keysAttempted = new();

            PopulateFailedResults(configFailedResult, exceptionStrings, keysAttempted);
            PopulateFailedResults(vpFailedResult, exceptionStrings, keysAttempted);

            bool kidExists = !string.IsNullOrEmpty(jwtToken.Kid);
            bool kidMatched = configKidMatched || vpKidMatched;

            // No valid signature found. Return the validation error.
            return GetSignatureValidationError(
                jwtToken,
                validationParameters,
                configuration,
                exceptionStrings,
                keysAttempted,
                kidExists,
                kidMatched);
        }

        private static (ValidationResult<TokenValidationUnit>? validResult, bool KidMatched, KeyMatchFailedResult? failedResult) ValidateUsingKeys(
            JsonWebToken jwtToken,
            ValidationParameters validationParameters,
            ICollection<SecurityKey>? keys,
            CallContext callContext)
        {
            if (keys is null || keys.Count == 0)
                return (null, false, null);

            if (keys is not IList<SecurityKey> keysList)
                keysList = keys.ToList();

            bool kidExists = !string.IsNullOrEmpty(jwtToken.Kid);
            bool kidMatched = false;
            IList<SecurityKey>? keysAttempted = null;
            IList<ValidationError>? errors = null;

            for (int i = 0; i < keysList.Count; i++)
            {
                SecurityKey key = keysList[i];
                ValidationResult<TokenValidationUnit> result = ValidateSignatureWithKey(jwtToken, key, validationParameters, callContext);
                if (result.IsSuccess)
                {
                    jwtToken.SigningKey = key;
                    return (result, true, null);
                }

                keysAttempted ??= [];
                errors ??= [];

                errors.Add(result.UnwrapError());
                keysAttempted.Add(key);

                if (kidExists && !kidMatched && key.KeyId is not null)
                    kidMatched = jwtToken.Kid.Equals(key.KeyId, key is X509SecurityKey ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
            }

            if (errors is not null && errors.Count > 0 && keysAttempted is not null && keysAttempted.Count > 0)
                return (null, kidMatched, new KeyMatchFailedResult(errors, keysAttempted));

            // No keys were attempted.
            return (null, kidMatched, null);
        }

        private static ValidationResult<TokenValidationUnit> ValidateSignatureWithKey(
            JsonWebToken jsonWebToken,
            SecurityKey key,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            CryptoProviderFactory cryptoProviderFactory = validationParameters.CryptoProviderFactory ?? key.CryptoProviderFactory;
            if (!cryptoProviderFactory.IsSupportedAlgorithm(jsonWebToken.Alg, key))
            {
                return new ValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10400,
                        LogHelper.MarkAsNonPII(jsonWebToken.Alg),
                        key),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenInvalidAlgorithmException),
                    new StackFrame(true));
            }

            ValidationResult<string> result = validationParameters.AlgorithmValidator(
                jsonWebToken.Alg,
                key,
                jsonWebToken,
                validationParameters,
                callContext);

            if (!result.IsSuccess)
                return new ValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10518,
                        result.UnwrapError().MessageDetail.Message),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenInvalidSignatureException),
                    new StackFrame(true),
                    result.UnwrapError());

            SignatureProvider signatureProvider = cryptoProviderFactory.CreateForVerifying(key, jsonWebToken.Alg);
            try
            {
                if (signatureProvider == null)
                    return new ValidationError(
                        new MessageDetail(
                            TokenLogMessages.IDX10636,
                            key?.ToString() ?? "Null",
                            LogHelper.MarkAsNonPII(jsonWebToken.Alg)),
                        ValidationFailureType.SignatureValidationFailed,
                        typeof(InvalidOperationException),
                        new StackFrame(true));

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
                    return TokenValidationUnit.Default;
                else
                    return new ValidationError(
                        new MessageDetail(
                            TokenLogMessages.IDX10504,
                            LogHelper.MarkAsSecurityArtifact(
                                jsonWebToken.EncodedToken,
                                JwtTokenUtilities.SafeLogJwtToken)),
                        ValidationFailureType.SignatureValidationFailed,
                        typeof(SecurityTokenInvalidSignatureException),
                        new StackFrame(true));
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new ValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10504,
                        LogHelper.MarkAsSecurityArtifact(
                            jsonWebToken.EncodedToken,
                            JwtTokenUtilities.SafeLogJwtToken)),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenInvalidSignatureException),
                    new StackFrame(true),
                    ex);
            }
            finally
            {
                cryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

        private static ValidationError GetSignatureValidationError(
            JsonWebToken jwtToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            StringBuilder exceptionStrings,
            StringBuilder keysAttempted,
            bool kidExists,
            bool kidMatched)
        {
            // Get information on where keys used during token validation came from for debugging purposes.
            IList<SecurityKey> keysInTokenValidationParameters = validationParameters.IssuerSigningKeys;
            ICollection<SecurityKey>? keysInConfiguration = configuration?.SigningKeys;
            int numKeysInTokenValidationParameters = keysInTokenValidationParameters.Count;
            int numKeysInConfiguration = keysInConfiguration?.Count ?? 0;

            if (kidExists && kidMatched)
            {
                JsonWebToken localJwtToken = jwtToken; // avoid closure on non-exceptional path
                bool isKidInTVP = keysInTokenValidationParameters.Any(x => x.KeyId.Equals(localJwtToken.Kid));
                string keyLocation = isKidInTVP ? "TokenValidationParameters" : "Configuration";
                return new ValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10511,
                        LogHelper.MarkAsNonPII(keysAttempted.ToString()),
                        LogHelper.MarkAsNonPII(numKeysInTokenValidationParameters),
                        LogHelper.MarkAsNonPII(numKeysInConfiguration),
                        LogHelper.MarkAsNonPII(keyLocation),
                        LogHelper.MarkAsNonPII(jwtToken.Kid),
                        exceptionStrings.ToString(),
                        LogHelper.MarkAsSecurityArtifact(jwtToken.EncodedToken, JwtTokenUtilities.SafeLogJwtToken)),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenSignatureKeyNotFoundException),
                    new StackFrame(true));
            }

            if (kidExists)
                return new ValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10503,
                        LogHelper.MarkAsNonPII(jwtToken.Kid),
                        LogHelper.MarkAsNonPII(keysAttempted.ToString()),
                        LogHelper.MarkAsNonPII(numKeysInTokenValidationParameters),
                        LogHelper.MarkAsNonPII(numKeysInConfiguration),
                        exceptionStrings.ToString(),
                        LogHelper.MarkAsSecurityArtifact(jwtToken.EncodedToken, JwtTokenUtilities.SafeLogJwtToken)),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenSignatureKeyNotFoundException),
                    new StackFrame(true));

            return new ValidationError(
                new MessageDetail(
                    TokenLogMessages.IDX10517, // Kid is missing and no keys match.
                    LogHelper.MarkAsNonPII(keysAttempted.ToString()),
                    LogHelper.MarkAsNonPII(numKeysInTokenValidationParameters),
                    LogHelper.MarkAsNonPII(numKeysInConfiguration),
                    exceptionStrings.ToString(),
                    LogHelper.MarkAsSecurityArtifact(jwtToken.EncodedToken, JwtTokenUtilities.SafeLogJwtToken)),
                ValidationFailureType.SignatureValidationFailed,
                typeof(SecurityTokenSignatureKeyNotFoundException),
                new StackFrame(true));
        }

        private static void PopulateFailedResults(
            KeyMatchFailedResult? failedResult,
            StringBuilder exceptionStrings,
            StringBuilder keysAttempted)
        {
            if (failedResult is KeyMatchFailedResult result)
            {
                for (int i = 0; i < result.KeysAttempted.Count; i++)
                {
                    exceptionStrings.AppendLine(result.FailedResults[i].MessageDetail.Message);
                    keysAttempted.AppendLine(result.KeysAttempted[i].ToString());
                }
            }
        }

        private struct KeyMatchFailedResult(
            IList<ValidationError> failedResults,
            IList<SecurityKey> keysAttempted)
        {
            public IList<ValidationError> FailedResults = failedResults;
            public IList<SecurityKey> KeysAttempted = keysAttempted;
        }
    }
}
#nullable restore
