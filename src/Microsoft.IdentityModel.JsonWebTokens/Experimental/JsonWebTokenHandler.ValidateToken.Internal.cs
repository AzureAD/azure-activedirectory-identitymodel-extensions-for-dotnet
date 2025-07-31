// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

#nullable enable
namespace Microsoft.IdentityModel.JsonWebTokens
{
    public partial class JsonWebTokenHandler : TokenHandler, IResultBasedValidation
    {
        private static IDictionary<string, StackFrame> _stackFrames = new Dictionary<string, StackFrame>();

        /// <inheritdoc/>
        internal override async Task<OperationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            // TODO - add support for ReadonlyMemory<char>
            if (string.IsNullOrEmpty(token))
            {
                if (!ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(new StackFrame(0, true));

                return ValidationError.NullParameter(
                    nameof(token),
                    stackFrame!);
            }

            if (validationParameters is null)
            {
                if (!ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(new StackFrame(0, true));

                return ValidationError.NullParameter(
                    nameof(validationParameters),
                    stackFrame!);
            }

            if (token.Length > MaximumTokenSizeInBytes)
            {
                if (!ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(new StackFrame(0, true));

                return new ValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10209,
                        LogHelper.MarkAsNonPII(token.Length),
                        LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes)),
                    ValidationFailureType.TokenExceedsMaximumSize,
                    stackFrame!);
            }

            // TODO - hook into the extensibility for reading tokens.
            OperationResult<SecurityToken, ValidationError> readResult = ReadToken(token, callContext);
            if (!readResult.Succeeded)
            {
                if (!ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(new StackFrame(0, true));

                return readResult.Error!.AddStackFrame(stackFrame!);
            }

            OperationResult<ValidatedToken, ValidationError> validationResult = await ValidateTokenAsync(
                readResult.Result!,
                validationParameters,
                callContext,
                cancellationToken).ConfigureAwait(false);

            if (!validationResult.Succeeded)
            {
                if (!ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(new StackFrame(0, true));

                return validationResult.Error!.AddAsyncStackFrame(stackFrame!);
            }

            return validationResult;
        }

        /// <inheritdoc/>
        internal override async Task<OperationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            if (securityToken is null)
            {
                if (!ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(new StackFrame(0, true));

                return ValidationError.NullParameter(
                    nameof(securityToken),
                    stackFrame!);
            }

            if (validationParameters is null)
            {
                if (!ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(new StackFrame(0, true));

                return ValidationError.NullParameter(
                    nameof(validationParameters),
                    stackFrame!);
            }

            if (securityToken is not JsonWebToken jsonWebToken)
            {
                if (!ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(new StackFrame(0, true));

                return new ValidationError(
                    new MessageDetail(TokenLogMessages.IDX10001, nameof(securityToken), nameof(JsonWebToken)),
                    ValidationFailureType.SecurityTokenNotExpectedType,
                    stackFrame!);
            }

            BaseConfiguration? currentConfiguration =
                await GetCurrentConfigurationAsync(validationParameters, cancellationToken).ConfigureAwait(false);

            OperationResult<ValidatedToken, ValidationError> result = jsonWebToken.IsEncrypted ?
                await ValidateJWEAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false) :
                await ValidateJWSAsync(jsonWebToken, validationParameters, currentConfiguration, callContext, cancellationToken).ConfigureAwait(false);

            if (validationParameters.ConfigurationManager is null)
            {
                if (result.Succeeded)
                    return result;

                if (!ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(new StackFrame(0, true));

                return result.Error!.AddStackFrame(stackFrame!);
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

            if (!ValidationError.TryGetStackFrame(out StackFrame? stackFrameFinal))
                stackFrameFinal = ValidationError.GetAsyncStackFrame(new StackFrame(0, true));

            // If we reach this point, the securityToken validation failed and we should return the error.
            return result.Error!.AddStackFrame(stackFrameFinal!);
        }

        private async ValueTask<OperationResult<ValidatedToken, ValidationError>> ValidateJWEAsync(
            JsonWebToken jwtToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            OperationResult<string, ValidationError> decryptionResult = DecryptToken(
                jwtToken, validationParameters, configuration, callContext);
            if (!decryptionResult.Succeeded)
            {
                return decryptionResult.Error!.AddCurrentStackFrame();
            }

            OperationResult<SecurityToken, ValidationError> readResult = ReadToken(decryptionResult.Result!, callContext);
            if (!readResult.Succeeded)
            {
                return readResult.Error!.AddCurrentStackFrame();
            }

            JsonWebToken decryptedToken = (readResult.Result as JsonWebToken)!;
            OperationResult<ValidatedToken, ValidationError> validationResult =
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

        private async ValueTask<OperationResult<ValidatedToken, ValidationError>> ValidateJWSAsync(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            StackFrame? stackFrame;
            DateTime? expires = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Exp) ? jsonWebToken.ValidTo : null;
            DateTime? notBefore = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Nbf) ? jsonWebToken.ValidFrom : null;

            OperationResult<ValidatedLifetime, ValidationError> lifetimeResult =
                Validators.ValidateLifetimeInternal(
                    notBefore,
                    expires,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!lifetimeResult.Succeeded)
            {
                if (ValidationError.TryGetStackFrame(out stackFrame))
                    return lifetimeResult.Error!.AddStackFrame(stackFrame!);

                return lifetimeResult.Error!.AddAsyncStackFrame(new StackFrame(0, true));
            }

            if (jsonWebToken.Audiences is not IList<string> audiences)
                audiences = [.. jsonWebToken.Audiences];

            OperationResult<string, ValidationError> audienceResult =
                Validators.ValidateAudienceInternal(
                    audiences,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!audienceResult.Succeeded)
            {
                if (ValidationError.TryGetStackFrame(out stackFrame))
                    return audienceResult.Error!.AddStackFrame(stackFrame!);

                return audienceResult.Error!.AddAsyncStackFrame(new StackFrame(0, true));
            }

            OperationResult<ValidatedIssuer, ValidationError> issuerResult =
                await Validators.ValidateIssuerInternalAsync(
                    jsonWebToken.Issuer,
                    jsonWebToken,
                    validationParameters,
                    callContext,
                    cancellationToken).ConfigureAwait(false);

            if (!issuerResult.Succeeded)
            {
                if (ValidationError.TryGetStackFrame(out stackFrame))
                    return issuerResult.Error!.AddStackFrame(stackFrame!);

                return issuerResult.Error!.AddAsyncStackFrame(new StackFrame(0, true));
            }

            OperationResult<DateTime?, ValidationError>? tokenReplayResult =
                Validators.ValidateTokenReplayInternal(
                    expires,
                    jsonWebToken.EncodedToken,
                    validationParameters,
                    callContext);

            if (!tokenReplayResult.Value.Succeeded)
            {
                if (ValidationError.TryGetStackFrame(out stackFrame))
                    return tokenReplayResult.Value.Error!.AddStackFrame(stackFrame!);

                return tokenReplayResult.Value.Error!.AddAsyncStackFrame(new StackFrame(0, true));
            }

            OperationResult<ValidatedTokenType, ValidationError> tokenTypeResult =
                Validators.ValidateTokenTypeInternal(
                    jsonWebToken.Typ,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!tokenTypeResult.Succeeded)
            {
                if (ValidationError.TryGetStackFrame(out stackFrame))
                    return tokenTypeResult.Error!.AddStackFrame(stackFrame!);

                return tokenTypeResult.Error!.AddAsyncStackFrame(new StackFrame(0, true));
            }

            OperationResult<string, ValidationError> algorithmResult =
                Validators.ValidateAlgorithmInternal(
                    jsonWebToken.Alg,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!algorithmResult.Succeeded)
            {
                if (ValidationError.TryGetStackFrame(out stackFrame))
                    return algorithmResult.Error!.AddStackFrame(stackFrame!);

                return algorithmResult.Error!.AddAsyncStackFrame(new StackFrame(0, true));
            }

            // The signature validation delegate is yet to be migrated to ValidationParameters.
            OperationResult<SecurityKey, ValidationError> signatureResult =
                ValidateSignature(
                    jsonWebToken,
                    validationParameters,
                    configuration,
                    callContext);

            if (!signatureResult.Succeeded)
            {
                if (ValidationError.TryGetStackFrame(out stackFrame))
                    return signatureResult.Error!.AddStackFrame(stackFrame!);

                return signatureResult.Error!.AddAsyncStackFrame(new StackFrame(0, true));
            }

            OperationResult<ValidatedSignatureKey, ValidationError> signatureKeyResult =
                Validators.ValidateSignatureKeyInternal(
                    jsonWebToken.SigningKey,
                    jsonWebToken,
                    validationParameters,
                    callContext);

            if (!signatureKeyResult.Succeeded)
            {
                if (ValidationError.TryGetStackFrame(out stackFrame))
                    return signatureKeyResult.Error!.AddStackFrame(stackFrame!);

                return signatureKeyResult.Error!.AddAsyncStackFrame(new StackFrame(0, true));
            }

            // actor validation
            OperationResult<ValidatedToken, ValidationError>? actorResult = null;
            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jsonWebToken.Actor))
            {
                OperationResult<SecurityToken, ValidationError> readResult = ReadToken(jsonWebToken.Actor, callContext);
                if (!readResult.Succeeded)
                    return readResult.Error!.AddCurrentStackFrame();

                if (validationParameters.ActorValidationParameters is null)
                    return ValidationError.NullParameter(
                        nameof(validationParameters.ActorValidationParameters),
                        ValidationError.GetCurrentStackFrame());

                JsonWebToken actorToken = (readResult.Result as JsonWebToken)!;
                actorResult = await ValidateTokenAsync(
                    actorToken,
                    validationParameters.ActorValidationParameters,
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
                    // and signing key set directly on them, allowing the library to continue with securityToken validation.
                    // TODO: Move to CallContext.
                    //if (LogHelper.IsEnabled(EventLogLevel.Warning))
                    //    LogHelper.LogWarning(LogHelper.FormatInvariant(TokenLogMessages.IDX10261, validationParameters.ConfigurationManager.MetadataAddress, ex.ToString()));
                }
            }

            return currentConfiguration;
        }

        #region Explicit Interface Implementations
        async Task<OperationResult<ValidatedToken, ValidationError>> IResultBasedValidation.ValidateTokenAsync(
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

        async Task<OperationResult<ValidatedToken, ValidationError>> IResultBasedValidation.ValidateTokenAsync(
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

        async Task<OperationResult<ValidatedToken, ValidationError>> IResultBasedValidation.ValidateTokenAsync(
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

        async Task<OperationResult<ValidatedToken, ValidationError>> IResultBasedValidation.ValidateTokenAsync(
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

        private static StackFrame GetAsyncStackFrame(string key, Exception ex, int nativeOffset, int ilOffset)
        {
            if (_stackFrames.TryGetValue(key, out StackFrame? stackFrame))
                return stackFrame;

            StackTrace stackTrace = new StackTrace(ex, true);
            StackFrame? stackframe = stackTrace.GetFrame(0);
            string? filename = stackframe!.GetFileName();

            CustomStackFrame newStackFrame = new CustomStackFrame(
                ilOffset,
                nativeOffset,
                filename!,
                stackframe!.GetFileLineNumber(),
                stackframe!.GetFileColumnNumber(),
                key);

            _stackFrames[key] = newStackFrame;
            return _stackFrames[key];
        }

        private static bool TryGetAsyncStackFrame(string key, out StackFrame? stackFrame)
        {
            if (_stackFrames.TryGetValue(key, out stackFrame))
                return true;

            stackFrame = null;
            return false;
        }

        private static StackFrame SetAsyncStackFrame(string key, string methodName, StackFrame stackFrame)
        {
            string? filename = stackFrame!.GetFileName();
            CustomStackFrame newStackFrame = new CustomStackFrame(
                stackFrame!.GetILOffset(),
                stackFrame!.GetNativeOffset(),
                filename!,
                stackFrame!.GetFileLineNumber(),
                stackFrame!.GetFileColumnNumber(),
                methodName);

            _stackFrames[key] = newStackFrame;
            return _stackFrames[key];
        }

        private class CustomStackFrame : StackFrame
        {
            private string _methodName;
            private int _lineNumber;
            private int _columnNumber;
            private string _fileName;
            private int _nativeOffset;
            private int _ilOffset;

            public CustomStackFrame(int ilOffset, int nativeOffset, string fileName, int lineNumber, int columnNumber, string methodName)
                : base(fileName, lineNumber, columnNumber)
            {
                _lineNumber = lineNumber;
                _columnNumber = columnNumber;
                _methodName = methodName;
                _fileName = fileName;
                _nativeOffset = nativeOffset;
                _ilOffset = ilOffset;
            }

            public override string ToString()
            {
                return $"{_methodName} at offset {_nativeOffset} in file: line: column {_fileName}:{_lineNumber}:{_columnNumber}";
            }

            public override string GetFileName()
            {
                return _fileName;
            }

            public override int GetFileLineNumber()
            {
                return _lineNumber;
            }

            public override int GetFileColumnNumber()
            {
                return _columnNumber;
            }

            public override int GetNativeOffset()
            {
                return _nativeOffset;
            }

            public override int GetILOffset()
            {
                return _ilOffset;
            }
        }
    }
}
#nullable restore
