// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens.Experimental;
using Microsoft.IdentityModel.Tokens.Saml;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// A <see cref="SecurityTokenHandler"/> designed for creating and validating Saml2 Tokens. See: http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    /// </summary>
    public partial class Saml2SecurityTokenHandler : SecurityTokenHandler, IResultBasedValidation
    {
        /// <inheritdoc/>
        internal override async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            StackFrame? stackFrame;
            if (string.IsNullOrEmpty(token))
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return ValidationError.NullParameter(
                    nameof(token),
                    stackFrame!);
            }

            if (validationParameters is null)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return ValidationError.NullParameter(
                    nameof(validationParameters),
                    stackFrame!);
            }

            if (token.Length > MaximumTokenSizeInBytes)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return new ValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10209,
                        LogHelper.MarkAsNonPII(token.Length),
                        LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes)),
                    ValidationFailureType.TokenExceedsMaximumSize,
                    stackFrame!);
            }

            ValidationResult<SecurityToken, ValidationError> readResult = ReadToken(token, Serializer, callContext);
            if (!readResult.Succeeded)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return readResult.Error!.AddStackFrame(stackFrame!);
            }

            ValidationResult<ValidatedToken, ValidationError> validationResult =
                await ValidateTokenAsync(
                    readResult.Result!,
                    validationParameters,
                    callContext,
                    cancellationToken).ConfigureAwait(false);

            if (!validationResult.Succeeded)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return validationResult.Error!.AddStackFrame(stackFrame!);
            }

            return validationResult;
        }

        /// <inheritdoc/>
        internal async override Task<ValidationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            StackFrame? stackFrame;
            if (securityToken is null)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return ValidationError.NullParameter(
                    nameof(securityToken),
                    stackFrame!);
            }

            if (validationParameters is null)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return ValidationError.NullParameter(
                    nameof(validationParameters),
                    stackFrame!);
            }

            if (securityToken is not Saml2SecurityToken samlToken)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return new ValidationError(
                    new MessageDetail(TokenLogMessages.IDX10001, nameof(securityToken), nameof(Saml2SecurityToken)),
                    ValidationFailureType.SecurityTokenNotExpectedType,
                    stackFrame!);
            }

            if (samlToken.Assertion is null)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return new ValidationError(
                    new MessageDetail(Saml.LogMessages.IDX11315),
                    ValidationFailureType.SecurityTokenNotExpectedType,
                    stackFrame!);
            }

            ValidationResult<ValidatedLifetime, ValidationError> lifetimeResult =
                Validators.ValidateLifetimeInternal(
                    samlToken.Assertion.Conditions?.NotBefore,
                    samlToken.Assertion.Conditions?.NotOnOrAfter,
                    samlToken,
                    validationParameters,
                    callContext);

            if (!lifetimeResult.Succeeded)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return lifetimeResult.Error!.AddStackFrame(stackFrame!);
            }

            List<string> audiences = [];
            if (samlToken.Assertion?.Conditions is not null)
            {
                foreach (var audienceRestriction in samlToken.Assertion!.Conditions.AudienceRestrictions)
                {
                    // AudienceRestriction.Audiences is a List<string> but returned as ICollection<string>
                    // no conversion occurs, ToList() is never called but we have to account for the possibility.
                    if (audienceRestriction.Audiences is not List<string> audiencesAsList)
                    {
                        if (audiences == null)
                            audiences = [.. audienceRestriction.Audiences];
                        else
                            foreach (string audience in audienceRestriction.Audiences)
                                audiences.Add(audience);
                    }
                    else
                    {
                        if (audiences == null)
                        {
                            audiences = audiencesAsList;
                        }
                        else
                            foreach (string audience in audienceRestriction.Audiences)
                                audiences.Add(audience);
                    }
                }
            }

            ValidationResult<string, ValidationError> audienceResult =
                Validators.ValidateAudienceInternal(
                    audiences,
                    samlToken,
                    validationParameters,
                    callContext);

            if (!audienceResult.Succeeded)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return audienceResult.Error!.AddStackFrame(stackFrame!);
            }

            ValidationResult<ValidatedIssuer, ValidationError> issuerResult =
                await Validators.ValidateIssuerInternalAsync(
                    samlToken.Issuer,
                    samlToken,
                    validationParameters,
                    callContext,
                    cancellationToken).ConfigureAwait(false);

            if (!issuerResult.Succeeded)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return issuerResult.Error!.AddStackFrame(stackFrame!);
            }

            ValidationResult<DateTime?, ValidationError>? tokenReplayResult = Validators.ValidateTokenReplayInternal(
                        samlToken.Assertion!.Conditions?.NotOnOrAfter,
                        samlToken.Assertion!.CanonicalString!,
                        validationParameters,
                        callContext);

            if (!tokenReplayResult.Value.Succeeded)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return tokenReplayResult.Value.Error!.AddStackFrame(stackFrame!);
            }

            ValidationResult<string, ValidationError> algorithmResult =
                Validators.ValidateAlgorithmInternal(
                    samlToken!.Assertion!.Signature?.SignedInfo?.SignatureMethod,
                    samlToken,
                    validationParameters,
                    callContext);

            if (!algorithmResult.Succeeded)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return algorithmResult.Error!.AddStackFrame(stackFrame!);
            }

            BaseConfiguration? configuration = null;
            if (validationParameters.ConfigurationManager is not null)
            {
                try
                {
                    configuration = await validationParameters.ConfigurationManager.GetBaseConfigurationAsync(cancellationToken).ConfigureAwait(false);
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch
#pragma warning restore CA1031 // Do not catch general exception types
                {
                    // The exception is tracked and dismissed as the ValidationParameters may have the issuer
                    // and signing key set directly on them, allowing the library to continue with token validation.
                }
            }

            var signatureResult = SamlTokenUtilities.ValidateSignature(
                samlToken,
                samlToken.Assertion.Signature,
                samlToken.Assertion.CanonicalString,
                validationParameters,
                configuration,
                callContext);

            if (!signatureResult.Succeeded)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return signatureResult.Error!.AddStackFrame(stackFrame!);
            }

            ValidationResult<ValidatedSignatureKey, ValidationError> signingKeyResult =
                Validators.ValidateSignatureKeyInternal(
                    samlToken.SigningKey,
                    samlToken,
                    validationParameters,
                    callContext);

            if (!signingKeyResult.Succeeded)
            {
                string key = ValidationError.GetStackFrameKey(memberName: nameof(ValidateTokenAsync));
                if (!ValidationError.TryGetStackFrame(key, out stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(key, new StackFrame(0, true));

                return signingKeyResult.Error!.AddStackFrame(stackFrame!);
            }

            return new ValidatedToken(samlToken, this, validationParameters)
            {
                ValidatedAudience = audienceResult.Result,
                ValidatedAlgorithm = algorithmResult.Result,
                ValidatedLifetime = lifetimeResult.Result,
                ValidatedIssuer = issuerResult.Result,
                ValidatedSignatureKey = signatureResult.Result
            };
        }

#pragma warning disable CA1801 // Review unused parameters
        internal virtual ValidationError? ValidateProxyRestriction(Saml2SecurityToken samlToken, ValidationParameters validationParameters, CallContext callContext)
#pragma warning restore CA1801 // Review unused parameters
        {
            return null;
        }

#pragma warning disable CA1801 // Review unused parameters
        internal virtual ValidationError? ValidateOneTimeUseCondition(Saml2SecurityToken samlToken, ValidationParameters validationParameters, CallContext callContext)
#pragma warning restore CA1801 // Review unused parameters
        {
            return null;
        }

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
