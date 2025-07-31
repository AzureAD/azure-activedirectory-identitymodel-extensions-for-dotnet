// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Abstractions;
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
        internal override async Task<OperationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            if (token is null)
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

            OperationResult<SecurityToken, ValidationError> readResult = ReadToken(token, Serializer, callContext);
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
        internal async override Task<OperationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
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

            if (securityToken is not Saml2SecurityToken samlToken)
            {
                if (!ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(new StackFrame(0, true));

                return new ValidationError(
                    new MessageDetail(TokenLogMessages.IDX10001, nameof(securityToken), nameof(Saml2SecurityToken)),
                    ValidationFailureType.SecurityTokenNotExpectedType,
                    stackFrame!);
            }

            if (samlToken.Assertion is null)
            {
                if (!ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(new StackFrame(0, true));

                return new ValidationError(
                    new MessageDetail(Saml.LogMessages.IDX11315),
                    ValidationFailureType.SecurityTokenNotExpectedType,
                    stackFrame!);
            }

            OperationResult<ValidatedLifetime, ValidationError> lifetimeResult =
                Validators.ValidateLifetimeInternal(
                    samlToken.Assertion.Conditions?.NotBefore,
                    samlToken.Assertion.Conditions?.NotOnOrAfter,
                    samlToken,
                    validationParameters,
                    callContext);

            if (!lifetimeResult.Succeeded)
            {
                if (!ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    stackFrame = ValidationError.GetAsyncStackFrame(new StackFrame(0, true));

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

            OperationResult<string, ValidationError> audienceResult =
                Validators.ValidateAudienceInternal(
                    audiences,
                    samlToken,
                    validationParameters,
                    callContext);

            if (!audienceResult.Succeeded)
            {
                if (ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    return audienceResult.Error!.AddStackFrame(stackFrame!);

                return audienceResult.Error!.AddAsyncStackFrame(new StackFrame(0, true));
            }

            OperationResult<ValidatedIssuer, ValidationError> issuerResult =
                await Validators.ValidateIssuerInternalAsync(
                    samlToken.Issuer,
                    samlToken,
                    validationParameters,
                    callContext,
                    cancellationToken).ConfigureAwait(false);

            if (!issuerResult.Succeeded)
            {
                if (ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    return issuerResult.Error!.AddStackFrame(stackFrame!);

                return issuerResult.Error!.AddAsyncStackFrame(new StackFrame(0, true));
            }

            OperationResult<DateTime?, ValidationError>? tokenReplayResult = Validators.ValidateTokenReplayInternal(
                        samlToken.Assertion!.Conditions?.NotOnOrAfter,
                        samlToken.Assertion!.CanonicalString!,
                        validationParameters,
                        callContext);

            if (!tokenReplayResult.Value.Succeeded)
            {
                if (ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    return tokenReplayResult.Value.Error!.AddStackFrame(stackFrame!);

                return tokenReplayResult.Value.Error!.AddAsyncStackFrame(new StackFrame(0, true));
            }

            OperationResult<string, ValidationError> algorithmResult =
                Validators.ValidateAlgorithmInternal(
                    samlToken!.Assertion!.Signature?.SignedInfo?.SignatureMethod,
                    samlToken,
                    validationParameters,
                    callContext);

            if (!algorithmResult.Succeeded)
            {
                if (ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    return algorithmResult.Error!.AddStackFrame(stackFrame!);

                return algorithmResult.Error!.AddAsyncStackFrame(new StackFrame(0, true));
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
                if (ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    return signatureResult.Error!.AddStackFrame(stackFrame!);

                return signatureResult.Error!.AddAsyncStackFrame(new StackFrame(0, true));
            }

            OperationResult<ValidatedSignatureKey, ValidationError> signingKeyResult =
                Validators.ValidateSignatureKeyInternal(
                    samlToken.SigningKey,
                    samlToken,
                    validationParameters,
                    callContext);

            if (!signingKeyResult.Succeeded)
            {
                if (ValidationError.TryGetStackFrame(out StackFrame? stackFrame))
                    return signingKeyResult.Error!.AddStackFrame(stackFrame!);

                return signingKeyResult.Error!.AddAsyncStackFrame(new StackFrame(0, true));
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
    }
}
#nullable restore
