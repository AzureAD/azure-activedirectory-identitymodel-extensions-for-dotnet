// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Abstractions;
using Microsoft.IdentityModel.Tokens.Experimental;
using Microsoft.IdentityModel.Tokens.Saml;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// A <see cref="SecurityTokenHandler"/> designed for creating and validating Saml2 Tokens. See: http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    /// </summary>
    public partial class Saml2SecurityTokenHandler : SecurityTokenHandler, IResultBasedValidation
    {
        /// <summary>
        /// Validates a token.
        /// On a validation failure, no exception will be thrown; instead, the <see cref="ValidationError"/> will contain the information about the error that occurred.
        /// Callers should always check the ValidationResult.IsValid property to verify the validity of the result.
        /// </summary>
        /// <param name="token">The token to be validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">A <see cref="CallContext"/> that contains call information.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> that can be used to request cancellation of the asynchronous operation.</param>
        /// <returns>A <see cref="OperationResult{TResult, TError}"/> with either a <see cref="ValidatedToken"/> if the token was validated or an <see cref="ValidationError"/> with the failure information and exception otherwise.</returns>
#pragma warning disable RS0051 // Add internal types and members to the declared API
        internal override async Task<OperationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
#pragma warning restore RS0051 // Add internal types and members to the declared API
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            if (token is null)
                return ValidationError.NullParameter(nameof(token), ValidationError.GetCurrentStackFrame());

            if (validationParameters is null)
                return ValidationError.NullParameter(nameof(validationParameters), ValidationError.GetCurrentStackFrame());

            var tokenReadingResult = ReadSaml2Token(token, callContext);
            if (!tokenReadingResult.Succeeded)
                return tokenReadingResult.Error!.AddCurrentStackFrame();

            return await ValidateTokenAsync(tokenReadingResult.Result!, validationParameters, callContext, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
#pragma warning disable RS0051 // Add internal types and members to the declared API
        internal async override Task<OperationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
#pragma warning restore RS0051 // Add internal types and members to the declared API
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            if (securityToken is null)
            {
                return ValidationError.NullParameter(
                    nameof(securityToken),
                    ValidationError.GetCurrentStackFrame());
            }

            if (securityToken is not Saml2SecurityToken samlToken)
            {
                return new ValidationError(
                    new MessageDetail(
                        Saml.LogMessages.IDX11400,
                        this,
                        typeof(Saml2SecurityToken),
                        securityToken.GetType()),
                        ValidationFailureType.InvalidSecurityToken,
                        ValidationError.GetCurrentStackFrame());
            }

            if (validationParameters is null)
            {
                return ValidationError.NullParameter(
                    nameof(validationParameters),
                    ValidationError.GetCurrentStackFrame());
            }

            validationParameters = await SamlTokenUtilities.PopulateValidationParametersWithCurrentConfigurationAsync(validationParameters, cancellationToken).ConfigureAwait(false);

            var conditionsResult = ValidateConditions(
                samlToken,
                validationParameters,
                callContext);

            if (!conditionsResult.Succeeded)
                return conditionsResult.Error!.AddCurrentStackFrame();

            OperationResult<ValidatedIssuer, ValidationError> issuerValidationResult;

            try
            {
                issuerValidationResult = await validationParameters.IssuerValidatorAsync(
                    samlToken.Issuer,
                    samlToken,
                    validationParameters,
                    callContext,
                    cancellationToken).ConfigureAwait(false);

                if (!issuerValidationResult.Succeeded)
                    return issuerValidationResult.Error!.AddCurrentStackFrame();
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new IssuerValidationError(
                    new MessageDetail(Tokens.LogMessages.IDX10269),
                    ValidationFailureType.IssuerValidatorThrew,
                    ValidationError.GetCurrentStackFrame(),
                    samlToken.Issuer,
                    ex);
            }

            OperationResult<DateTime?, ValidationError>? tokenReplayValidationResult = null;

            if (samlToken.Assertion.Conditions is not null)
            {
                try
                {
                    tokenReplayValidationResult = validationParameters.TokenReplayValidator(
                        samlToken.Assertion.Conditions.NotOnOrAfter,
                        samlToken.Assertion.CanonicalString,
                        validationParameters,
                        callContext);

                    if (!tokenReplayValidationResult.Value.Succeeded)
                        return tokenReplayValidationResult.Value.Error!.AddCurrentStackFrame();
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
                {
                    return new TokenReplayValidationError(
                        new MessageDetail(Tokens.LogMessages.IDX10276),
                        ValidationFailureType.TokenReplayValidatorThrew,
                        ValidationError.GetCurrentStackFrame(),
                        samlToken.Assertion.Conditions.NotOnOrAfter,
                        ex);
                }
            }

            var signatureValidationResult = ValidateSignature(samlToken, validationParameters, callContext);
            if (!signatureValidationResult.Succeeded)
                return signatureValidationResult.Error!.AddCurrentStackFrame();

            OperationResult<ValidatedSigningKeyLifetime, ValidationError> issuerSigningKeyValidationResult;

            try
            {
                issuerSigningKeyValidationResult = validationParameters.IssuerSigningKeyValidator(
                    samlToken.SigningKey,
                    samlToken,
                    validationParameters,
                    callContext);

                if (!issuerSigningKeyValidationResult.Succeeded)
                    return issuerSigningKeyValidationResult.Error!.AddCurrentStackFrame();
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new IssuerSigningKeyValidationError(
                    new MessageDetail(Tokens.LogMessages.IDX10274),
                    ValidationFailureType.IssuerSigningKeyValidatorThrew,
                    ValidationError.GetCurrentStackFrame(),
                    samlToken.SigningKey,
                    ex);
            }

            return new ValidatedToken(samlToken, this, validationParameters)
            {
                ValidatedAudience = conditionsResult.Result!.ValidatedAudience,
                ValidatedLifetime = conditionsResult.Result!.ValidatedLifetime,
                ValidatedIssuer = issuerValidationResult.Result!,
                ValidatedTokenReplayExpirationTime = tokenReplayValidationResult?.Result,
                ValidatedSigningKey = signatureValidationResult.Result,
                ValidatedSigningKeyLifetime = issuerSigningKeyValidationResult.Result,
            };
        }

        // ValidatedConditions is basically a named tuple but using a record struct better expresses the intent.
#pragma warning disable RS0051 // Add internal types and members to the declared API
        internal class ValidatedConditions(string? ValidatedAudience, ValidatedLifetime? ValidatedLifetime)
        {
            /// <summary>
            /// The audience that was validated.
            /// </summary>
            public string? ValidatedAudience { get; } = ValidatedAudience;
            /// <summary>
            /// The lifetime that was validated.
            /// </summary>
            public ValidatedLifetime? ValidatedLifetime { get; } = ValidatedLifetime;
        }

        internal virtual OperationResult<ValidatedConditions, ValidationError> ValidateConditions(
            Saml2SecurityToken samlToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            if (samlToken.Assertion is null)
            {
                return ValidationError.NullParameter(
                    nameof(samlToken.Assertion),
                    ValidationError.GetCurrentStackFrame());
            }

            if (samlToken.Assertion.Conditions is null)
            {
                return ValidationError.NullParameter(
                    nameof(samlToken.Assertion.Conditions),
                    ValidationError.GetCurrentStackFrame());
            }

            OperationResult<ValidatedLifetime, ValidationError> lifetimeValidationResult;

            try
            {
                lifetimeValidationResult = validationParameters.LifetimeValidator(
                    samlToken.Assertion.Conditions.NotBefore,
                    samlToken.Assertion.Conditions.NotOnOrAfter,
                    samlToken,
                    validationParameters,
                    callContext);

                if (!lifetimeValidationResult.Succeeded)
                    return lifetimeValidationResult.Error!.AddCurrentStackFrame();
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new LifetimeValidationError(
                    new MessageDetail(Tokens.LogMessages.IDX10271),
                    ValidationFailureType.LifetimeValidatorThrew,
                    ValidationError.GetCurrentStackFrame(),
                    samlToken.Assertion.Conditions.NotBefore,
                    samlToken.Assertion.Conditions.NotOnOrAfter,
                    ex);
            }

            if (samlToken.Assertion.Conditions.OneTimeUse)
            {
                var oneTimeUseValidationError = ValidateOneTimeUseCondition(samlToken, validationParameters, callContext);

                if (oneTimeUseValidationError is not null)
                    return oneTimeUseValidationError.AddCurrentStackFrame();
            }

            if (samlToken.Assertion.Conditions.ProxyRestriction is not null)
            {
                var proxyValidationError = ValidateProxyRestriction(
                    samlToken,
                    validationParameters,
                    callContext);

                if (proxyValidationError is not null)
                    return proxyValidationError.AddCurrentStackFrame();
            }

            string? validatedAudience = null;
            foreach (var audienceRestriction in samlToken.Assertion.Conditions.AudienceRestrictions)
            {
                // AudienceRestriction.Audiences is a List<string> but returned as ICollection<string>
                // no conversion occurs, ToList() is never called but we have to account for the possibility.
                if (audienceRestriction.Audiences is not List<string> audiencesAsList)
                    audiencesAsList = [.. audienceRestriction.Audiences];

                OperationResult<string, ValidationError> audienceValidationResult;

                try
                {
                    audienceValidationResult = validationParameters.AudienceValidator(
                        audiencesAsList,
                        samlToken,
                        validationParameters,
                        callContext);

                    if (!audienceValidationResult.Succeeded)
                        return audienceValidationResult.Error!.AddCurrentStackFrame();
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
                {
                    return new AudienceValidationError(
                        new MessageDetail(Tokens.LogMessages.IDX10270),
                        ValidationFailureType.AudienceValidatorThrew,
                        ValidationError.GetCurrentStackFrame(),
                        audiencesAsList,
                        validationParameters.ValidAudiences,
                        ex);
                }

                // Audience is valid, save it for later.
                validatedAudience = audienceValidationResult.Result;
            }

            return new ValidatedConditions(validatedAudience, lifetimeValidationResult.Result!);
        }
#pragma warning restore RS0051 // Add internal types and members to the declared API

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
