// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// A <see cref="SecurityTokenHandler"/> designed for creating and validating Saml Tokens. See: http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    /// </summary>
    public partial class SamlSecurityTokenHandler : SecurityTokenHandler
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
        /// <returns>A <see cref="ValidationResult{TResult}"/> with either a <see cref="ValidatedToken"/> if the token was validated or an <see cref="ValidationError"/> with the failure information and exception otherwise.</returns>
        internal async override Task<ValidationResult<ValidatedToken>> ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken = default)
        {
            if (token is null)
                return ValidationError.NullParameter(nameof(token), ValidationError.GetCurrentStackFrame());

            if (validationParameters is null)
                return ValidationError.NullParameter(nameof(validationParameters), ValidationError.GetCurrentStackFrame());

            var tokenReadingResult = ReadSamlToken(token, callContext);
            if (!tokenReadingResult.IsValid)
                return tokenReadingResult.UnwrapError().AddCurrentStackFrame();

            return await ValidateTokenAsync(tokenReadingResult.UnwrapResult(), validationParameters, callContext, cancellationToken).ConfigureAwait(false);
        }

        internal override async Task<ValidationResult<ValidatedToken>> ValidateTokenAsync(
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken = default)
        {
            if (securityToken is null)
            {
                return ValidationError.NullParameter(
                    nameof(securityToken),
                    ValidationError.GetCurrentStackFrame());
            }

            if (securityToken is not SamlSecurityToken samlToken)
            {
                return new ValidationError(
                    new MessageDetail(
                        LogMessages.IDX11400,
                        this,
                        typeof(SamlSecurityToken),
                        securityToken.GetType()),
                    ValidationFailureType.InvalidSecurityToken,
                    typeof(SecurityTokenArgumentException),
                    ValidationError.GetCurrentStackFrame());
            }

            if (validationParameters is null)
            {
                return ValidationError.NullParameter(
                    nameof(validationParameters),
                    ValidationError.GetCurrentStackFrame());
            }

            ValidationResult<ValidatedConditions> conditionsResult = ValidateConditions(samlToken, validationParameters, callContext);

            if (!conditionsResult.IsValid)
                return conditionsResult.UnwrapError().AddCurrentStackFrame();

            ValidationResult<ValidatedIssuer> issuerValidationResult;

            try
            {
                issuerValidationResult = await validationParameters.IssuerValidatorAsync(
                    samlToken.Issuer,
                    samlToken,
                    validationParameters,
                    callContext,
                    cancellationToken).ConfigureAwait(false);

                if (!issuerValidationResult.IsValid)
                    return issuerValidationResult.UnwrapError().AddCurrentStackFrame();
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new IssuerValidationError(
                    new MessageDetail(Tokens.LogMessages.IDX10269),
                    ValidationFailureType.IssuerValidatorThrew,
                    typeof(SecurityTokenInvalidIssuerException),
                    ValidationError.GetCurrentStackFrame(),
                    samlToken.Issuer,
                    ex);
            }

            ValidationResult<DateTime?>? tokenReplayValidationResult = null;

            if (samlToken.Assertion.Conditions is not null)
            {
                try
                {
                    tokenReplayValidationResult = validationParameters.TokenReplayValidator(
                        samlToken.Assertion.Conditions.NotOnOrAfter,
                        samlToken.Assertion.CanonicalString,
                        validationParameters,
                        callContext);

                    if (!tokenReplayValidationResult.Value.IsValid)
                        return tokenReplayValidationResult.Value.UnwrapError().AddCurrentStackFrame();
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
                {
                    return new TokenReplayValidationError(
                        new MessageDetail(Tokens.LogMessages.IDX10276),
                        ValidationFailureType.TokenReplayValidatorThrew,
                        typeof(SecurityTokenReplayDetectedException),
                        ValidationError.GetCurrentStackFrame(),
                        samlToken.Assertion.Conditions.NotOnOrAfter,
                        ex);
                }
            }

            ValidationResult<SecurityKey> signatureValidationResult = ValidateSignature(samlToken, validationParameters, callContext);

            if (!signatureValidationResult.IsValid)
                return signatureValidationResult.UnwrapError().AddCurrentStackFrame();

            ValidationResult<ValidatedSigningKeyLifetime> issuerSigningKeyValidationResult;

            try
            {
                issuerSigningKeyValidationResult = validationParameters.IssuerSigningKeyValidator(
                    samlToken.SigningKey,
                    samlToken,
                    validationParameters,
                    callContext);

                if (!issuerSigningKeyValidationResult.IsValid)
                    return issuerSigningKeyValidationResult.UnwrapError().AddCurrentStackFrame();
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new IssuerSigningKeyValidationError(
                    new MessageDetail(Tokens.LogMessages.IDX10274),
                    ValidationFailureType.IssuerSigningKeyValidatorThrew,
                    typeof(SecurityTokenInvalidSigningKeyException),
                    ValidationError.GetCurrentStackFrame(),
                    samlToken.SigningKey,
                    ex);
            }

            return new ValidatedToken(samlToken, this, validationParameters)
            {
                ValidatedAudience = conditionsResult.UnwrapResult().ValidatedAudience,
                ValidatedLifetime = conditionsResult.UnwrapResult().ValidatedLifetime,
                ValidatedIssuer = issuerValidationResult.UnwrapResult(),
                ValidatedTokenReplayExpirationTime = tokenReplayValidationResult?.UnwrapResult(),
                ValidatedSigningKey = signatureValidationResult.UnwrapResult(),
                ValidatedSigningKeyLifetime = issuerSigningKeyValidationResult.UnwrapResult(),
            };
        }

        // ValidatedConditions is basically a named tuple but using a record struct better expresses the intent.
        internal record struct ValidatedConditions(string? ValidatedAudience, ValidatedLifetime? ValidatedLifetime);

        internal virtual ValidationResult<ValidatedConditions> ValidateConditions(
            SamlSecurityToken samlToken,
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

            ValidationResult<ValidatedLifetime> lifetimeValidationResult;

            try
            {
                lifetimeValidationResult = validationParameters.LifetimeValidator(
                    samlToken.Assertion.Conditions.NotBefore,
                    samlToken.Assertion.Conditions.NotOnOrAfter,
                    samlToken,
                    validationParameters,
                    callContext);

                if (!lifetimeValidationResult.IsValid)
                    return lifetimeValidationResult.UnwrapError().AddCurrentStackFrame();
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new LifetimeValidationError(
                    new MessageDetail(Tokens.LogMessages.IDX10271),
                    ValidationFailureType.LifetimeValidatorThrew,
                    typeof(SecurityTokenInvalidLifetimeException),
                    ValidationError.GetCurrentStackFrame(),
                    samlToken.Assertion.Conditions.NotBefore,
                    samlToken.Assertion.Conditions.NotOnOrAfter,
                    ex);
            }

            string? validatedAudience = null;
            foreach (var condition in samlToken.Assertion.Conditions.Conditions)
            {

                if (condition is SamlAudienceRestrictionCondition audienceRestriction)
                {
                    // AudienceRestriction.Audiences is an ICollection<Uri> so we need make a conversion to List<string> before calling our audience validator 
                    var audiencesAsList = audienceRestriction.Audiences.Select(static x => x.OriginalString).ToList();
                    ValidationResult<string> audienceValidationResult;

                    try
                    {
                        audienceValidationResult = validationParameters.AudienceValidator(
                            audiencesAsList,
                            samlToken,
                            validationParameters,
                            callContext);

                        if (!audienceValidationResult.IsValid)
                            return audienceValidationResult.UnwrapError().AddCurrentStackFrame();
                    }
#pragma warning disable CA1031 // Do not catch general exception types
                    catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
                    {
                        return new AudienceValidationError(
                            new MessageDetail(Tokens.LogMessages.IDX10270),
                            ValidationFailureType.AudienceValidatorThrew,
                            typeof(SecurityTokenInvalidAudienceException),
                            ValidationError.GetCurrentStackFrame(),
                            audiencesAsList,
                            validationParameters.ValidAudiences,
                            ex);
                    }

                    validatedAudience = audienceValidationResult.UnwrapResult();
                }

                if (validatedAudience != null)
                    break;
            }

            return new ValidatedConditions(validatedAudience, lifetimeValidationResult.UnwrapResult());
        }
    }
}
#nullable restore
