// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// A <see cref="SecurityTokenHandler"/> designed for creating and validating Saml2 Tokens. See: http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    /// </summary>
    public partial class Saml2SecurityTokenHandler : SecurityTokenHandler
    {
#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
        internal async Task<ValidationResult<ValidatedToken>> ValidateTokenAsync(
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
            Saml2SecurityToken samlToken,
            ValidationParameters validationParameters,
            CallContext callContext,
#pragma warning disable CA1801 // Review unused parameters
            CancellationToken cancellationToken)
#pragma warning restore CA1801 // Review unused parameters
        {
            if (samlToken is null)
            {
                StackFrames.TokenNull ??= new StackFrame(true);
                return ValidationError.NullParameter(
                    nameof(samlToken),
                    StackFrames.TokenNull);
            }

            if (validationParameters is null)
            {
                StackFrames.TokenValidationParametersNull ??= new StackFrame(true);
                return ValidationError.NullParameter(
                    nameof(validationParameters),
                    StackFrames.TokenValidationParametersNull);
            }

            var conditionsResult = ValidateConditions(samlToken, validationParameters, callContext);

            if (!conditionsResult.IsValid)
            {
                StackFrames.AssertionConditionsValidationFailed ??= new StackFrame(true);
                return conditionsResult.UnwrapError().AddStackFrame(StackFrames.AssertionConditionsValidationFailed);
            }

            return new ValidatedToken(samlToken, this, validationParameters);
        }

        // ValidatedConditions is basically a named tuple but using a record struct better expresses the intent.
        internal record struct ValidatedConditions(string? ValidatedAudience, ValidatedLifetime? ValidatedLifetime);

        internal virtual ValidationResult<ValidatedConditions> ValidateConditions(
            Saml2SecurityToken samlToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            if (samlToken.Assertion is null)
            {
                StackFrames.AssertionNull ??= new StackFrame(true);
                return ValidationError.NullParameter(
                    nameof(samlToken.Assertion),
                    StackFrames.AssertionNull);
            }

            if (samlToken.Assertion.Conditions is null)
            {
                StackFrames.AssertionConditionsNull ??= new StackFrame(true);
                return ValidationError.NullParameter(
                    nameof(samlToken.Assertion.Conditions),
                    StackFrames.AssertionConditionsNull);
            }

            var lifetimeValidationResult = validationParameters.LifetimeValidator(
                samlToken.Assertion.Conditions.NotBefore,
                samlToken.Assertion.Conditions.NotOnOrAfter,
                samlToken,
                validationParameters,
                callContext);

            if (!lifetimeValidationResult.IsValid)
            {
                StackFrames.LifetimeValidationFailed ??= new StackFrame(true);
                return lifetimeValidationResult.UnwrapError().AddStackFrame(StackFrames.LifetimeValidationFailed);
            }

            if (samlToken.Assertion.Conditions.OneTimeUse)
            {
                //ValidateOneTimeUseCondition(samlToken, validationParameters);
                // We can keep an overridable method for this, or rely on the TokenReplayValidator delegate.
                var oneTimeUseValidationResult = validationParameters.TokenReplayValidator(
                    samlToken.Assertion.Conditions.NotOnOrAfter,
                    samlToken.Assertion.CanonicalString,
                    validationParameters,
                    callContext);

                if (!oneTimeUseValidationResult.IsValid)
                {
                    StackFrames.OneTimeUseValidationFailed ??= new StackFrame(true);
                    return oneTimeUseValidationResult.UnwrapError().AddStackFrame(StackFrames.OneTimeUseValidationFailed);
                }
            }

            if (samlToken.Assertion.Conditions.ProxyRestriction != null)
            {
                //throw LogExceptionMessage(new SecurityTokenValidationException(LogMessages.IDX13511));
                var proxyValidationError = ValidateProxyRestriction(
                    samlToken,
                    validationParameters,
                    callContext);

                if (proxyValidationError is not null)
                {
                    return proxyValidationError;
                }
            }

            string? validatedAudience = null;
            foreach (var audienceRestriction in samlToken.Assertion.Conditions.AudienceRestrictions)
            {
                // AudienceRestriction.Audiences is a List<string> but returned as ICollection<string>
                // no conversion occurs, ToList() is never called but we have to account for the possibility.
                if (audienceRestriction.Audiences is not List<string> audiencesAsList)
                    audiencesAsList = [.. audienceRestriction.Audiences];

                var audienceValidationResult = validationParameters.AudienceValidator(
                    audiencesAsList,
                    samlToken,
                    validationParameters,
                    callContext);
                if (!audienceValidationResult.IsValid)
                {
                    StackFrames.AudienceValidationFailed ??= new StackFrame(true);
                    return audienceValidationResult.UnwrapError().AddStackFrame(StackFrames.AudienceValidationFailed);
                }

                // Audience is valid, save it for later.
                validatedAudience = audienceValidationResult.UnwrapResult();
            }

            return new ValidatedConditions(validatedAudience, lifetimeValidationResult.UnwrapResult());
        }

#pragma warning disable CA1801 // Review unused parameters
        internal virtual ValidationError? ValidateProxyRestriction(Saml2SecurityToken samlToken, ValidationParameters validationParameters, CallContext callContext)
#pragma warning restore CA1801 // Review unused parameters
        {
            // return an error, or ignore and allow overriding?
            return null;
        }
    }
}
#nullable restore
