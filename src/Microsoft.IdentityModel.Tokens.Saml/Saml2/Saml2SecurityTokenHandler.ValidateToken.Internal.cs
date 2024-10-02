// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
            var conditionsResult = ValidateConditions(samlToken, validationParameters, callContext);

            if (!conditionsResult.IsSuccess)
            {
                return conditionsResult.UnwrapError().AddStackFrame(new StackFrame(true));
            }

            //These TODO's follow the pattern of the current ValidateToken methods. They should be implemented in the future.
            //TODO: ValidateSubject() - Skip for now
            //TODO: ValidateIssuer()
            //TODO: ValidateIssuerSecurityKey()...etc

            return new ValidatedToken(samlToken, this, validationParameters);
        }



        // ValidatedConditions is basically a named tuple but using a record struct better expresses the intent.
        internal record struct ValidatedConditions(string? ValidatedAudience, ValidatedLifetime? ValidatedLifetime);

        internal virtual ValidationResult<ValidatedConditions> ValidateConditions(Saml2SecurityToken samlToken, ValidationParameters validationParameters, CallContext callContext)
        {
            if (samlToken == null)
                return ValidationError.NullParameter(nameof(samlToken), new System.Diagnostics.StackFrame(true));

            if (validationParameters == null)
                return ValidationError.NullParameter(nameof(validationParameters), new System.Diagnostics.StackFrame(true));

            if (samlToken.Assertion == null)
                return ValidationError.NullParameter(nameof(samlToken.Assertion), new System.Diagnostics.StackFrame(true));

            // TokenValidationParameters.RequireAudience is only used for SAML.
            // Should we add this to ValidationParameters? 
            // Should it be just a field in Saml2SecurityTokenHandler?
            bool requireAudience = true;

            if (samlToken.Assertion.Conditions == null)
            {
                if (requireAudience)
                    return new ValidationError(
                        new MessageDetail(LogMessages.IDX13002),
                        ValidationFailureType.AudienceValidationFailed,
                        typeof(Saml2SecurityTokenException),
                        new System.Diagnostics.StackFrame(true));

                return new ValidatedConditions(null, null); // no error occurred. There is no validated audience or lifetime.
            }

            var lifetimeValidationResult = validationParameters.LifetimeValidator(
                samlToken.Assertion.Conditions.NotBefore, samlToken.Assertion.Conditions.NotOnOrAfter, samlToken, validationParameters, callContext);
            if (!lifetimeValidationResult.IsSuccess)
                return lifetimeValidationResult.UnwrapError();

            if (samlToken.Assertion.Conditions.OneTimeUse)
            {
                //ValidateOneTimeUseCondition(samlToken, validationParameters);
                // We can keep an overridable method for this, or rely on the TokenReplayValidator delegate.
                var oneTimeUseValidationResult = validationParameters.TokenReplayValidator(
                    samlToken.Assertion.Conditions.NotOnOrAfter, samlToken.Assertion.CanonicalString, validationParameters, callContext);
                if (!oneTimeUseValidationResult.IsSuccess)
                    return oneTimeUseValidationResult.UnwrapError();
            }

            if (samlToken.Assertion.Conditions.ProxyRestriction != null)
            {
                //throw LogExceptionMessage(new SecurityTokenValidationException(LogMessages.IDX13511));
                var proxyValidationError = ValidateProxyRestriction(samlToken, validationParameters, callContext);
                if (proxyValidationError is not null)
                    return proxyValidationError;
            }

            string? validatedAudience = null;
            foreach (var audienceRestriction in samlToken.Assertion.Conditions.AudienceRestrictions)
            {
                // AudienceRestriction.Audiences is a List<string> but returned as ICollection<string>
                // no conversion occurs, ToList() is never called but we have to account for the possibility.
                if (!(audienceRestriction.Audiences is List<string> audiencesAsList))
                    audiencesAsList = audienceRestriction.Audiences.ToList();

                var audienceValidationResult = validationParameters.AudienceValidator(
                    audiencesAsList, samlToken, validationParameters, callContext);
                if (!audienceValidationResult.IsSuccess)
                    return audienceValidationResult.UnwrapError();

                // Audience is valid, save it for later.
                validatedAudience = audienceValidationResult.UnwrapResult();
            }

            if (requireAudience && validatedAudience is null)
            {
                return new ValidationError(
                    new MessageDetail(LogMessages.IDX13002),
                    ValidationFailureType.AudienceValidationFailed,
                    typeof(Saml2SecurityTokenException),
                    new System.Diagnostics.StackFrame(true));
            }

            return new ValidatedConditions(validatedAudience, lifetimeValidationResult.UnwrapResult()); // no error occurred. There is nothing else to return.
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
