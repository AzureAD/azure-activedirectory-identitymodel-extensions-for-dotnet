// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics;
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
#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
        internal async Task<ValidationResult<ValidatedToken>> ValidateTokenAsync(
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
            SamlSecurityToken samlToken,
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

            if (!conditionsResult.IsSuccess)
            {
                return conditionsResult.UnwrapError().AddStackFrame(new StackFrame(true));
            }

            return new ValidatedToken(samlToken, this, validationParameters);
        }

        // ValidatedConditions is basically a named tuple but using a record struct better expresses the intent.
        internal record struct ValidatedConditions(string? ValidatedAudience, ValidatedLifetime? ValidatedLifetime);

        internal virtual ValidationResult<ValidatedConditions> ValidateConditions(SamlSecurityToken samlToken, ValidationParameters validationParameters, CallContext callContext)
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

            if (!lifetimeValidationResult.IsSuccess)
            {
                StackFrames.LifetimeValidationFailed ??= new StackFrame(true);
                return lifetimeValidationResult.UnwrapError().AddStackFrame(StackFrames.LifetimeValidationFailed);
            }

            string? validatedAudience = null;
            foreach (var condition in samlToken.Assertion.Conditions.Conditions)
            {

                if (condition is SamlAudienceRestrictionCondition audienceRestriction)
                {

                    // AudienceRestriction.Audiences is an ICollection<Uri> so we need make a conversion to List<string> before calling our audience validator 
                    var audiencesAsList = audienceRestriction.Audiences.Select(static x => x.OriginalString).ToList();

                    var audienceValidationResult = validationParameters.AudienceValidator(
                        audiencesAsList,
                        samlToken,
                        validationParameters,
                        callContext);

                    if (!audienceValidationResult.IsSuccess)
                        return audienceValidationResult.UnwrapError();

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
