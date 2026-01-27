// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    public static class SkipValidationValidators
    {
        internal static readonly IAlgorithmValidator SkipAlgorithmValidation = new AlgorithmValidator();
        internal static readonly IAudienceValidator SkipAudienceValidation = new AudienceValidator();
        internal static readonly IIssuerValidator SkipIssuerValidation = new IssuerValidator();
        internal static readonly ISignatureKeyValidator SkipIssuerSigningKeyValidation = new SignatureKeyValidator();
        internal static readonly ILifetimeValidator SkipLifetimeValidation = new LifetimeValidator();
        internal static readonly ISignatureValidator SkipSignatureValidation = new SignatureValidator();
        internal static readonly ITokenReplayValidator SkipTokenReplayValidation = new TokenReplayValidator();
        internal static readonly ITokenTypeValidator SkipTokenTypeValidation = new TokenTypeValidator();

        private class AlgorithmValidator : IAlgorithmValidator
        {
            public ValidationResult<string, ValidationError> ValidateAlgorithm(
                string? algorithm,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return algorithm ?? string.Empty;
            }
        }

        private class AudienceValidator : IAudienceValidator
        {
            public ValidationResult<string, ValidationError> ValidateAudience(
                IList<string> tokenAudiences,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return "skipped"; // The audience that was validated.
            }
        }

        private class IssuerValidator : IIssuerValidator
        {
            public Task<ValidationResult<ValidatedIssuer, ValidationError>> ValidateIssuerAsync(
                string issuer,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext,
                CancellationToken cancellationToken)
            {
                return Task.FromResult(new ValidationResult<ValidatedIssuer, ValidationError>(
                    new ValidatedIssuer(issuer, IssuerValidationSource.NotValidated)));
            }
        }

        private class SignatureKeyValidator : ISignatureKeyValidator
        {
            public ValidationResult<ValidatedSignatureKey, ValidationError> ValidateSignatureKey(
                SecurityKey signingKey,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new ValidatedSignatureKey(
                    null, // ValidFrom
                    null, // ValidTo
                    null);// ValidationTime
            }
        }

        private class LifetimeValidator : ILifetimeValidator
        {
            public ValidationResult<ValidatedLifetime, ValidationError> ValidateLifetime(
                DateTime? notBefore,
                DateTime? expires,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new ValidatedLifetime(notBefore, expires);
            }
        }

        private class SignatureValidator : ISignatureValidator
        {
            public ValidationResult<SecurityKey, ValidationError> ValidateSignature(
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                BaseConfiguration? configuration,
                CallContext callContext)
            {
                // This key is not used during the validation process. It is only used to satisfy the delegate signature.
                // Follow up PR will change this to remove the SecurityKey return value.
                return new(result: new JsonWebKey());
            }
        }

        private class TokenReplayValidator : ITokenReplayValidator
        {
            public ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
                DateTime? expirationTime,
                string securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return expirationTime;
            }
        }

        private class TokenTypeValidator : ITokenTypeValidator
        {
            public ValidationResult<ValidatedTokenType, ValidationError> ValidateTokenType(
                string? type,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new ValidatedTokenType("skipped", 0);
            }
        }
    }
}
#nullable restore
