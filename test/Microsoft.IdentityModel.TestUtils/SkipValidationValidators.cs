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

        // Helper methods to wrap delegates into interfaces for test scenarios
        public static IAlgorithmValidator AlgorithmValidatorFromDelegate(AlgorithmValidationDelegate del)
            => new LambdaAlgorithmValidator(del);

        public static ISignatureValidator SignatureValidatorFromDelegate(SignatureValidationDelegate del)
            => new LambdaSignatureValidator(del);

        public static ISignatureKeyResolver SignatureKeyResolverFromDelegate(SignatureKeyResolverDelegate del)
            => new LambdaSignatureKeyResolver(del);

        public static ISignatureKeyValidator SignatureKeyValidatorFromDelegate(SignatureKeyValidationDelegate del)
            => new LambdaSignatureKeyValidator(del);

        public static ILifetimeValidator LifetimeValidatorFromDelegate(LifetimeValidationDelegate del)
            => new LambdaLifetimeValidator(del);

        public static ITokenReplayValidator TokenReplayValidatorFromDelegate(TokenReplayValidationDelegate del)
            => new LambdaTokenReplayValidator(del);

        public static ITokenTypeValidator TokenTypeValidatorFromDelegate(TokenTypeValidationDelegate del)
            => new LambdaTokenTypeValidator(del);

        public static IAudienceValidator AudienceValidatorFromDelegate(AudienceValidationDelegate del)
            => new LambdaAudienceValidator(del);

        public static IIssuerValidator IssuerValidatorFromDelegate(IssuerValidationDelegateAsync del)
            => new LambdaIssuerValidator(del);

        public static IDecryptionKeyResolver DecryptionKeyResolverFromDelegate(DecryptionKeyResolverDelegate del)
            => new LambdaDecryptionKeyResolver(del);

        private class LambdaAlgorithmValidator : IAlgorithmValidator
        {
            private readonly AlgorithmValidationDelegate _delegate;

            public LambdaAlgorithmValidator(AlgorithmValidationDelegate del)
            {
                _delegate = del;
            }

            public ValidationResult<string, ValidationError> ValidateAlgorithm(
                string? algorithm,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return _delegate(algorithm, securityToken, validationParameters, callContext);
            }
        }

        private class LambdaSignatureValidator : ISignatureValidator
        {
            private readonly SignatureValidationDelegate _delegate;

            public LambdaSignatureValidator(SignatureValidationDelegate del)
            {
                _delegate = del;
            }

            public ValidationResult<SecurityKey, ValidationError> ValidateSignature(
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                BaseConfiguration? configuration,
                CallContext callContext)
            {
                return _delegate(securityToken, validationParameters, configuration, callContext);
            }
        }

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

        private class LambdaSignatureKeyResolver : ISignatureKeyResolver
        {
            private readonly SignatureKeyResolverDelegate _delegate;

            public LambdaSignatureKeyResolver(SignatureKeyResolverDelegate del)
            {
                _delegate = del;
            }

            public SecurityKey? ResolveSignatureKey(
                string token,
                SecurityToken? securityToken,
                string? kid,
                ValidationParameters validationParameters,
                BaseConfiguration? configuration,
                CallContext? callContext)
            {
                return _delegate(token, securityToken, kid, validationParameters, configuration, callContext);
            }
        }

        private class LambdaSignatureKeyValidator : ISignatureKeyValidator
        {
            private readonly SignatureKeyValidationDelegate _delegate;

            public LambdaSignatureKeyValidator(SignatureKeyValidationDelegate del)
            {
                _delegate = del;
            }

            public ValidationResult<ValidatedSignatureKey, ValidationError> ValidateSignatureKey(
                SecurityKey signingKey,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return _delegate(signingKey, securityToken, validationParameters, callContext);
            }
        }

        private class LambdaLifetimeValidator : ILifetimeValidator
        {
            private readonly LifetimeValidationDelegate _delegate;

            public LambdaLifetimeValidator(LifetimeValidationDelegate del)
            {
                _delegate = del;
            }

            public ValidationResult<ValidatedLifetime, ValidationError> ValidateLifetime(
                DateTime? notBefore,
                DateTime? expires,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return _delegate(notBefore, expires, securityToken, validationParameters, callContext);
            }
        }

        private class LambdaTokenReplayValidator : ITokenReplayValidator
        {
            private readonly TokenReplayValidationDelegate _delegate;

            public LambdaTokenReplayValidator(TokenReplayValidationDelegate del)
            {
                _delegate = del;
            }

            public ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
                DateTime? expirationTime,
                string securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return _delegate(expirationTime, securityToken, validationParameters, callContext);
            }
        }

        private class LambdaTokenTypeValidator : ITokenTypeValidator
        {
            private readonly TokenTypeValidationDelegate _delegate;

            public LambdaTokenTypeValidator(TokenTypeValidationDelegate del)
            {
                _delegate = del;
            }

            public ValidationResult<ValidatedTokenType, ValidationError> ValidateTokenType(
                string? type,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return _delegate(type, securityToken, validationParameters, callContext);
            }
        }

        private class LambdaAudienceValidator : IAudienceValidator
        {
            private readonly AudienceValidationDelegate _delegate;

            public LambdaAudienceValidator(AudienceValidationDelegate del)
            {
                _delegate = del;
            }

            public ValidationResult<string, ValidationError> ValidateAudience(
                IList<string> tokenAudiences,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return _delegate(tokenAudiences, securityToken, validationParameters, callContext);
            }
        }

        private class LambdaIssuerValidator : IIssuerValidator
        {
            private readonly IssuerValidationDelegateAsync _delegate;

            public LambdaIssuerValidator(IssuerValidationDelegateAsync del)
            {
                _delegate = del;
            }

            public Task<ValidationResult<ValidatedIssuer, ValidationError>> ValidateIssuerAsync(
                string issuer,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext,
                CancellationToken cancellationToken)
            {
                return _delegate(issuer, securityToken, validationParameters, callContext, cancellationToken);
            }
        }

        private class LambdaDecryptionKeyResolver : IDecryptionKeyResolver
        {
            private readonly DecryptionKeyResolverDelegate _delegate;

            public LambdaDecryptionKeyResolver(DecryptionKeyResolverDelegate del)
            {
                _delegate = del;
            }

            public IList<SecurityKey> ResolveDecryptionKey(
                string token,
                SecurityToken securityToken,
                string kid,
                ValidationParameters validationParameters,
                CallContext? callContext)
            {
                return _delegate(token, securityToken, kid, validationParameters, callContext);
            }
        }
    }
}
#nullable restore
