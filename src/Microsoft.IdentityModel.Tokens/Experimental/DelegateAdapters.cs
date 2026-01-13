// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Adapter class that wraps an <see cref="AlgorithmValidationDelegate"/> to implement <see cref="IAlgorithmValidator"/>.
    /// </summary>
    internal class DelegateAlgorithmValidator : IAlgorithmValidator
    {
        private readonly AlgorithmValidationDelegate _delegate;

        public DelegateAlgorithmValidator(AlgorithmValidationDelegate del)
        {
            _delegate = del ?? throw new ArgumentNullException(nameof(del));
        }

        public ValidationResult<string, ValidationError> ValidateAlgorithm(
            string? algorithm,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return _delegate(algorithm, securityToken, validationParameters, callContext);
        }

        public static implicit operator DelegateAlgorithmValidator(AlgorithmValidationDelegate del)
        {
            return new DelegateAlgorithmValidator(del);
        }
    }

    /// <summary>
    /// Adapter class that wraps an <see cref="AudienceValidationDelegate"/> to implement <see cref="IAudienceValidator"/>.
    /// </summary>
    internal class DelegateAudienceValidator : IAudienceValidator
    {
        private readonly AudienceValidationDelegate _delegate;

        public DelegateAudienceValidator(AudienceValidationDelegate del)
        {
            _delegate = del ?? throw new ArgumentNullException(nameof(del));
        }

        public ValidationResult<string, ValidationError> ValidateAudience(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return _delegate(tokenAudiences, securityToken, validationParameters, callContext);
        }

        public static implicit operator DelegateAudienceValidator(AudienceValidationDelegate del)
        {
            return new DelegateAudienceValidator(del);
        }
    }

    /// <summary>
    /// Adapter class that wraps an <see cref="IssuerValidationDelegateAsync"/> to implement <see cref="IIssuerValidator"/>.
    /// </summary>
    internal class DelegateIssuerValidator : IIssuerValidator
    {
        private readonly IssuerValidationDelegateAsync _delegate;

        public DelegateIssuerValidator(IssuerValidationDelegateAsync del)
        {
            _delegate = del ?? throw new ArgumentNullException(nameof(del));
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

        public static implicit operator DelegateIssuerValidator(IssuerValidationDelegateAsync del)
        {
            return new DelegateIssuerValidator(del);
        }
    }

    /// <summary>
    /// Adapter class that wraps a <see cref="SignatureKeyValidationDelegate"/> to implement <see cref="ISignatureKeyValidator"/>.
    /// </summary>
    internal class DelegateSignatureKeyValidator : ISignatureKeyValidator
    {
        private readonly SignatureKeyValidationDelegate _delegate;

        public DelegateSignatureKeyValidator(SignatureKeyValidationDelegate del)
        {
            _delegate = del ?? throw new ArgumentNullException(nameof(del));
        }

        public ValidationResult<ValidatedSignatureKey, ValidationError> ValidateSignatureKey(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return _delegate(signingKey, securityToken, validationParameters, callContext);
        }

        public static implicit operator DelegateSignatureKeyValidator(SignatureKeyValidationDelegate del)
        {
            return new DelegateSignatureKeyValidator(del);
        }
    }

    /// <summary>
    /// Adapter class that wraps a <see cref="LifetimeValidationDelegate"/> to implement <see cref="ILifetimeValidator"/>.
    /// </summary>
    internal class DelegateLifetimeValidator : ILifetimeValidator
    {
        private readonly LifetimeValidationDelegate _delegate;

        public DelegateLifetimeValidator(LifetimeValidationDelegate del)
        {
            _delegate = del ?? throw new ArgumentNullException(nameof(del));
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

        public static implicit operator DelegateLifetimeValidator(LifetimeValidationDelegate del)
        {
            return new DelegateLifetimeValidator(del);
        }
    }

    /// <summary>
    /// Adapter class that wraps a <see cref="TokenReplayValidationDelegate"/> to implement <see cref="ITokenReplayValidator"/>.
    /// </summary>
    internal class DelegateTokenReplayValidator : ITokenReplayValidator
    {
        private readonly TokenReplayValidationDelegate _delegate;

        public DelegateTokenReplayValidator(TokenReplayValidationDelegate del)
        {
            _delegate = del ?? throw new ArgumentNullException(nameof(del));
        }

        public ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return _delegate(expirationTime, securityToken, validationParameters, callContext);
        }

        public static implicit operator DelegateTokenReplayValidator(TokenReplayValidationDelegate del)
        {
            return new DelegateTokenReplayValidator(del);
        }
    }

    /// <summary>
    /// Adapter class that wraps a <see cref="TokenTypeValidationDelegate"/> to implement <see cref="ITokenTypeValidator"/>.
    /// </summary>
    internal class DelegateTokenTypeValidator : ITokenTypeValidator
    {
        private readonly TokenTypeValidationDelegate _delegate;

        public DelegateTokenTypeValidator(TokenTypeValidationDelegate del)
        {
            _delegate = del ?? throw new ArgumentNullException(nameof(del));
        }

        public ValidationResult<ValidatedTokenType, ValidationError> ValidateTokenType(
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return _delegate(type, securityToken, validationParameters, callContext);
        }

        public static implicit operator DelegateTokenTypeValidator(TokenTypeValidationDelegate del)
        {
            return new DelegateTokenTypeValidator(del);
        }
    }

    /// <summary>
    /// Adapter class that wraps a <see cref="SignatureValidationDelegate"/> to implement <see cref="ISignatureValidator"/>.
    /// </summary>
    internal class DelegateSignatureValidator : ISignatureValidator
    {
        private readonly SignatureValidationDelegate _delegate;

        public DelegateSignatureValidator(SignatureValidationDelegate del)
        {
            _delegate = del ?? throw new ArgumentNullException(nameof(del));
        }

        public ValidationResult<SecurityKey, ValidationError> ValidateSignature(
            SecurityToken token,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return _delegate(token, validationParameters, configuration, callContext);
        }

        public static implicit operator DelegateSignatureValidator(SignatureValidationDelegate del)
        {
            return new DelegateSignatureValidator(del);
        }
    }

    /// <summary>
    /// Adapter class that wraps a <see cref="SignatureKeyResolverDelegate"/> to implement <see cref="ISignatureKeyResolver"/>.
    /// </summary>
    internal class DelegateSignatureKeyResolver : ISignatureKeyResolver
    {
        private readonly SignatureKeyResolverDelegate _delegate;

        public DelegateSignatureKeyResolver(SignatureKeyResolverDelegate del)
        {
            _delegate = del ?? throw new ArgumentNullException(nameof(del));
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

        public static implicit operator DelegateSignatureKeyResolver(SignatureKeyResolverDelegate del)
        {
            return new DelegateSignatureKeyResolver(del);
        }
    }

    /// <summary>
    /// Adapter class that wraps a <see cref="DecryptionKeyResolverDelegate"/> to implement <see cref="IDecryptionKeyResolver"/>.
    /// </summary>
    internal class DelegateDecryptionKeyResolver : IDecryptionKeyResolver
    {
        private readonly DecryptionKeyResolverDelegate _delegate;

        public DelegateDecryptionKeyResolver(DecryptionKeyResolverDelegate del)
        {
            _delegate = del ?? throw new ArgumentNullException(nameof(del));
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

        public static implicit operator DelegateDecryptionKeyResolver(DecryptionKeyResolverDelegate del)
        {
            return new DelegateDecryptionKeyResolver(del);
        }
    }
}
#nullable restore
