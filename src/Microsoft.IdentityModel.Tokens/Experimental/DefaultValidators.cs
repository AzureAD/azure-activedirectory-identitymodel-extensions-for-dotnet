// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading;
using System;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental;

/// <summary>
/// Default implementation of <see cref="IAlgorithmValidator"/> that uses the static Validators.ValidateAlgorithm method.
/// </summary>
internal sealed class DefaultAlgorithmValidator : IAlgorithmValidator
{
    /// <inheritdoc/>
    public ValidationResult<string, ValidationError> ValidateAlgorithm(
        string? algorithm,
        SecurityToken securityToken,
        ValidationParameters validationParameters,
        CallContext callContext)
    {
        return Validators.ValidateAlgorithm(algorithm, securityToken, validationParameters, callContext);
    }
}

/// <summary>
/// Default implementation of <see cref="IAudienceValidator"/> that uses the static Validators.ValidateAudience method.
/// </summary>
internal sealed class DefaultAudienceValidator : IAudienceValidator
{
    /// <inheritdoc/>
    public ValidationResult<string, ValidationError> ValidateAudience(
        IList<string> tokenAudiences,
        SecurityToken? securityToken,
        ValidationParameters validationParameters,
        CallContext callContext)
    {
        return Validators.ValidateAudience(tokenAudiences, securityToken, validationParameters, callContext);
    }
}

/// <summary>
/// Default implementation of <see cref="IIssuerValidator"/> that uses the static Validators.ValidateIssuerAsync method.
/// </summary>
internal sealed class DefaultIssuerValidator : IIssuerValidator
{
    /// <inheritdoc/>
    public Task<ValidationResult<ValidatedIssuer, ValidationError>> ValidateIssuerAsync(
        string issuer,
        SecurityToken securityToken,
        ValidationParameters validationParameters,
        CallContext callContext,
        CancellationToken cancellationToken)
    {
        return Validators.ValidateIssuerAsync(issuer, securityToken, validationParameters, callContext, cancellationToken);
    }
}

/// <summary>
/// Default implementation of <see cref="ISignatureKeyValidator"/> that uses the static Validators.ValidateSignatureKey method.
/// </summary>
internal sealed class DefaultSignatureKeyValidator : ISignatureKeyValidator
{
    /// <inheritdoc/>
    public ValidationResult<ValidatedSignatureKey, ValidationError> ValidateSignatureKey(
        SecurityKey signingKey,
        SecurityToken securityToken,
        ValidationParameters validationParameters,
        CallContext callContext)
    {
        return Validators.ValidateSignatureKey(signingKey, securityToken, validationParameters, callContext);
    }
}

/// <summary>
/// Default implementation of <see cref="ILifetimeValidator"/> that uses the static Validators.ValidateLifetime method.
/// </summary>
internal sealed class DefaultLifetimeValidator : ILifetimeValidator
{
    /// <inheritdoc/>
    public ValidationResult<ValidatedLifetime, ValidationError> ValidateLifetime(
        DateTime? notBefore,
        DateTime? expires,
        SecurityToken? securityToken,
        ValidationParameters validationParameters,
        CallContext callContext)
    {
        return Validators.ValidateLifetime(notBefore, expires, securityToken, validationParameters, callContext);
    }
}

/// <summary>
/// Default implementation of <see cref="ITokenReplayValidator"/> that uses the static Validators.ValidateTokenReplay method.
/// </summary>
internal sealed class DefaultTokenReplayValidator : ITokenReplayValidator
{
    /// <inheritdoc/>
    public ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
        DateTime? expirationTime,
        string securityToken,
        ValidationParameters validationParameters,
        CallContext callContext)
    {
        return Validators.ValidateTokenReplay(expirationTime, securityToken, validationParameters, callContext);
    }
}

/// <summary>
/// Default implementation of <see cref="ITokenTypeValidator"/> that uses the static Validators.ValidateTokenType method.
/// </summary>
internal sealed class DefaultTokenTypeValidator : ITokenTypeValidator
{
    /// <inheritdoc/>
    public ValidationResult<ValidatedTokenType, ValidationError> ValidateTokenType(
        string? type,
        SecurityToken? securityToken,
        ValidationParameters validationParameters,
        CallContext callContext)
    {
        return Validators.ValidateTokenType(type, securityToken, validationParameters, callContext);
    }
}
#nullable restore
