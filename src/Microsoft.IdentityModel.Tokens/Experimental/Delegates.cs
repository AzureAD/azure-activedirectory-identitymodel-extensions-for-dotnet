// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading;
using System;
using Microsoft.Identity.Abstractions;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Definition for delegate that will validate a given algorithm for a <see cref="SecurityKey"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm to be validated.</param>
    /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
    /// <param name="callContext"></param>
    /// <returns>A <see cref="OperationResult{TResult, TError}"/>that contains the results of validating the algorithm.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
#pragma warning disable RS0016 // Add public types and members to the declared API
    public delegate OperationResult<string, ValidationError> AlgorithmValidationDelegate(
#pragma warning restore RS0016 // Add public types and members to the declared API
        string algorithm,
        SecurityKey securityKey,
        SecurityToken securityToken,
        ValidationParameters validationParameters,
        CallContext callContext);

    /// <summary>
    /// Definition for delegate that will validate the audiences value in a token.
    /// </summary>
    /// <param name="tokenAudiences">The audiences found in the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <param name="callContext"></param>
    /// <returns>A <see cref="OperationResult{TResult, TError}"/>that contains the results of validating the issuer.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
#pragma warning disable RS0016 // Add public types and members to the declared API
    public delegate OperationResult<string, ValidationError> AudienceValidationDelegate(
#pragma warning restore RS0016 // Add public types and members to the declared API
        IList<string> tokenAudiences,
        SecurityToken? securityToken,
        ValidationParameters validationParameters,
        CallContext callContext);

    /// <summary>
    /// Definition for delegate that will validate the issuer value in a token.
    /// </summary>
    /// <param name="issuer">The issuer to validate.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
    /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
    /// <param name="callContext"></param>
    /// <param name="cancellationToken"></param>
    /// <returns>A <see cref="OperationResult{TResult, TError}"/> that contains the results of validating the issuer.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
#pragma warning disable RS0016 // Add public types and members to the declared API
    public delegate Task<OperationResult<ValidatedIssuer, ValidationError>> IssuerValidationDelegateAsync(
#pragma warning restore RS0016 // Add public types and members to the declared API
        string issuer,
        SecurityToken securityToken,
        ValidationParameters validationParameters,
        CallContext callContext,
        CancellationToken cancellationToken);

    /// <summary>
    /// Definition for delegate that will validate the <see cref="SecurityKey"/> that signed a <see cref="SecurityToken"/>.
    /// </summary>
    /// <param name="signingKey">The security key to validate.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
    /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
    /// <param name="callContext">The <see cref="CallContext"/> to be used for logging.</param> 
    /// <returns>A <see cref="OperationResult{TResult, TError}"/>that contains the results of validating the issuer.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
#pragma warning disable RS0016 // Add public types and members to the declared API
    public delegate OperationResult<ValidatedSigningKeyLifetime, ValidationError> IssuerSigningKeyValidationDelegate(
#pragma warning restore RS0016 // Add public types and members to the declared API
        SecurityKey signingKey,
        SecurityToken securityToken,
        ValidationParameters validationParameters,
        CallContext callContext);

    /// <summary>
    /// Definition for delegate that will validate the lifetime of a <see cref="SecurityToken"/>.
    /// </summary>
    /// <param name="notBefore">The 'notBefore' time found in the <see cref="SecurityToken"/>.</param>
    /// <param name="expires">The 'expiration' time found in the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <param name="callContext">The <see cref="CallContext"/> that contains call information.</param>
    /// <returns>A <see cref="OperationResult{TResult, TError}"/> that contains the results of validating the issuer.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
#pragma warning disable RS0016 // Add public types and members to the declared API
    public delegate OperationResult<ValidatedLifetime, ValidationError> LifetimeValidationDelegate(
#pragma warning restore RS0016 // Add public types and members to the declared API
        DateTime? notBefore,
        DateTime? expires,
        SecurityToken? securityToken,
        ValidationParameters validationParameters,
        CallContext callContext);

    /// <summary>
    /// Definition for delegate that will validate that a <see cref="SecurityToken"/> has not been replayed.
    /// </summary>
    /// <param name="expirationTime">When does the <see cref="SecurityToken"/> expire..</param>
    /// <param name="securityToken">The security token that is being validated.</param>
    /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
    /// <param name="callContext">The <see cref="CallContext"/> that contains call information.</param>
    /// <returns>A <see cref="OperationResult{TResult, TError}"/> that contains the results of validating the token.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
#pragma warning disable RS0016 // Add public types and members to the declared API
    public delegate OperationResult<DateTime?, ValidationError> TokenReplayValidationDelegate(
#pragma warning restore RS0016 // Add public types and members to the declared API
        DateTime? expirationTime,
        string securityToken,
        ValidationParameters validationParameters,
        CallContext callContext);

    /// <summary>
    /// Definition for delegate that will validate the token type of a token.
    /// </summary>
    /// <param name="type">The token type or <c>null</c> if it couldn't be resolved (e.g from the 'typ' header for a JWT).</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
    /// <param name="validationParameters"><see cref="ValidationParameters"/> required for validation.</param>
    /// <param name="callContext">The <see cref="CallContext"/> that contains call information.</param>
    /// <returns> A <see cref="OperationResult{TResult, TError}"/>that contains the results of validating the token type.</returns>
    /// <remarks>An EXACT match is required. <see cref="StringComparison.Ordinal"/> (case sensitive) is used for comparing <paramref name="type"/> against <see cref="ValidationParameters.ValidTypes"/>.</remarks>
#pragma warning disable RS0016 // Add public types and members to the declared API
    public delegate OperationResult<ValidatedTokenType, ValidationError> TokenTypeValidationDelegate(
#pragma warning restore RS0016 // Add public types and members to the declared API
        string? type,
        SecurityToken? securityToken,
        ValidationParameters validationParameters,
        CallContext callContext);

    /// <summary>
    /// Resolves the signing key used for validating a token's signature.
    /// </summary>
    /// <param name="token">The string representation of the token being validated.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated, which may be null.</param>
    /// <param name="kid">The key identifier, which may be null.</param>
    /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
    /// <param name="configuration">The <see cref="BaseConfiguration"/> to be used for validating the token.</param>
    /// <param name="callContext">The <see cref="CallContext"/> used for logging.</param>
    /// <returns>The <see cref="SecurityKey"/> used to validate the signature.</returns>
    /// <remarks>If both <see cref="IssuerSigningKeyResolverUsingConfiguration"/> and <see cref="IssuerSigningKeyResolver"/> are set, <see cref="IssuerSigningKeyResolverUsingConfiguration"/> takes priority.</remarks>
#pragma warning disable RS0016 // Add public types and members to the declared API
    public delegate SecurityKey? IssuerSigningKeyResolverDelegate(
#pragma warning restore RS0016 // Add public types and members to the declared API
        string token,
        SecurityToken? securityToken,
        string? kid,
        ValidationParameters validationParameters,
        BaseConfiguration? configuration,
        CallContext? callContext);

    /// <summary>
    /// Resolves the decryption key for the security token.
    /// </summary>
    /// <param name="token">The string representation of the token to be decrypted.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> to be decrypted, which is null by default.</param>
    /// <param name="kid">The key identifier, which may be null.</param>
    /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
    /// <param name="callContext">The <see cref="CallContext"/> to be used for logging.</param>
    /// <returns>The <see cref="SecurityKey"/> used to decrypt the token.</returns>
#pragma warning disable RS0016 // Add public types and members to the declared API
    public delegate IList<SecurityKey> DecryptionKeyResolverDelegate(
#pragma warning restore RS0016 // Add public types and members to the declared API
        string token,
        SecurityToken securityToken,
        string kid,
        ValidationParameters validationParameters,
        CallContext? callContext);

    /// <summary>
    /// Validates the signature of the security token.
    /// </summary>
    /// <param name="token">The <see cref="SecurityToken"/> with a signature.</param>
    /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
    /// <param name="configuration">The <see cref="BaseConfiguration"/> to be used for validating the token.</param>
    /// <param name="callContext">The <see cref="CallContext"/> to be used for logging.</param>
    /// <remarks>This method is not expected to throw.</remarks>
    /// <returns>The validated <see cref="SecurityToken"/>.</returns>
#pragma warning disable RS0016 // Add public types and members to the declared API
    public delegate OperationResult<SecurityKey, ValidationError> SignatureValidationDelegate(
#pragma warning restore RS0016 // Add public types and members to the declared API
        SecurityToken token,
        ValidationParameters validationParameters,
        BaseConfiguration? configuration,
        CallContext callContext);
#nullable restore
}
