// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading;
using System;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Interface for validating algorithms used with <see cref="SecurityKey"/>.
    /// </summary>
    public interface IAlgorithmValidator
    {
        /// <summary>
        /// Validates a given algorithm for a <see cref="SecurityKey"/>.
        /// </summary>
        /// <param name="algorithm">The algorithm to be validated.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="ValidationParameters"/> required for validation.</param>
        /// <param name="callContext">The <see cref="CallContext"/> to be used for logging.</param>
        /// <returns>A <see cref="ValidationResult{TResult, TError}"/>that contains the results of validating the algorithm.</returns>
        /// <remarks>This method is not expected to throw.</remarks>
        ValidationResult<string, ValidationError> ValidateAlgorithm(
            string? algorithm,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext);
    }

    /// <summary>
    /// Interface for validating token audiences.
    /// </summary>
    public interface IAudienceValidator
    {
        /// <summary>
        /// Validates the audiences value in a token.
        /// </summary>
        /// <param name="tokenAudiences">The audiences found in the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">The <see cref="CallContext"/> to be used for logging.</param>
        /// <returns>A <see cref="ValidationResult{TResult, TError}"/>that contains the results of validating the issuer.</returns>
        /// <remarks>This method is not expected to throw.</remarks>
        ValidationResult<string, ValidationError> ValidateAudience(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext);
    }

    /// <summary>
    /// Interface for validating token issuers.
    /// </summary>
    public interface IIssuerValidator
    {
        /// <summary>
        /// Validates the issuer value in a token.
        /// </summary>
        /// <param name="issuer">The issuer to validate.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">The <see cref="CallContext"/> to be used for logging.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A <see cref="ValidationResult{TResult, TError}"/> that contains the results of validating the issuer.</returns>
        /// <remarks>This method is not expected to throw.</remarks>
        Task<ValidationResult<ValidatedIssuer, ValidationError>> ValidateIssuerAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken);
    }

    /// <summary>
    /// Interface for validating signature keys.
    /// </summary>
    public interface ISignatureKeyValidator
    {
        /// <summary>
        /// Validates the <see cref="SecurityKey"/> that signed a <see cref="SecurityToken"/>.
        /// </summary>
        /// <param name="signingKey">The security key to validate.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">The <see cref="CallContext"/> to be used for logging.</param> 
        /// <returns>A <see cref="ValidationResult{TResult, TError}"/>that contains the results of validating the issuer.</returns>
        /// <remarks>This method is not expected to throw.</remarks>
        ValidationResult<ValidatedSignatureKey, ValidationError> ValidateSignatureKey(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext);
    }

    /// <summary>
    /// Interface for validating token lifetime.
    /// </summary>
    public interface ILifetimeValidator
    {
        /// <summary>
        /// Validates the lifetime of a <see cref="SecurityToken"/>.
        /// </summary>
        /// <param name="notBefore">The 'notBefore' time found in the <see cref="SecurityToken"/>.</param>
        /// <param name="expires">The 'expiration' time found in the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">The <see cref="CallContext"/> that contains call information.</param>
        /// <returns>A <see cref="ValidationResult{TResult, TError}"/> that contains the results of validating the issuer.</returns>
        /// <remarks>This method is not expected to throw.</remarks>
        ValidationResult<ValidatedLifetime, ValidationError> ValidateLifetime(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext);
    }

    /// <summary>
    /// Interface for validating token replay.
    /// </summary>
    public interface ITokenReplayValidator
    {
        /// <summary>
        /// Validates that a <see cref="SecurityToken"/> has not been replayed.
        /// </summary>
        /// <param name="expirationTime">When does the <see cref="SecurityToken"/> expire..</param>
        /// <param name="securityToken">The security token that is being validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">The <see cref="CallContext"/> that contains call information.</param>
        /// <returns>A <see cref="ValidationResult{TResult, TError}"/> that contains the results of validating the token.</returns>
        /// <remarks>This method is not expected to throw.</remarks>
        ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext);
    }

    /// <summary>
    /// Interface for validating token type.
    /// </summary>
    public interface ITokenTypeValidator
    {
        /// <summary>
        /// Validates the token type of a token.
        /// </summary>
        /// <param name="type">The token type or <c>null</c> if it couldn't be resolved (e.g from the 'typ' header for a JWT).</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters"><see cref="ValidationParameters"/> required for validation.</param>
        /// <param name="callContext">The <see cref="CallContext"/> that contains call information.</param>
        /// <returns> A <see cref="ValidationResult{TResult, TError}"/> that contains the results of validating the token type.</returns>
        /// <remarks>An EXACT match is required. <see cref="StringComparison.Ordinal"/> (case sensitive) is used for comparing <paramref name="type"/> against <see cref="ValidationParameters.ValidTypes"/>.</remarks>
        ValidationResult<ValidatedTokenType, ValidationError> ValidateTokenType(
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext);
    }

    /// <summary>
    /// Interface for resolving signing keys.
    /// </summary>
    public interface ISignatureKeyResolver
    {
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
        SecurityKey? ResolveSignatureKey(
            string token,
            SecurityToken? securityToken,
            string? kid,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext? callContext);
    }

    /// <summary>
    /// Interface for resolving decryption keys.
    /// </summary>
    public interface IDecryptionKeyResolver
    {
        /// <summary>
        /// Resolves the decryption key for the security token.
        /// </summary>
        /// <param name="token">The string representation of the token to be decrypted.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> to be decrypted, which is null by default.</param>
        /// <param name="kid">The key identifier, which may be null.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext">The <see cref="CallContext"/> to be used for logging.</param>
        /// <returns>The <see cref="SecurityKey"/> used to decrypt the token.</returns>
        IList<SecurityKey> ResolveDecryptionKey(
            string token,
            SecurityToken securityToken,
            string kid,
            ValidationParameters validationParameters,
            CallContext? callContext);
    }

    /// <summary>
    /// Interface for validating signatures.
    /// </summary>
    public interface ISignatureValidator
    {
        /// <summary>
        /// Validates the signature of the security token.
        /// </summary>
        /// <param name="token">The <see cref="SecurityToken"/> with a signature.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="configuration">The <see cref="BaseConfiguration"/> to be used for validating the token.</param>
        /// <param name="callContext">The <see cref="CallContext"/> to be used for logging.</param>
        /// <remarks>This method is not expected to throw.</remarks>
        /// <returns>A <see cref="ValidationResult{TResult, TError}"/> containing the <see cref="SecurityKey"/> used to validate the signature.</returns>
        ValidationResult<SecurityKey, ValidationError> ValidateSignature(
            SecurityToken token,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext);
    }
}
#nullable restore
