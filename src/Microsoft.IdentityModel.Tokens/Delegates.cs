// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Validates the cryptographic algorithm used.
    /// </summary>
    /// <param name="algorithm">The algorithm to be validated.</param>
    /// <param name="securityKey">The <see cref="SecurityKey"/> used to sign the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <returns><see langword="true"/> if the algorithm is valid; otherwise, <see langword="false"/>.</returns>
    public delegate bool AlgorithmValidator(string algorithm, SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters);

    /// <summary>
    /// Validates the audiences found in the security token.
    /// </summary>
    /// <param name="audiences">The audiences found in the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <returns><see langword="true"/> if the audience is valid; otherwise, <see langword="false"/>.</returns>
    public delegate bool AudienceValidator(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters);

    /// <summary>
    /// Resolves the signing key used for validating a token's signature.
    /// </summary>
    /// <param name="token">The string representation of the token being validated.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated, which may be null.</param>
    /// <param name="kid">The key identifier, which may be null.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <returns>The <see cref="SecurityKey"/> used to validate the signature.</returns>
    /// <remarks>If both <see cref="IssuerSigningKeyResolverUsingConfiguration"/> and <see cref="IssuerSigningKeyResolver"/> are set, <see cref="IssuerSigningKeyResolverUsingConfiguration"/> takes priority.</remarks>
    public delegate IEnumerable<SecurityKey> IssuerSigningKeyResolver(string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters);

    /// <summary>
    /// Resolves the signing key using additional configuration.
    /// </summary>
    /// <param name="token">The string representation of the token being validated.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated, which may be null.</param>
    /// <param name="kid">The key identifier, which may be null.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <param name="configuration">The configuration required for validation.</param>
    /// <returns>The <see cref="SecurityKey"/> used to validate the signature.</returns>
    /// <remarks>If both <see cref="IssuerSigningKeyResolverUsingConfiguration"/> and <see cref="IssuerSigningKeyResolver"/> are set, <see cref="IssuerSigningKeyResolverUsingConfiguration"/> takes priority.</remarks>
    public delegate IEnumerable<SecurityKey> IssuerSigningKeyResolverUsingConfiguration(string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters, BaseConfiguration configuration);

    /// <summary>
    /// Validates the signing key used for the security token.
    /// </summary>
    /// <param name="securityKey">The <see cref="SecurityKey"/> used to sign the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <returns><see langword="true"/> if the signing key is valid; otherwise, <see langword="false"/>.</returns>
    public delegate bool IssuerSigningKeyValidator(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters);

    /// <summary>
    /// Validates the signing key using additional configuration.
    /// </summary>
    /// <param name="securityKey">The <see cref="SecurityKey"/> used to sign the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <param name="configuration">The configuration required for validation.</param>
    /// <returns><see langword="true"/> if the signing key is valid; otherwise, <see langword="false"/>.</returns>
    public delegate bool IssuerSigningKeyValidatorUsingConfiguration(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters, BaseConfiguration configuration);

    /// <summary>
    /// Validates the issuer of the security token.
    /// </summary>
    /// <param name="issuer">The issuer to be validated.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <returns>The validated issuer to use when creating claims.</returns>
    /// <remarks>The delegate should return a non-null string that represents the issuer. If null, a default value will be used. If both <see cref="IssuerValidatorUsingConfiguration"/> and <see cref="IssuerValidator"/> are set, <see cref="IssuerValidatorUsingConfiguration"/> takes priority.</remarks>
    public delegate string IssuerValidator(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters);

    /// <summary>
    /// Validates the issuer using additional configuration.
    /// </summary>
    /// <param name="issuer">The issuer to be validated.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <param name="configuration">The configuration required for validation.</param>
    /// <returns>The validated issuer to use when creating claims.</returns>
    /// <remarks>The delegate should return a non-null string that represents the issuer. If null, a default value will be used. If both <see cref="IssuerValidatorUsingConfiguration"/> and <see cref="IssuerValidator"/> are set, <see cref="IssuerValidatorUsingConfiguration"/> takes priority.</remarks>
    public delegate string IssuerValidatorUsingConfiguration(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters, BaseConfiguration configuration);

    /// <summary>
    /// Asynchronously validates the issuer of the security token.
    /// </summary>
    /// <param name="issuer">The issuer to be validated.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <returns>A task that represents the asynchronous operation, containing the validated issuer to use when creating claims.</returns>
    /// <remarks>The delegate should return a non-null string that represents the issuer. If null, a default value will be used. <see cref="IssuerValidatorAsync"/> will be called before <see cref="IssuerSigningKeyValidatorUsingConfiguration"/> or <see cref="IssuerSigningKeyValidator"/> if set.</remarks>
    internal delegate ValueTask<string> IssuerValidatorAsync(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters);

    /// <summary>
    /// Validates the lifetime of the security token.
    /// </summary>
    /// <param name="notBefore">The 'not before' time found in the <see cref="SecurityToken"/>.</param>
    /// <param name="expires">The 'expiration' time found in the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <returns><see langword="true"/> if the lifetime is valid; otherwise, <see langword="false"/>.</returns>
    public delegate bool LifetimeValidator(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters);

    /// <summary>
    /// Validates the replay of the security token.
    /// </summary>
    /// <param name="expirationTime">The 'expiration' time found in the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <returns><see langword="true"/> if the token replay is valid; otherwise, <see langword="false"/>.</returns>
    public delegate bool TokenReplayValidator(DateTime? expirationTime, string securityToken, TokenValidationParameters validationParameters);

    /// <summary>
    /// Validates the signature of the security token.
    /// </summary>
    /// <param name="token">The security token with a signature.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <returns>The validated <see cref="SecurityToken"/>.</returns>
    public delegate SecurityToken SignatureValidator(string token, TokenValidationParameters validationParameters);

    /// <summary>
    /// Validates the signature using additional configuration.
    /// </summary>
    /// <param name="token">The security token with a signature.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <param name="configuration">The configuration required for validation.</param>
    /// <returns>The validated <see cref="SecurityToken"/>.</returns>
    public delegate SecurityToken SignatureValidatorUsingConfiguration(string token, TokenValidationParameters validationParameters, BaseConfiguration configuration);

    /// <summary>
    /// Reads the security token.
    /// </summary>
    /// <param name="token">The security token.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <returns>The read <see cref="SecurityToken"/>.</returns>
    public delegate SecurityToken TokenReader(string token, TokenValidationParameters validationParameters);

    /// <summary>
    /// Resolves the decryption key for the security token.
    /// </summary>
    /// <param name="token">The string representation of the token to be decrypted.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> to be decrypted, which is null by default.</param>
    /// <param name="kid">The key identifier, which may be null.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <returns>The <see cref="SecurityKey"/> used to decrypt the token.</returns>
    public delegate IEnumerable<SecurityKey> TokenDecryptionKeyResolver(string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters);

    /// <summary>
    /// Validates the type of the security token.
    /// </summary>
    /// <param name="type">The token type to be validated.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <returns>The actual token type, which may be the same as <paramref name="type"/> or a different value if the token type was resolved from a different location.</returns>
    public delegate string TypeValidator(string type, SecurityToken securityToken, TokenValidationParameters validationParameters);

    /// <summary>
    /// Transforms the security token before signature validation.
    /// </summary>
    /// <param name="token">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
    /// <returns>The transformed <see cref="SecurityToken"/>.</returns>
    public delegate SecurityToken TransformBeforeSignatureValidation(SecurityToken token, TokenValidationParameters validationParameters);

    /// <summary>
    /// When JSON Web Token header or payload is being read claim by claim,
    /// this delegate is called after all claims known to the library have been processed.
    /// When called, the reader is positioned at the claim value.
    /// </summary>
    /// <remarks>
    /// An example implementation:
    /// <code>
    /// bool TryReadJwtClaim(ref Utf8JsonReader reader, JwtSegmentType jwtSegmentType, string claimName, out object claimValue)
    /// {
    ///     if (jwtSegmentType == JwtSegmentType.Payload &amp;&amp; claimName == "CustomClaimName")
    ///         claimValue = JsonSerializer.Deserialize&lt;CustomClaim&gt;(reader.GetString());
    ///         return true;
    ///     return false;
    /// }
    /// </code>
    /// </remarks>
    /// <param name="reader">Reader for the underlying token bytes.</param>
    /// <param name="jwtSegmentType">Specifies whether the claim is from the JWT header or payload.</param>
    /// <param name="claimName">The claim name for this claim value.</param>
    /// <param name="claimValue">The claim value that was read and parsed from the reader.</param>
    /// <returns>True, if the claim value was read successfully; false otherwise.</returns>
    public delegate bool TryReadJwtClaim(ref Utf8JsonReader reader, JwtSegmentType jwtSegmentType, string claimName, out object claimValue);

#nullable enable
    /// <summary>
    /// Definition for delegate that will validate a given algorithm for a <see cref="SecurityKey"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm to be validated.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
    /// <param name="callContext"></param>
    /// <returns>A <see cref="ValidationResult{TResult, TError}"/>that contains the results of validating the algorithm.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
    public delegate ValidationResult<string, ValidationError> AlgorithmValidationDelegate(
        string? algorithm,
        SecurityToken securityToken,
        ValidationParameters validationParameters,
        CallContext callContext);

    /// <summary>
    /// Definition for delegate that will validate the audiences value in a token.
    /// </summary>
    /// <param name="tokenAudiences">The audiences found in the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
    /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
    /// <param name="callContext"></param>
    /// <returns>A <see cref="ValidationResult{TResult, TError}"/>that contains the results of validating the issuer.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
    public delegate ValidationResult<string, ValidationError> AudienceValidationDelegate(
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
    /// <returns>A <see cref="ValidationResult{TResult, TError}"/> that contains the results of validating the issuer.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
    public delegate Task<ValidationResult<ValidatedIssuer, ValidationError>> IssuerValidationDelegateAsync(
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
    /// <returns>A <see cref="ValidationResult{TResult, TError}"/>that contains the results of validating the issuer.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
    public delegate ValidationResult<ValidatedSignatureKey, ValidationError> SignatureKeyValidationDelegate(
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
    /// <returns>A <see cref="ValidationResult{TResult, TError}"/> that contains the results of validating the issuer.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
    public delegate ValidationResult<ValidatedLifetime, ValidationError> LifetimeValidationDelegate(
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
    /// <returns>A <see cref="ValidationResult{TResult, TError}"/> that contains the results of validating the token.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
    public delegate ValidationResult<DateTime?, ValidationError> TokenReplayValidationDelegate(
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
    /// <returns> A <see cref="ValidationResult{TResult, TError}"/>that contains the results of validating the token type.</returns>
    /// <remarks>An EXACT match is required. <see cref="StringComparison.Ordinal"/> (case sensitive) is used for comparing <paramref name="type"/> against <see cref="ValidationParameters.ValidTypes"/>.</remarks>
    public delegate ValidationResult<ValidatedTokenType, ValidationError> TokenTypeValidationDelegate(
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
    public delegate SecurityKey? SignatureKeyResolverDelegate(
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
    public delegate IList<SecurityKey> DecryptionKeyResolverDelegate(
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
    public delegate ValidationResult<SecurityKey, ValidationError> SignatureValidationDelegate(
        SecurityToken token,
        ValidationParameters validationParameters,
        BaseConfiguration? configuration,
        CallContext callContext);
#nullable restore
}
