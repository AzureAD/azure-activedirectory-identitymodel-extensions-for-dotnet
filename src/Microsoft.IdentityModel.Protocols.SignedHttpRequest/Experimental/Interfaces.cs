// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest
{
    /// <summary>Resolves the PoP key instead of the default confirmation-claim processing.</summary>
    public interface IPopKeyResolver
    {
        /// <summary>Returns the resolved key or a validation error. Implementations should not throw except for cancellation.</summary>
        /// <param name="validatedAccessToken">The validated access token.</param>
        /// <param name="signedHttpRequest">The SHR being validated.</param>
        /// <param name="validationContext">The validation context.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        Task<ValidationResult<SecurityKey, ValidationError>> ResolvePopKeyAsync(SecurityToken validatedAccessToken, SecurityToken signedHttpRequest, SignedHttpRequestValidationContext validationContext, CancellationToken cancellationToken);
    }

    /// <summary>Resolves a confirmation key by key ID.</summary>
    public interface IPopKeyResolverFromKeyId
    {
        /// <summary>Returns the resolved key or a validation error. Implementations should not throw except for cancellation.</summary>
        /// <param name="kid">The key ID.</param>
        /// <param name="validatedAccessToken">The validated access token.</param>
        /// <param name="signedHttpRequest">The SHR, or null while resolving a thumbprint reference.</param>
        /// <param name="validationContext">The validation context.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        Task<ValidationResult<SecurityKey, ValidationError>> ResolvePopKeyFromKeyIdAsync(string kid, SecurityToken validatedAccessToken, SecurityToken? signedHttpRequest, SignedHttpRequestValidationContext validationContext, CancellationToken cancellationToken);
    }

    /// <summary>Resolves keys for decrypting an encrypted confirmation key.</summary>
    public interface ICnfDecryptionKeysResolver
    {
        /// <summary>Returns decryption keys or a validation error.</summary>
        /// <param name="jweCnf">The encrypted confirmation key.</param>
        /// <param name="validationContext">The validation context.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        Task<ValidationResult<IList<SecurityKey>, ValidationError>> ResolveDecryptionKeysAsync(SecurityToken jweCnf, SignedHttpRequestValidationContext validationContext, CancellationToken cancellationToken);
    }

    /// <summary>Overrides SHR signature verification.</summary>
    public interface ISignedHttpRequestSignatureValidator
    {
        /// <summary>Returns the key that verified the signature or a validation error.</summary>
        /// <param name="popKey">The resolved PoP key.</param>
        /// <param name="signedHttpRequest">The SHR.</param>
        /// <param name="validationContext">The validation context.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        Task<ValidationResult<SecurityKey, ValidationError>> ValidateSignatureAsync(SecurityKey popKey, SecurityToken signedHttpRequest, SignedHttpRequestValidationContext validationContext, CancellationToken cancellationToken);
    }

    /// <summary>Validates the SHR nonce.</summary>
    public interface INonceValidator
    {
        /// <summary>Returns true on success or a validation error on failure. A false result is rejected.</summary>
        /// <param name="popKey">The resolved PoP key.</param>
        /// <param name="signedHttpRequest">The SHR.</param>
        /// <param name="validationContext">The validation context.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        Task<ValidationResult<bool, ValidationError>> ValidateNonceAsync(SecurityKey popKey, SecurityToken signedHttpRequest, SignedHttpRequestValidationContext validationContext, CancellationToken cancellationToken);
    }

    /// <summary>Validates SHR replay using an application-owned cache or policy.</summary>
    public interface IReplayValidator
    {
        /// <summary>Returns true on success or a validation error on replay. A false result is rejected.</summary>
        /// <param name="signedHttpRequest">The SHR.</param>
        /// <param name="validationContext">The validation context.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        Task<ValidationResult<bool, ValidationError>> ValidateReplayAsync(SecurityToken signedHttpRequest, SignedHttpRequestValidationContext validationContext, CancellationToken cancellationToken);
    }
}
