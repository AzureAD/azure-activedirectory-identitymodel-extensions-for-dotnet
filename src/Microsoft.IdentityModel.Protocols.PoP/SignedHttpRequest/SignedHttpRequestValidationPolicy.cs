//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using ClaimTypes = Microsoft.IdentityModel.Protocols.Pop.PopConstants.SignedHttpRequest.ClaimTypes;

namespace Microsoft.IdentityModel.Protocols.Pop.SignedHttpRequest
{
    /// <summary>
    /// A delegate that will be called to validate a custom claim, if set. 
    /// </summary>
    /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
    /// <param name="validatedAccessToken">An access token ("at") that was already validated during SignedHttpRequest validation process.</param>
    /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>Expected to throw an appropriate exception if custom claim validation failed.</returns>
    public delegate Task AdditionalClaimValidatorAsync(SecurityToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken);

    /// <summary>
    /// A delegate that will be called to retrieve a collection of <see cref="SecurityKey"/>s used for the 'cnf' claim decryption.
    /// </summary>
    /// <param name="jweCnf">A 'cnf' claim represented as a <see cref="SecurityToken"/>.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns></returns>
    public delegate Task<IEnumerable<SecurityKey>> CnfDecryptionKeysResolverAsync(SecurityToken jweCnf, CancellationToken cancellationToken);

    /// <summary>
    /// A delegate that will take control over PoP key resolution, if set.
    /// </summary>
    /// <param name="validatedAccessToken">An access token ("at") that was already validated during SignedHttpRequest validation process.</param>
    /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.></param>
    /// <returns>A resolved <see cref="SecurityKey"/>.</returns>
    public delegate Task<SecurityKey> PopKeyResolverAsync(SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken);

    /// <summary>
    /// A delegate that will be called to resolve a <see cref="SecurityKey"/> from a 'cnf' claim that contains only the 'kid' claim.
    /// </summary>
    /// <param name="kid">KeyIdentifier value.</param>
    /// <param name="validatedAccessToken">An access token ("at") that was already validated during SignedHttpRequest validation process.</param>
    /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns></returns>
    /// <remarks>https://tools.ietf.org/html/rfc7800#section-3.4</remarks>
    public delegate Task<SecurityKey> PopKeyResolverFromKeyIdAsync(string kid, SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken);

    /// <summary>
    /// A delegate that will be called to check if SignedHttpRequest is replayed, if set.
    /// </summary>
    /// <param name="nonce">A value of the 'nonce' claim. Value will be <see cref="string.Empty"/> if 'nonce' claim is not found.</param>
    /// <param name="signedHttpRequest">SignedHttpRequest.</param>
    /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>Expected to throw an appropriate exception if SignedHttpRequest replay is detected.</returns>
    public delegate Task SignedHttpRequestReplayValidatorAsync(string nonce, SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken);

    /// <summary>
    /// A delegate that will take control over SignedHttpRequest signature validation, if set.
    /// </summary>
    /// <param name="popKey">A resolved PoP key.</param>
    /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
    /// <param name="validatedAccessToken">An access token ("at") that was already validated during SignedHttpRequest validation process.</param>
    /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>Expected to throw an appropriate exception if SignedHttpRequest has invalid signature.</returns>
    public delegate Task SignedHttpRequestSignatureValidatorAsync(SecurityKey popKey, SecurityToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken);

    /// <summary>
    /// Defines a policy for validating signed http requests. 
    /// </summary>
    public class SignedHttpRequestValidationPolicy
    {
        private TimeSpan _signedHttpRequestLifetime = DefaultSignedHttpRequestLifetime;

        /// <summary>
        /// Gets or sets a value indicating whether the uncovered query parameters are accepted or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-5.1</remarks>
        public bool AcceptUncoveredQueryParameters { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the uncovered headers are accepted or not. 
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-5.1</remarks>
        public bool AcceptUncoveredHeaders { get; set; } = true;

        /// <summary>
        /// Gets or sets the <see cref="AdditionalClaimValidatorAsync"/> delegate.
        /// </summary>
        public AdditionalClaimValidatorAsync AdditionalClaimValidatorAsync { get; set; }

        /// <summary>
        /// Gets or sets a collection of <see cref="SecurityKey"/> used for the 'cnf' claim decryption.
        /// </summary>
        public IEnumerable<SecurityKey> CnfDecryptionKeys { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="SignedHttpRequestSignatureValidatorAsync"/> delegate.
        /// </summary>
        public CnfDecryptionKeysResolverAsync CnfDecryptionKeysResolverAsync { get; set; }

        /// <summary>
        /// Default value for the <see cref="SignedHttpRequestLifetime"/>.
        /// </summary>
        public static readonly TimeSpan DefaultSignedHttpRequestLifetime = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Gets or sets a custom HttpClient when obtaining a JWK set using the 'jku' claim.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/rfc7800#section-3.5</remarks> s
        public HttpClient HttpClientForJkuResourceRetrieval { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="PopKeyResolverAsync"/> delegate.
        /// </summary>
        public PopKeyResolverAsync PopKeyResolverAsync { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="PopKeyResolverFromKeyIdAsync"/> delegate.
        /// </summary>
        public PopKeyResolverFromKeyIdAsync PopKeyResolverFromKeyIdAsync { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether TLS is required when obtaining a JWK set using the 'jku' claim.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/rfc7800#section-3.5</remarks>
        public bool RequireHttpsForJkuResourceRetrieval { get; set; } = true;

        /// <summary>
        /// Gets or sets the signed http request lifetime.
        /// </summary>
        public TimeSpan SignedHttpRequestLifetime
        {
            get
            {
                return _signedHttpRequestLifetime;
            }

            set
            {
                if (value < TimeSpan.Zero)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(value)));

                _signedHttpRequestLifetime = value;
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="SignedHttpRequestReplayValidatorAsync"/> delegate.
        /// </summary>
        public SignedHttpRequestReplayValidatorAsync SignedHttpRequestReplayValidatorAsync { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="SignedHttpRequestSignatureValidatorAsync"/> delegate.
        /// </summary>
        public SignedHttpRequestSignatureValidatorAsync SignedHttpRequestSignatureValidatorAsync { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.Ts"/> claim should be validated or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3</remarks>  
        public bool ValidateTs { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.M"/> claim should be validated or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3</remarks>  
        public bool ValidateM { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.U"/> claim should be validated or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3</remarks>  
        public bool ValidateU { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.P"/> claim should be validated or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3</remarks>  
        public bool ValidateP { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.Q"/> claim should be validated or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3</remarks>  
        public bool ValidateQ { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.H"/> claim should be validated or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3</remarks>  
        public bool ValidateH { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.B"/> claim should be validated or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3</remarks>  
        public bool ValidateB { get; set; } = false;

        /// <summary>
        /// Checks if the policy applies to the <paramref name="signedHttpRequest"/>.
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <returns><c>true</c> if the policy applies to the <paramref name="signedHttpRequest"/>, otherwise <c>false</c>.</returns>
        internal bool DoesApply(SecurityToken signedHttpRequest)
        {
            if (!(signedHttpRequest is JsonWebToken jwtSignedHttpRequest))
                return false;

            if (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.At, out string at) || string.IsNullOrEmpty(at))
                return false;

            if (ValidateTs && (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.Ts, out long _)))
                return false;

            if (ValidateM && (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.M, out string m) || string.IsNullOrEmpty(m)))
                return false;

            if (ValidateU && (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.U, out string u) || string.IsNullOrEmpty(u)))
                return false;

            if (ValidateP && (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.P, out string p) || string.IsNullOrEmpty(p)))
                return false;

            if (ValidateQ && (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.Q, out object q) || q == null))
                return false;

            if (ValidateH && (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.H, out object h) || h == null))
                return false;

            if (ValidateB && (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.B, out string b) || string.IsNullOrEmpty(b)))
                return false;

            return true;
        }
    }
}
