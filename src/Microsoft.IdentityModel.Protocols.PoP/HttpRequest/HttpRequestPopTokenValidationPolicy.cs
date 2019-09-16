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

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.PoP.HttpRequest
{
    using ClaimTypes = PopConstants.HttpRequest.ClaimTypes;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="jwtPopToken"></param>
    /// <param name="validatedAccessToken"></param>
    /// <param name="httpRequestData"></param>
    /// <param name="popTokenValidationPolicy"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public delegate Task CustomClaimValidatorAsync(JsonWebToken jwtPopToken, JsonWebToken validatedAccessToken, HttpRequestData httpRequestData, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="validatedAccessToken"></param>
    /// <param name="popTokenValidationPolicy"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public delegate Task<SecurityKey> PopKeyResolverAsync(JsonWebToken validatedAccessToken, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="kid"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public delegate Task<SecurityKey> PopKeyResolverFromKeyIdentifierAsync(string kid, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="jwtPopToken"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public delegate Task PopTokenReplayValidatorAsync(JsonWebToken jwtPopToken, CancellationToken cancellationToken);


    /// <summary>
    /// 
    /// </summary>
    /// <param name="popKey"></param>
    /// <param name="jwtPopToken"></param>
    /// <param name="validatedAccessToken"></param>
    /// <param name="popTokenValidationPolicy"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public delegate Task PopTokenSignatureValidatorAsync(SecurityKey popKey, JsonWebToken jwtPopToken, JsonWebToken validatedAccessToken, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="jwe"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public delegate Task<IEnumerable<SecurityKey>> CnfDecryptionKeysResolverAsync(JsonWebToken jwe, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    public class HttpRequestPopTokenValidationPolicy
    {
        private TimeSpan _popTokenLifetime = DefaultPopTokenLifetime;

        /// <summary>
        /// https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-5.1
        /// </summary>
        public bool AcceptUncoveredQueryParameters { get; set; } = true;

        /// <summary>
        /// https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-5.2
        /// </summary>
        public bool AcceptUncoveredHeaders { get; set; } = true;

        /// <summary>
        /// 
        /// </summary>
        public IEnumerable<SecurityKey> CnfDecryptionKeys { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public CnfDecryptionKeysResolverAsync CnfDecryptionKeysResolverAsync { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public CustomClaimValidatorAsync CustomClaimValidatorAsync { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public static readonly TimeSpan DefaultPopTokenLifetime = TimeSpan.FromMinutes(5);

        /// <summary>
        /// 
        /// </summary>
        public HttpClient HttpClientForJkuResourceRetrieval { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public TimeSpan PopTokenLifetime
        {
            get
            {
                return _popTokenLifetime;
            }

            set
            {
                if (value < TimeSpan.Zero)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(value)));

                _popTokenLifetime = value;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public PopKeyResolverAsync PopKeyResolverAsync { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public PopKeyResolverFromKeyIdentifierAsync PopKeyResolverFromKeyIdentifierAsync { get; set; }

        /// <summary>
        /// Gets or sets a delegate that will be used to check if the pop token is replayed.
        /// </summary>
        public PopTokenReplayValidatorAsync PopTokenReplayValidatorAsync { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public PopTokenSignatureValidatorAsync PopTokenSignatureValidatorAsync { get; set; }

        /// <summary>
        /// </summary>
        public bool RequireHttpsForJkuResourceRetrieval { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.Ts"/> claim should be validated or not.
        /// </summary>
        public bool ValidateTs { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.M"/> claim should be validated or not.
        /// </summary>
        public bool ValidateM { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.U"/> claim should be validated or not.
        /// </summary>
        public bool ValidateU { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.P"/> claim should be validated or not.
        /// </summary>
        public bool ValidateP { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.Q"/> claim should be validated or not.
        /// </summary>
        public bool ValidateQ { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.H"/> claim should be validated or not.
        /// </summary>
        public bool ValidateH { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.B"/> claim should be validated or not.
        /// </summary>
        public bool ValidateB { get; set; } = false;
    }
}
