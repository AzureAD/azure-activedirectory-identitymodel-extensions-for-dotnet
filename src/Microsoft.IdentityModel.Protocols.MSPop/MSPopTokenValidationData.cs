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

using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.MSPop
{
    /// <summary>
    /// Structure that wraps parameters needed for MSPop token validation.
    /// </summary>
    public class MSPopTokenValidationData : MSPopTokenData
    {
        /// <summary>
        /// Initializes a new instance of <see cref="MSPopTokenValidationData"/>.
        /// </summary>
        /// <param name="msPopToken">An MSPop token to be validated as a JWS in Compact Serialization Format.</param>
        /// <param name="httpRequestData">A structure that represents an incoming http request.</param>
        /// <param name="accessTokenValidationParameters">A <see cref="TokenValidationParameters"/> required for access token ("at") validation.</param>
        /// <param name="msPopTokenValidationPolicy">A policy for validating the MSPop token.</param>
        public MSPopTokenValidationData(string msPopToken, HttpRequestData httpRequestData, TokenValidationParameters accessTokenValidationParameters, MSPopTokenValidationPolicy msPopTokenValidationPolicy) : base(httpRequestData, CallContext.Default)
        {
            AccessTokenValidationParameters = accessTokenValidationParameters ?? throw LogHelper.LogArgumentNullException(nameof(accessTokenValidationParameters));
            MSPopToken = !string.IsNullOrEmpty(msPopToken) ? msPopToken : throw LogHelper.LogArgumentNullException(nameof(msPopToken));
            MSPopTokenValidationPolicy = msPopTokenValidationPolicy ?? throw LogHelper.LogArgumentNullException(nameof(msPopTokenValidationPolicy));
        }

        /// <summary>
        /// Initializes a new instance of <see cref="MSPopTokenValidationData"/>.
        /// </summary>
        /// <param name="msPopToken">An MSPop token to be validated as a JWS in Compact Serialization Format.</param>
        /// <param name="httpRequestData">A structure that represents an incoming http request.</param>
        /// <param name="accessTokenValidationParameters">A <see cref="TokenValidationParameters"/> required for access token ("at") validation.</param>
        /// <param name="msPopTokenValidationPolicy">A policy for validating the MSPop token.</param>
        /// <param name="callContext">An opaque context used to store work when working with authentication artifacts.</param>
        public MSPopTokenValidationData(string msPopToken, HttpRequestData httpRequestData, TokenValidationParameters accessTokenValidationParameters, MSPopTokenValidationPolicy msPopTokenValidationPolicy, CallContext callContext) : base(httpRequestData, callContext)
        {
            AccessTokenValidationParameters = accessTokenValidationParameters ?? throw LogHelper.LogArgumentNullException(nameof(accessTokenValidationParameters));
            MSPopToken = !string.IsNullOrEmpty(msPopToken) ? msPopToken : throw LogHelper.LogArgumentNullException(nameof(msPopToken));
            MSPopTokenValidationPolicy = msPopTokenValidationPolicy ?? throw LogHelper.LogArgumentNullException(nameof(msPopTokenValidationPolicy));
        }

        /// <summary>
        /// Gets <see cref="TokenValidationParameters"/> required for access token ("at") validation.
        /// </summary>
        public TokenValidationParameters AccessTokenValidationParameters { get; }

        /// <summary>
        /// Gets an MSPop token that is to be validated as a JWS in Compact Serialization Format.
        /// </summary>
        public string MSPopToken { get; }

        /// <summary>
        /// Gets a policy that is used for validating a MSPop.
        /// </summary>
        public MSPopTokenValidationPolicy MSPopTokenValidationPolicy { get; }
    }
}
