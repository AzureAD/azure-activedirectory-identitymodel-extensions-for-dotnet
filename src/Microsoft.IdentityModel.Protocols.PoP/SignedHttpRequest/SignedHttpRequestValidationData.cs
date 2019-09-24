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

namespace Microsoft.IdentityModel.Protocols.PoP.SignedHttpRequest
{
    /// <summary>
    /// 
    /// </summary>
    public class SignedHttpRequestValidationData : SignedHttpRequestData
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="signedHttpRequestToken"></param>
        /// <param name="httpRequestData"></param>
        /// <param name="accessTokenValidationParameters"></param>
        /// <param name="signedHttpRequestValidationPolicy"></param>
        public SignedHttpRequestValidationData(string signedHttpRequestToken, HttpRequestData httpRequestData, TokenValidationParameters accessTokenValidationParameters, SignedHttpRequestValidationPolicy signedHttpRequestValidationPolicy) : base(httpRequestData, CallContext.Default)
        {
            SignedHttpRequest = !string.IsNullOrEmpty(signedHttpRequestToken) ? signedHttpRequestToken : throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestToken));
            AccessTokenValidationParameters = accessTokenValidationParameters ?? throw LogHelper.LogArgumentNullException(nameof(accessTokenValidationParameters));
            SignedHttpRequestValidationPolicy = signedHttpRequestValidationPolicy ?? throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestValidationPolicy));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signedHttpRequestToken"></param>
        /// <param name="httpRequestData"></param>
        /// <param name="accessTokenValidationParameters"></param>
        /// <param name="signedHttpRequestValidationPolicy"></param>
        /// <param name="callContext"></param>
        public SignedHttpRequestValidationData(string signedHttpRequestToken, HttpRequestData httpRequestData, TokenValidationParameters accessTokenValidationParameters, SignedHttpRequestValidationPolicy signedHttpRequestValidationPolicy, CallContext callContext) : base(httpRequestData, callContext)
        {
            SignedHttpRequest = !string.IsNullOrEmpty(signedHttpRequestToken) ? signedHttpRequestToken : throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestToken));
            AccessTokenValidationParameters = accessTokenValidationParameters ?? throw LogHelper.LogArgumentNullException(nameof(accessTokenValidationParameters));
            SignedHttpRequestValidationPolicy = signedHttpRequestValidationPolicy ?? throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestValidationPolicy));
        }

        /// <summary>
        /// 
        /// </summary>
        public TokenValidationParameters AccessTokenValidationParameters { get; }

        /// <summary>
        /// 
        /// </summary>
        public string SignedHttpRequest { get; }

        /// <summary>
        /// 
        /// </summary>
        public SignedHttpRequestValidationPolicy SignedHttpRequestValidationPolicy { get; }
    }
}
