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
    public class SignedHttpRequestCreationData : SignedHttpRequestData
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="httpRequestData"></param>
        /// <param name="httpRequestSigningCredentials"></param>
        /// <param name="signedHttpRequestCreationPolicy"></param>
        public SignedHttpRequestCreationData(string accessToken, HttpRequestData httpRequestData, SigningCredentials httpRequestSigningCredentials, SignedHttpRequestCreationPolicy signedHttpRequestCreationPolicy) 
            : base(httpRequestData, CallContext.Default)
        {
            AccessToken = !string.IsNullOrEmpty(accessToken) ? accessToken : throw LogHelper.LogArgumentNullException(nameof(accessToken));
            HttpRequestSigningCredentials = httpRequestSigningCredentials ?? throw LogHelper.LogArgumentNullException(nameof(httpRequestSigningCredentials));
            SignedHttpRequestCreationPolicy = signedHttpRequestCreationPolicy ?? throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestCreationPolicy));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="httpRequestData"></param>
        /// <param name="httpRequestSigningCredentials"></param>
        /// <param name="signedHttpRequestCreationPolicy"></param>
        /// <param name="callContext"></param>
        public SignedHttpRequestCreationData(string accessToken, HttpRequestData httpRequestData, SigningCredentials httpRequestSigningCredentials, SignedHttpRequestCreationPolicy signedHttpRequestCreationPolicy, CallContext callContext) 
            : base(httpRequestData, callContext)
        {
            AccessToken = !string.IsNullOrEmpty(accessToken) ? accessToken : throw LogHelper.LogArgumentNullException(nameof(accessToken));
            HttpRequestSigningCredentials = httpRequestSigningCredentials ?? throw LogHelper.LogArgumentNullException(nameof(httpRequestSigningCredentials));
            SignedHttpRequestCreationPolicy = signedHttpRequestCreationPolicy ?? throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestCreationPolicy));
        }

        /// <summary>
        /// 
        /// </summary>
        public string AccessToken { get; }

        /// <summary>
        /// 
        /// </summary>
        public SigningCredentials HttpRequestSigningCredentials { get; }

        /// <summary>
        /// 
        /// </summary>
        public SignedHttpRequestCreationPolicy SignedHttpRequestCreationPolicy { get; }
    }
}
