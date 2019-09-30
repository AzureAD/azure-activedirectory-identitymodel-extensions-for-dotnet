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

namespace Microsoft.IdentityModel.Protocols.Pop.SignedHttpRequest
{
    /// <summary>
    /// Structure that wraps parameters needed for SignedHttpRequest processing.
    /// </summary>
    public abstract class SignedHttpRequestData
    {
        /// <summary>
        /// Initializes a new instance of <see cref="SignedHttpRequestData"/> from a <see cref="HttpRequestData"/> and <see cref="CallContext"/>.
        /// </summary>
        /// <param name="httpRequestData">A structure that represents an incoming or an outgoing http request.</param>
        /// <param name="callContext">An opaque context used to store work when working with authentication artifacts.</param>
        public SignedHttpRequestData(HttpRequestData httpRequestData, CallContext callContext)
        {
            HttpRequestData = httpRequestData ?? throw LogHelper.LogArgumentNullException(nameof(httpRequestData));
            CallContext = callContext ?? throw LogHelper.LogArgumentNullException(nameof(callContext));
        }

        /// <summary>
        /// An opaque context used to store work when working with authentication artifacts.
        /// </summary>
        public CallContext CallContext { get; }

        /// <summary>
        /// A structure that represents an incoming or an outgoing http request.
        /// </summary>
        public HttpRequestData HttpRequestData { get; }
    }
}
