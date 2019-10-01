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

using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.Pop
{
    /// <summary>
    /// A class which contains useful methods related to processing of proof-of-possession protocol.
    /// </summary>
    public static class PopUtilities
    {
        /// <summary>
        /// Creates an authorization header using the SignedHttpRequest.
        /// </summary>
        /// <param name="signedHttpRequest">A signed http request.</param>
        /// <returns>A SignedHttpRequest value prefixed with the word "PoP".</returns>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-4.1</remarks>
        public static string CreateSignedHttpRequestHeader(string signedHttpRequest)
        {
            if (string.IsNullOrEmpty(signedHttpRequest))
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            return $"{PopConstants.SignedHttpRequest.AuthorizationHeaderSchemeName} {signedHttpRequest}";
        }

        /// <summary>
        /// A helper method that converts <see cref="HttpRequestMessage"/> into <see cref="HttpRequestData"/> object.
        /// </summary>
        /// <param name="httpRequestMessage"><see cref="HttpRequestMessage"/> object that represents incoming or outgoing http request.</param>
        /// <returns><see cref="HttpRequestData"/> object</returns>
        public static async Task<HttpRequestData> ToHttpRequestDataAsync(this HttpRequestMessage httpRequestMessage)
        {
            if (httpRequestMessage == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestMessage));

            var httpRequestData = new HttpRequestData()
            {
                Method = httpRequestMessage.Method?.ToString(),
                Uri = httpRequestMessage.RequestUri
            };

            httpRequestData.AppendHeaders(httpRequestMessage.Headers);

            if (httpRequestMessage.Content != null)
            {
                httpRequestData.Body = await httpRequestMessage.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                httpRequestData.AppendHeaders(httpRequestMessage.Content.Headers);
            }

            return httpRequestData;
        }
    }
}
