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

using Microsoft.IdentityModel.Logging;
using System.Net.Http;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.PoP
{
    /// <summary>
    /// 
    /// </summary>
    public static class PopUtilities
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="signedHttpRequest"></param>
        /// <returns></returns>
        public static string CreateSignedHttpRequestHeader(string signedHttpRequest)
        {
            if (string.IsNullOrEmpty(signedHttpRequest))
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            return $"{PopConstants.SignedHttpRequest.AuthorizationHeader} {signedHttpRequest}";
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="httpRequestMessage"></param>
        /// <returns></returns>
        public static async Task<HttpRequestData> ToHttpRequestDataAsync(this HttpRequestMessage httpRequestMessage)
        {
            if (httpRequestMessage == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestMessage));

            var httpRequestData = new HttpRequestData()
            {
                HttpMethod = httpRequestMessage.Method?.ToString(),
                HttpRequestUri = httpRequestMessage.RequestUri
            };

            httpRequestData.AppendHeaders(httpRequestMessage.Headers);

            if (httpRequestMessage.Content != null)
            {
                httpRequestData.HttpRequestBody = await httpRequestMessage.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                httpRequestData.AppendHeaders(httpRequestMessage.Content.Headers);
            }

            return httpRequestData;
        }


    }
}
