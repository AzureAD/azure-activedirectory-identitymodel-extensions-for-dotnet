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
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Globalization;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Retrieves metadata information using HttpClient.
    /// </summary>
    public class HttpDocumentRetriever : IDocumentRetriever
    {
        private HttpClient _httpClient;
        private static readonly HttpClient _defaultHttpClient = new HttpClient();

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpDocumentRetriever"/> class.
        /// </summary>
        public HttpDocumentRetriever()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpDocumentRetriever"/> class with a specified httpClient.
        /// </summary>
        /// <param name="httpClient"><see cref="HttpClient"/></param>
        /// <exception cref="ArgumentNullException">'httpClient' is null.</exception>
        public HttpDocumentRetriever(HttpClient httpClient)
        {
            if (httpClient == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("httpClient", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "httpClient"))); 

            _httpClient = httpClient;
        }

        /// <summary>
        /// Requires Https secure channel for sending requests.. This is turned ON by default for security reasons. It is RECOMMENDED that you do not allow retrieval from http addresses by default.
        /// </summary>
        public bool RequireHttps { get; set; } = true;

        /// <summary>
        /// Returns a task which contains a string converted from remote document when completed, by using the provided address.
        /// </summary>
        /// <param name="address">Location of document</param>
        /// <param name="cancel">A cancellation token that can be used by other objects or threads to receive notice of cancellation. <see cref="CancellationToken"/></param>
        /// <returns>Document as a string</returns>
        public async Task<string> GetDocumentAsync(string address, CancellationToken cancel)
        {
            if (string.IsNullOrWhiteSpace(address))
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("address", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "address"))); 

            if (!Utility.IsHttps(address) && RequireHttps)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX10108, address));

            try
            {
                IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10805, address);
                var httpClient = _httpClient ?? _defaultHttpClient;
                HttpResponseMessage response = await httpClient.GetAsync(address, cancel).ConfigureAwait(false);

                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new IOException(String.Format(LogMessages.IDX10804, address), ex));
            }
        }
    }
}
