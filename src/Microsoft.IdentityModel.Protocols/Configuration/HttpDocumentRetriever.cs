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
using System.Diagnostics.Tracing;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Retrieves metadata information using HttpClient.
    /// </summary>
    public class HttpDocumentRetriever : IDocumentRetriever
    {
        private readonly HttpClient _httpClient;
        private bool _requireHttps;

        public HttpDocumentRetriever() : this(new HttpClient())
        {
        }

        public HttpDocumentRetriever(HttpClient httpClient)
        {
            if (httpClient == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": httpClient"), typeof(ArgumentNullException), EventLevel.Verbose);
            }
            _httpClient = httpClient;
            _requireHttps = true;
        }

        /// <summary>
        /// Requires Https secure channel for sending requests.. This is turned ON by default for security reasons. It is RECOMMENDED that you do not allow retrieval from http addresses by default.
        /// </summary>
        public bool RequireHttps
        {
            get { return _requireHttps; }
            set { _requireHttps = value; }
        }

        public async Task<string> GetDocumentAsync(string address, CancellationToken cancel)
        {
            if (string.IsNullOrWhiteSpace(address))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": address"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (!Utility.IsHttps(address) && RequireHttps)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10108, address), typeof(ArgumentException), EventLevel.Error);
            }

            try
            {
                IdentityModelEventSource.Logger.WriteVerbose(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10805, address));
                HttpResponseMessage response = _httpClient.GetAsync(address, cancel).Result;
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10804, address), typeof(IOException), EventLevel.Error, ex);
                return null;
            }
        }
    }
}
