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
using System.Linq;
using System.Net.Http.Headers;

namespace Microsoft.IdentityModel.Protocols.PoP
{
    /// <summary>
    /// 
    /// </summary>
    public class HttpRequestData
    {
        /// <summary>
        /// </summary>
        public Uri HttpRequestUri { get; set; }

        /// <summary>
        /// </summary>
        public string HttpMethod { get; set; }

        /// <summary>
        /// </summary>
        public byte[] HttpRequestBody { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public IDictionary<string, IEnumerable<string>> HttpRequestHeaders { get; set; }

        internal void AppendHeaders(HttpHeaders headers)
        {
            if (HttpRequestHeaders == null)
                HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>(StringComparer.OrdinalIgnoreCase);

            foreach (var header in headers)
            {
                if (HttpRequestHeaders.ContainsKey(header.Key))
                    HttpRequestHeaders[header.Key] = HttpRequestHeaders[header.Key].Concat(header.Value);
                else
                    HttpRequestHeaders.Add(header.Key, header.Value);
            }

        }
    }
}
