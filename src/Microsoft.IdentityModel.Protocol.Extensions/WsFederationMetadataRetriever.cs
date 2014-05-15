//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using Microsoft.IdentityModel.Extensions;
using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Helper for parsing WsFederation metadata.
    /// </summary>
    public static class WsFederationMetadataRetriever
    {
        /// <summary>
        /// Obtains <see cref="WsFederationMetadata"/> from an endpoint.
        /// </summary>
        /// <param name="metadataUrl"> a pointer to the metadata. Can refer to a file or a absolute uri.</param>
        /// <param name="httpClient">the <see cref="HttpClient"/> to use obtain the metadata.</param>
        /// <returns>A populated <see cref="WsFederationMetadata"/>.</returns>
        /// <exception cref="ArgumentNullException"> if 'metadataUrl' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">if 'httpclient' is null.</exception>
        public static WsFederationMetadata GetMetadata(string metadataUrl, HttpClient httpClient)
        {
            if (string.IsNullOrWhiteSpace(metadataUrl))
            {
                throw new ArgumentNullException("metadataUrl");
            }

            if (httpClient == null)
            {
                throw new ArgumentNullException("httpClient");
            }

            HttpResponseMessage metadataResponse = httpClient.GetAsync(metadataUrl).Result;
            metadataResponse.EnsureSuccessStatusCode();
            return GetMetadata(metadataResponse.Content.ReadAsStreamAsync().Result);
        }

        /// <summary>
        /// Obtains <see cref="OpenIdConnectMetadata"/> from an endpoint.
        /// </summary>
        /// <param name="metadataUrl"> a pointer to the metadata. Can refer to a file or a absolute uri.</param>
        /// <returns>A populated <see cref="OpenIdConnectMetadata"/>.</returns>
        /// <exception cref="ArgumentNullException"> if 'metadataUrl' is null or whitespace.</exception>
        public static WsFederationMetadata GetMetadata(string metadataUrl)
        {
            if (string.IsNullOrWhiteSpace(metadataUrl))
            {
                throw new ArgumentNullException("metadataUrl");
            }

            using (Stream stream = OpenStream(metadataUrl))
            {
                return GetMetadata(stream);
            }
        }

        /// <summary>
        /// Returns a populated <see cref="OpenIdConnectMetadata"/> instance by reading the stream.
        /// </summary>
        /// <param name="stream"> a JSON formated stream conforming to OpenIdConnect discovery: http://openid.net/specs/openid-connect-discovery-1_0.html </param>
        /// <returns><see cref="OpenIdConnectMetadata"/></returns>
        /// <exception cref="ArgumentNullException"> if 'stream' is null.</exception>
        public static WsFederationMetadata GetMetadata(Stream stream)
        {
            return new WsFederationMetadata();
        }

        private static Stream OpenStream(string metadataUrl)
        {
            Stream stream;
            if (File.Exists(metadataUrl))
            {
                stream = new FileStream(metadataUrl, FileMode.Open);
            }
            else
            {
                if (!Uri.IsWellFormedUriString(metadataUrl, UriKind.Absolute))
                {
                    throw new ArgumentException(ErrorMessages.IDX10220 + "'" + metadataUrl + "'.");
                }

                WebRequest webRequest = WebRequest.Create(metadataUrl);
                WebResponse webResponse = webRequest.GetResponse();
                stream = webResponse.GetResponseStream();
            }

            return stream;
        }
    }
}
