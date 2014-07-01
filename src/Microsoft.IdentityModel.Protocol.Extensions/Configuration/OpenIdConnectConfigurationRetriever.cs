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

using System;
using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// OpenIdConnectConfigurationRetriever - TODO
    /// </summary>
    public class OpenIdConnectConfigurationRetriever : IConfigurationRetriever<OpenIdConnectConfiguration>
    {

        /// <summary>
        /// GetAsync
        /// </summary>
        /// <param name="address">TODO</param>
        /// <param name="cancel">TODO</param>
        /// <returns></returns>
        public static Task<OpenIdConnectConfiguration> GetAsync(string address, CancellationToken cancel)
        {
            return GetAsync(new GenericDocumentRetriever(), address, cancel);
        }

        /// <summary>
        /// GetAsync
        /// </summary>
        /// <param name="address">TODO</param>
        /// <param name="httpClient">TODO</param>
        /// <param name="cancel">TODO</param>
        /// <returns></returns>
        public static Task<OpenIdConnectConfiguration> GetAsync(string address, HttpClient httpClient, CancellationToken cancel)
        {
            return GetAsync(new HttpDocumentRetriever(httpClient), address, cancel);
        }

        Task<OpenIdConnectConfiguration> IConfigurationRetriever<OpenIdConnectConfiguration>.GetConfigurationAsync(IDocumentRetriever retriever, string address, CancellationToken cancel)
        {
            return GetAsync(retriever, address, cancel);
        }


        /// <summary>
        /// GetAsync
        /// </summary>
        /// <param name="retriever">TODO</param>
        /// <param name="address">TODO</param>
        /// <param name="cancel">TODO</param>
        /// <returns></returns>
        public static async Task<OpenIdConnectConfiguration> GetAsync(IDocumentRetriever retriever, string address, CancellationToken cancel)
        {
            if (retriever == null)
                throw new ArgumentNullException("retriever");

            if (string.IsNullOrWhiteSpace(address))
                throw new ArgumentNullException("address");

            OpenIdConnectConfiguration openIdConnectConfiguration = null;
            string doc = await retriever.GetDocumentAsync(address, cancel);

            openIdConnectConfiguration = new OpenIdConnectConfiguration(doc);
            if (!string.IsNullOrEmpty(openIdConnectConfiguration.JwksUri))
            {
                doc = await retriever.GetDocumentAsync(openIdConnectConfiguration.JwksUri, cancel);
                openIdConnectConfiguration.JsonWebKeySet = new JsonWebKeySet(doc);
                foreach (SecurityToken token in openIdConnectConfiguration.JsonWebKeySet.GetSigningTokens())
                {
                    openIdConnectConfiguration.SigningTokens.Add(token);
                }
            }

            return openIdConnectConfiguration;
        }
    }
}
