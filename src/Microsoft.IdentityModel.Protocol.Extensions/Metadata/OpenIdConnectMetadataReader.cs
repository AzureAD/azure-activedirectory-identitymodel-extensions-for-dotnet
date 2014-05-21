using System;
using System.IdentityModel.Tokens;
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

using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols
{
    public class OpenIdConnectMetadataReader : IMetadataReader<OpenIdConnectMetadata>
    {
        public async Task<OpenIdConnectMetadata> ReadMetadataAysnc(IDocumentRetriever retriever, string address, CancellationToken cancel)
        {
            if (retriever == null)
            {
                throw new ArgumentNullException("retriever");
            }
            if (string.IsNullOrWhiteSpace(address))
            {
                throw new ArgumentNullException("address");
            }

            OpenIdConnectMetadata openIdConnectMetadata = null;
            string doc = await retriever.GetDocumentAsync(address, cancel);

            openIdConnectMetadata = new OpenIdConnectMetadata(doc);
            if (!string.IsNullOrEmpty(openIdConnectMetadata.JwksUri))
            {
                doc = await retriever.GetDocumentAsync(openIdConnectMetadata.JwksUri, cancel);
                JsonWebKeys jsonWebKeys = new JsonWebKeys(doc);
                foreach (JsonWebKey webKey in jsonWebKeys.Keys)
                {
                    // Add chaining
                    if (webKey.X5c.Count == 1)
                    {
                        X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(webKey.X5c[0]));
                        openIdConnectMetadata.SigningKeys.Add(new X509SecurityKey(cert));
                    }

                    openIdConnectMetadata.JsonWebKeys.Add(webKey);
                }
            }

            return openIdConnectMetadata;
        }
    }
}
