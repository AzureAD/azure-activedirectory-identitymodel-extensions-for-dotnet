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
using System.IdentityModel.Metadata;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// WsFederationConfigurationRetriever - TODO
    /// </summary>
    public class WsFederationConfigurationRetriever : IConfigurationRetriever<WsFederationConfiguration>
    {
        private static readonly XmlReaderSettings SafeSettings = new XmlReaderSettings { XmlResolver = null, DtdProcessing = DtdProcessing.Prohibit, ValidationType = ValidationType.None };

        /// <summary>
        /// GetAsync - TODO
        /// </summary>
        /// <param name="address">TODO</param>
        /// <param name="cancel">TODO</param>
        /// <returns>TODO</returns>
        public static Task<WsFederationConfiguration> GetAsync(string address, CancellationToken cancel)
        {
            return GetAsync(new GenericDocumentRetriever(), address, cancel);
        }

        /// <summary>
        /// GetAsync - TODO
        /// </summary>
        /// <param name="address">TODO</param>
        /// <param name="httpClient">TODO</param>
        /// <param name="cancel">TODO</param>
        /// <returns>TODO</returns>
        public static Task<WsFederationConfiguration> GetAsync(string address, HttpClient httpClient, CancellationToken cancel)
        {
            return GetAsync(new HttpDocumentRetriever(httpClient), address, cancel);
        }

        // Internal
        Task<WsFederationConfiguration> IConfigurationRetriever<WsFederationConfiguration>.GetConfigurationAsync(IDocumentRetriever retriever, string address, CancellationToken cancel)
        {
            return GetAsync(retriever, address, cancel);
        }

        /// <summary>
        /// GetAsync - TODO
        /// </summary>
        /// <param name="retriever">TODO</param>
        /// <param name="address">TODO</param>
        /// <param name="cancel">TODO</param>
        /// <returns>TODO</returns>
        public static async Task<WsFederationConfiguration> GetAsync(IDocumentRetriever retriever, string address, CancellationToken cancel)
        {
            if (retriever == null)
            {
                throw new ArgumentNullException("retriever");
            }
            if (string.IsNullOrWhiteSpace(address))
            {
                throw new ArgumentNullException("address");
            }
            WsFederationConfiguration configuration = new WsFederationConfiguration();

            string document = await retriever.GetDocumentAsync(address, cancel);

            using (XmlReader metaDataReader = XmlReader.Create(new StringReader(document), SafeSettings))
            {
                var serializer = new MetadataSerializer { CertificateValidationMode = X509CertificateValidationMode.None };

                MetadataBase metadataBase = serializer.ReadMetadata(metaDataReader);
                var entityDescriptor = (EntityDescriptor)metadataBase;

                if (!string.IsNullOrWhiteSpace(entityDescriptor.EntityId.Id))
                {
                    configuration.Issuer = entityDescriptor.EntityId.Id;
                }

                SecurityTokenServiceDescriptor stsd = entityDescriptor.RoleDescriptors.OfType<SecurityTokenServiceDescriptor>().First();
                if (stsd == null)
                {
                    throw new InvalidOperationException("Missing descriptor"/*Resources.Exception_MissingDescriptor*/);
                }

                configuration.TokenEndpoint = stsd.PassiveRequestorEndpoints.First().Uri.AbsoluteUri;

                foreach (KeyDescriptor keyDescriptor in stsd.Keys)
                {
                    if (keyDescriptor.KeyInfo != null && (keyDescriptor.Use == KeyType.Signing || keyDescriptor.Use == KeyType.Unspecified))
                    {
                        foreach (SecurityKeyIdentifierClause clause in keyDescriptor.KeyInfo)
                        {
                            X509RawDataKeyIdentifierClause x509Clause = clause as X509RawDataKeyIdentifierClause;
                            if (x509Clause != null)
                            {
                                var key =  new X509SecurityKey(new X509Certificate2(x509Clause.GetX509RawData()));
                                configuration.SigningKeys.Add(key);
                            }
                        }
                    }
                }
            }

            return configuration;
        }
    }
}
