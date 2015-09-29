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
using System.Diagnostics.Tracing;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsFederation
{
    /// <summary>
    ///  Retrieves a populated <see cref="WsFederationConfiguration"/> given an address.
    /// </summary>
    public class WsFederationConfigurationRetriever : IConfigurationRetriever<WsFederationConfiguration>
    {
        private static readonly XmlReaderSettings SafeSettings = new XmlReaderSettings { XmlResolver = null, DtdProcessing = DtdProcessing.Prohibit, ValidationType = ValidationType.None };

        /// <summary>
        /// Retrieves a populated <see cref="WsFederationConfiguration"/> given an address.
        /// </summary>
        /// <param name="address">address of the metadata document.</param>
        /// <param name="cancel"><see cref="CancellationToken"/>.</param>
        /// <returns>A populated <see cref="WsFederationConfiguration"/> instance.</returns>
        public static Task<WsFederationConfiguration> GetAsync(string address, CancellationToken cancel)
        {
            return GetAsync(address, new HttpDocumentRetriever(), cancel);
        }

        /// <summary>
        /// Retrieves a populated <see cref="WsFederationConfiguration"/> given an address and an <see cref="HttpClient"/>.
        /// </summary>
        /// <param name="address">address of the metadata document.</param>
        /// <param name="httpClient">the <see cref="HttpClient"/> to use to read the metadata document.</param>
        /// <param name="cancel"><see cref="CancellationToken"/>.</param>
        /// <returns>A populated <see cref="WsFederationConfiguration"/> instance.</returns>
        public static Task<WsFederationConfiguration> GetAsync(string address, HttpClient httpClient, CancellationToken cancel)
        {
            return GetAsync(address, new HttpDocumentRetriever(httpClient), cancel);
        }

        Task<WsFederationConfiguration> IConfigurationRetriever<WsFederationConfiguration>.GetConfigurationAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
        {
            return GetAsync(address, retriever, cancel);
        }

        /// <summary>
        /// Retrieves a populated <see cref="WsFederationConfiguration"/> given an address and an <see cref="IDocumentRetriever"/>.
        /// </summary>
        /// <param name="address">address of the metadata document.</param>
        /// <param name="retriever">the <see cref="IDocumentRetriever"/> to use to read the metadata document</param>
        /// <param name="cancel"><see cref="CancellationToken"/>.</param>
        /// <returns>A populated <see cref="WsFederationConfiguration"/> instance.</returns>
        public static async Task<WsFederationConfiguration> GetAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
        {
            if (string.IsNullOrWhiteSpace(address))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": address"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (retriever == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": retriever"), typeof(ArgumentNullException), EventLevel.Verbose);
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
                if (stsd != null)
                {
                    configuration.TokenEndpoint = stsd.PassiveRequestorEndpoints.First().Uri.AbsoluteUri;
                    foreach (KeyDescriptor keyDescriptor in stsd.Keys)
                    {
                        if (keyDescriptor.KeyInfo != null && (keyDescriptor.Use == KeyType.Signing || keyDescriptor.Use == KeyType.Unspecified))
                        {
                            IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10807);
                            foreach (SecurityKeyIdentifierClause clause in keyDescriptor.KeyInfo)
                            {
                                X509RawDataKeyIdentifierClause x509Clause = clause as X509RawDataKeyIdentifierClause;
                                if (x509Clause != null)
                                {
                                    var key = new X509SecurityKey(new X509Certificate2(x509Clause.GetX509RawData()));
                                    configuration.SigningKeys.Add(key);
                                }
                            }
                        }
                    }
                }
            }

            return configuration;
        }
    }
}
