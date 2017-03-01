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

using System.IdentityModel.Metadata;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using WsFedMetadataSerializer = System.IdentityModel.Metadata.MetadataSerializer;

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
                LogHelper.LogArgumentNullException(nameof(address));
            }

            if (retriever == null)
            {
                LogHelper.LogArgumentNullException(nameof(retriever));
            }

            WsFederationConfiguration configuration = new WsFederationConfiguration();

            string document = await retriever.GetDocumentAsync(address, cancel);

            using (XmlReader metaDataReader = XmlReader.Create(new StringReader(document), SafeSettings))
            {
                var serializer = new WsFedMetadataSerializer { CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None };

                var metadataBase = serializer.ReadMetadata(metaDataReader);
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
                            //IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10807);
                            foreach (System.IdentityModel.Tokens.SecurityKeyIdentifierClause clause in keyDescriptor.KeyInfo)
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
