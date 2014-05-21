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
using System.Collections.Generic;
using System.IdentityModel.Metadata;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

namespace Microsoft.IdentityModel.Protocols
{
    public class WsFederationMetadataReader : IMetadataReader<WsFederationMetadata>
    {
        private static readonly XmlReaderSettings SafeSettings = new XmlReaderSettings { XmlResolver = null, DtdProcessing = DtdProcessing.Prohibit, ValidationType = ValidationType.None };

        public async Task<WsFederationMetadata> ReadMetadataAysnc(IDocumentRetriever retriever, string address, CancellationToken cancel)
        {
            if (retriever == null)
            {
                throw new ArgumentNullException("retriever");
            }
            if (string.IsNullOrWhiteSpace(address))
            {
                throw new ArgumentNullException("address");
            }
            WsFederationMetadata metadata = new WsFederationMetadata();

            string document = await retriever.GetDocumentAsync(address, cancel);

            using (XmlReader metaDataReader = XmlReader.Create(new StringReader(document), SafeSettings))
            {
                var serializer = new MetadataSerializer { CertificateValidationMode = X509CertificateValidationMode.None };

                MetadataBase metadataBase = serializer.ReadMetadata(metaDataReader);
                var entityDescriptor = (EntityDescriptor)metadataBase;

                if (!string.IsNullOrWhiteSpace(entityDescriptor.EntityId.Id))
                {
                    metadata.Issuer = entityDescriptor.EntityId.Id;
                }

                SecurityTokenServiceDescriptor stsd = entityDescriptor.RoleDescriptors.OfType<SecurityTokenServiceDescriptor>().First();
                if (stsd == null)
                {
                    throw new InvalidOperationException("Missing descriptor"/*Resources.Exception_MissingDescriptor*/);
                }

                metadata.TokenEndpoint = stsd.PassiveRequestorEndpoints.First().Uri.AbsoluteUri;

                IEnumerable<X509RawDataKeyIdentifierClause> x509DataClauses =
                    stsd.Keys.Where(key => key.KeyInfo != null
                        && (key.Use == KeyType.Signing || key.Use == KeyType.Unspecified))
                            .Select(key => key.KeyInfo.OfType<X509RawDataKeyIdentifierClause>().First());

                foreach (var key in x509DataClauses.Select(token => new X509SecurityKey(new X509Certificate2(token.GetX509RawData()))))
                {
                    metadata.SigningKeys.Add(key);
                }
            }

            return metadata;
        }
    }
}
