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
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.IdentityModel.Protocols;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// Test class to imitate OpenIdConnectConfigurationRetriever/WsFederationConfigurationRetriever's behavior. Retrieves a populated <see cref="FakeConfiguration"/> given an address.
    /// </summary>
    public class FakeConfigurationRetriever : IConfigurationRetriever<FakeConfiguration>
    {
        private static readonly XmlReaderSettings SafeSettings = new XmlReaderSettings { XmlResolver = null, DtdProcessing = DtdProcessing.Prohibit, ValidationType = ValidationType.None };

        Task<FakeConfiguration> IConfigurationRetriever<FakeConfiguration>.GetConfigurationAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
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
        public static async Task<FakeConfiguration> GetAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
        {
            if (string.IsNullOrWhiteSpace(address))
            {
                throw new ArgumentNullException("address");
            }

            if (retriever == null)
            {
                throw new ArgumentNullException("retriever");
            }

            FakeConfiguration configuration = new FakeConfiguration();

            string document = await retriever.GetDocumentAsync(address, cancel).ConfigureAwait(false);

            using (XmlReader reader = XmlReader.Create(new StringReader(document), SafeSettings))
            {
                if (reader.Read())
                    reader.MoveToContent();

                while (reader.Read())
                {
                    if (reader.IsStartElement())
                    {
                        if (reader.LocalName.Equals("Title", StringComparison.OrdinalIgnoreCase))
                        {
                            reader.MoveToContent();
                            if (reader.Read() && reader.HasValue)
                                configuration.Title = reader.Value;
                            break;
                        }
                    }
                }
            }

            return configuration;
        }
    }
}
