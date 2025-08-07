// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.PQC.Tests
{
    /// <summary>
    /// This class tests integration with SymCrypt
    /// </summary>
    public class MetadataTests
    {
        /// <summary>
        /// Parses a OpenIdConnectMetadata.
        /// </summary>
        [Fact]

        public async Task SerializeMetadata()
        {
            string jsonWebKeySetString = PQCTestUtilities.JsonWebKeySetWithMultipleKeys();
            OpenIdConnectConfiguration openIdConnectConfiguration = new OpenIdConnectConfiguration();
            openIdConnectConfiguration.Issuer = "https://localhost:5001";
            openIdConnectConfiguration.JwksUri = "JsonWebKeySetAddress";

            string openIdConnectConfigurationString = OpenIdConnectConfiguration.Write(openIdConnectConfiguration);

            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    "MetadataAddress",
                    new OpenIdConnectConfigurationRetriever(),
                    new StaticDocumentRetriever(openIdConnectConfigurationString, jsonWebKeySetString));

            var configuration = await configurationManager.GetConfigurationAsync(CancellationToken.None);
        }
    }
}
