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
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using NSubstitute;
using Xunit;

namespace Microsoft.IdentityModel.Validators.Tests
{
    public class IssuerConfigurationRetrieverTests
    {
        [Fact]
        public async Task GetConfigurationAsync_NullOrEmptyParameters_ThrowsException()
        {
            var configurationRetriever = new IssuerConfigurationRetriever();

            var exception = await Assert.ThrowsAsync<ArgumentNullException>("address", () => configurationRetriever.GetConfigurationAsync(null, null, CancellationToken.None)).ConfigureAwait(false);

            string netFrameworkErrorMessage = "IDX40101: Azure AD Issuer metadata address URL is required. \r\nParameter name: address";
            Assert.Equal(netFrameworkErrorMessage, exception.Message);

            exception = await Assert.ThrowsAsync<ArgumentNullException>("address", () => configurationRetriever.GetConfigurationAsync(string.Empty, null, CancellationToken.None)).ConfigureAwait(false);

            Assert.Equal(netFrameworkErrorMessage, exception.Message);

            exception = await Assert.ThrowsAsync<ArgumentNullException>("retriever", () => configurationRetriever.GetConfigurationAsync("address", null, CancellationToken.None)).ConfigureAwait(false);

            Assert.Equal("IDX40102: No metadata document retriever is provided. \r\nParameter name: retriever", exception.Message);
        }

        [Fact]
        public async Task GetConfigurationAsync_ValidParameters_ReturnsIssuerMetadata()
        {
            var metadata = @"{""tenant_discovery_endpoint"":""https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"",""api-version"":""1.1"",""metadata"":[{""preferred_network"":""login.microsoftonline.com"",""preferred_cache"":""login.windows.net"",""aliases"":[""login.microsoftonline.com""]}]}";
            var metadataAddress = "address";

            var configurationRetriever = new IssuerConfigurationRetriever();
            var documentRetriever = Substitute.For<IDocumentRetriever>();
            documentRetriever.GetDocumentAsync(metadataAddress, CancellationToken.None).Returns(Task.FromResult(metadata));

            Assert.NotNull(await configurationRetriever.GetConfigurationAsync(metadataAddress, documentRetriever, CancellationToken.None).ConfigureAwait(false));
        }
    }
}
