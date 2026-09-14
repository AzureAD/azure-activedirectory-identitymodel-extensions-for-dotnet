// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.Tests
{
    public class HttpRequestDataTests
    {
        [Fact]
        public void ClientCertificates()
        {
            var httpRequestData = new HttpRequestData();
            Assert.NotNull(httpRequestData.ClientCertificates);
            Assert.Empty(httpRequestData.ClientCertificates);

            X509Certificate2 cert = TestUtils.CertificateHelper.LoadX509Certificate(KeyingMaterial.AADCertData);
            httpRequestData.ClientCertificates.Add(cert);

            Assert.Single(httpRequestData.ClientCertificates);
            Assert.Equal(cert, httpRequestData.ClientCertificates[0]);
        }

        [Fact]
        public void LazyClientCertificates()
        {
            var httpRequestData = new HttpRequestData();
            Assert.NotNull(httpRequestData.ClientCertificates);
            Assert.Empty(httpRequestData.ClientCertificates);

            X509Certificate2 cert = TestUtils.CertificateHelper.LoadX509Certificate(KeyingMaterial.AADCertData);

            int numberCertsPopulatedCalled = 0;
            httpRequestData.SetLazyClientCertificates((c) =>
            {
                numberCertsPopulatedCalled++;
                c.Add(cert);
            });

            Assert.Equal(0, numberCertsPopulatedCalled);

            Assert.Single(httpRequestData.ClientCertificates);
            Assert.Equal(cert, httpRequestData.ClientCertificates[0]);
            Assert.Equal(1, numberCertsPopulatedCalled);

            // Invoke again, should not call the delegate again
            _ = httpRequestData.ClientCertificates;

            Assert.Equal(1, numberCertsPopulatedCalled);
        }
    }
}
