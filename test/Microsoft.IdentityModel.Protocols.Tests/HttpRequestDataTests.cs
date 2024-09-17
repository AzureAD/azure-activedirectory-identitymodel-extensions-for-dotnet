// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
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

            X509Certificate2 cert;
#if NET9_0_OR_GREATER
            cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(KeyingMaterial.AADCertData));
#else
            cert = new X509Certificate2(Convert.FromBase64String(KeyingMaterial.AADCertData));
#endif
            httpRequestData.ClientCertificates.Add(cert);

            Assert.Single(httpRequestData.ClientCertificates);
            Assert.Equal(cert, httpRequestData.ClientCertificates[0]);
        }
    }
}
