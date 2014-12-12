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
using System.IdentityModel.Test;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Xunit;

namespace Microsoft.IdentityModel.Test
{
    public class OpenIdConnectConfigurationRetrieverTests
    {

        [Fact]
        public async Task OpenIdConnectConfigurationRetriever_FromNetwork()
        {
            OpenIdConnectConfiguration configuration = await GetConfigurationFromHttpAsync(OpenIdConfigData.AADCommonUrl, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsNotNull(configuration);
            
            await GetConfigurationFromHttpAsync(string.Empty, expectedException: ExpectedException.ArgumentNullException());
            await GetConfigurationFromHttpAsync(OpenIdConfigData.BadUri, expectedException: ExpectedException.IOException(inner: typeof(InvalidOperationException)));
        }

        [Fact]

        public async Task OpenIdConnectConfigurationRetriever_FromFile()
        {
            OpenIdConnectConfiguration configuration;
            configuration = await GetConfigurationAsync(OpenIdConfigData.OpenIdConnectMetadataFile, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsTrue(IdentityComparer.AreEqual(configuration, OpenIdConfigData.OpenIdConnectConfigurationWithKeys1));

            // jwt_uri points to bad formated JSON
            configuration = await GetConfigurationAsync(OpenIdConfigData.OpenIdConnectMetadataJsonWebKeySetBadUriFile, expectedException: ExpectedException.IOException(inner: typeof(WebException)));
        }

        [Fact]
        public async Task OpenIdConnectConfigurationRetriever_FromText()
        {
            OpenIdConnectConfiguration configuration;

            configuration = await GetConfigurationFromMixedAsync(OpenIdConfigData.OpenIdConnectMetadataPingString, expectedException: ExpectedException.NoExceptionExpected);

            configuration = await GetConfigurationFromMixedAsync(OpenIdConfigData.OpenIdConnectMetadataPingLabsJWKSString, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsTrue(IdentityComparer.AreEqual(configuration, OpenIdConfigData.OpenIdConnectConfigurationPingLabsJWKS));

            configuration = await GetConfigurationFromMixedAsync(OpenIdConfigData.OpenIdConnectMetadataString, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsTrue(IdentityComparer.AreEqual(configuration, OpenIdConfigData.OpenIdConnectConfigurationWithKeys1));

            // jwt_uri is not reachable
            await GetConfigurationFromTextAsync(OpenIdConfigData.OpenIdConnectMetadataBadUriKeysString, string.Empty, expectedException: ExpectedException.IOException());

            // stream is not well formated
            await GetConfigurationFromTextAsync(OpenIdConfigData.OpenIdConnectMetadataBadFormatString, string.Empty, expectedException: new ExpectedException(typeExpected: typeof(ArgumentException)));

            configuration = await GetConfigurationFromMixedAsync(OpenIdConfigData.OpenIdConnectMetadataSingleX509DataString, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsTrue(IdentityComparer.AreEqual(configuration, OpenIdConfigData.OpenIdConnectConfigurationSingleX509Data1));

            await GetConfigurationFromMixedAsync(OpenIdConfigData.OpenIdConnectMetadataBadX509DataString, expectedException: ExpectedException.InvalidOperationException(inner: typeof(CryptographicException)));
            await GetConfigurationFromMixedAsync(OpenIdConfigData.OpenIdConnectMetadataBadBase64DataString, expectedException: ExpectedException.InvalidOperationException(inner: typeof(FormatException)));
        }

        [Fact]
        public void OpenIdConnectConfiguration_Properties()
        {
            // ensure that each property can be set independently
            GetAndCheckConfiguration("authorization_endpoint", "AuthorizationEndpoint");
            GetAndCheckConfiguration("check_session_iframe", "CheckSessionIframe");
            GetAndCheckConfiguration("end_session_endpoint", "EndSessionEndpoint");
            GetAndCheckConfiguration("jwks_uri", "JwksUri", OpenIdConfigData.AADCommonUrl);
            GetAndCheckConfiguration("token_endpoint", "TokenEndpoint");
            GetAndCheckConfiguration("user_info_endpoint", "UserInfoEndpoint");
        }

        private async Task<OpenIdConnectConfiguration> GetConfigurationFromHttpAsync(string uri, ExpectedException expectedException, OpenIdConnectConfiguration expectedConfiguration = null)
        {
            OpenIdConnectConfiguration openIdConnectConfiguration = null;
            try
            {
                openIdConnectConfiguration = await OpenIdConnectConfigurationRetriever.GetAsync(uri, new HttpClient(), CancellationToken.None);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            if (expectedConfiguration != null)
            {
                Assert.IsTrue(IdentityComparer.AreEqual(openIdConnectConfiguration, expectedConfiguration));
            }

            return openIdConnectConfiguration;
        }

        private async Task<OpenIdConnectConfiguration> GetConfigurationAsync(string uri, ExpectedException expectedException, OpenIdConnectConfiguration expectedConfiguration = null)
        {
            OpenIdConnectConfiguration openIdConnectConfiguration = null;
            try
            {
                openIdConnectConfiguration = await OpenIdConnectConfigurationRetriever.GetAsync(uri, CancellationToken.None);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            if (expectedConfiguration != null)
            {
                Assert.IsTrue(IdentityComparer.AreEqual(openIdConnectConfiguration, expectedConfiguration));
            }

            return openIdConnectConfiguration;
        }

        private async Task<OpenIdConnectConfiguration> GetConfigurationFromTextAsync(string primaryDocument, string secondaryDocument, ExpectedException expectedException, OpenIdConnectConfiguration expectedConfiguration = null)
        {
            OpenIdConnectConfiguration openIdConnectConfiguration = null;
            try
            {
                openIdConnectConfiguration = await OpenIdConnectConfigurationRetriever.GetAsync(
                     "primary", new TestDocumentRetriever(primaryDocument, secondaryDocument), CancellationToken.None);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            if (expectedConfiguration != null)
            {
                Assert.IsTrue(IdentityComparer.AreEqual(openIdConnectConfiguration, expectedConfiguration));
            }

            return openIdConnectConfiguration;
        }

        private async Task<OpenIdConnectConfiguration> GetConfigurationFromMixedAsync(string primaryDocument, ExpectedException expectedException, OpenIdConnectConfiguration expectedConfiguration = null)
        {
            OpenIdConnectConfiguration openIdConnectConfiguration = null;
            try
            {
                openIdConnectConfiguration = await OpenIdConnectConfigurationRetriever.GetAsync("primary",
                    new TestDocumentRetriever(primaryDocument, new GenericDocumentRetriever()), CancellationToken.None));
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            if (expectedConfiguration != null)
            {
                Assert.IsTrue(IdentityComparer.AreEqual(openIdConnectConfiguration, expectedConfiguration));
            }

            return openIdConnectConfiguration;
        }

        private void GetAndCheckConfiguration(string jsonName, string propertyName, string propertyValue=null)
        {
            string jsonValue = propertyValue;
            if (jsonValue == null)
            {
                jsonValue = Guid.NewGuid().ToString();
            }

            string jsonString = @"{""" + jsonName + @""":""" + jsonValue + @"""}";
            try
            {
                OpenIdConnectConfiguration openIdConnectConfiguration = new OpenIdConnectConfiguration(jsonString);
                OpenIdConnectConfiguration expectedConfiguration = new OpenIdConnectConfiguration();
                TestUtilities.SetProperty(expectedConfiguration, propertyName, jsonValue);
                Assert.IsTrue(IdentityComparer.AreEqual(openIdConnectConfiguration, expectedConfiguration));
            }
            catch (Exception exception)
            {
                ExpectedException.NoExceptionExpected.ProcessException(exception);
            }

            return;
        }

        private class TestDocumentRetriever : IDocumentRetriever
        {
            private string _primaryDocument;
            private string _secondaryDocument;
            private IDocumentRetriever _fallback;

            public TestDocumentRetriever(string primaryDocument, string secondaryDocument)
            {
                _primaryDocument = primaryDocument;
                _secondaryDocument = secondaryDocument;
            }

            public TestDocumentRetriever(string primaryDocument, IDocumentRetriever fallback)
            {
                _primaryDocument = primaryDocument;
                _fallback = fallback;
            }
            
            public Task<string> GetDocumentAsync(string address, CancellationToken cancel)
            {
                if (string.Equals("primary", address))
                {
                    return Task.FromResult(_primaryDocument);
                }
                if (string.Equals("secondary", address) && !string.IsNullOrWhiteSpace(_secondaryDocument))
                {
                    return Task.FromResult(_secondaryDocument);
                }
                if (_fallback != null)
                {
                    return _fallback.GetDocumentAsync(address, cancel);
                }
                throw new IOException("Document not found: " + address);
            }
        }
    }
}
