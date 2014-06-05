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
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.IdentityModel.Test
{
    [TestClass]
    public class OpenIdConnectConfigurationRetrieverTests
    {
        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void ClassSetup(TestContext testContext)
        {
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
        }

        [TestInitialize]
        public void Initialize()
        {
        }

        [TestMethod]
        public async Task OpenIdConnectConfigurationRetriever_FromNetwork()
        {
            OpenIdConnectConfiguration configuration = await GetConfigurationFromHttpAsync(SharedData.AADCommonUrl, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsNotNull(configuration);
            
            await GetConfigurationFromHttpAsync(string.Empty, expectedException: ExpectedException.ArgumentNullException());
            await GetConfigurationFromHttpAsync(SharedData.BadUri, expectedException: ExpectedException.IOException(inner: typeof(InvalidOperationException)));
        }
        
        [TestMethod]
        public async Task OpenIdConnectConfigurationRetriever_FromFile()
        {
            OpenIdConnectConfiguration configuration;
            configuration = await GetConfigurationAsync(SharedData.OpenIdConnectMetadataFile, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsTrue(IdentityComparer.AreEqual(configuration, SharedData.OpenIdConnectMetatdataWithKeys1));

            // jwt_uri points to bad formated JSON
            configuration = await GetConfigurationAsync(SharedData.OpenIdConnectMetadataJsonWebKeysBadUriFile, expectedException: ExpectedException.IOException(inner: typeof(WebException)));
        }

        [TestMethod]
        public async Task OpenIdConnectConfigurationRetriever_FromText()
        {
            OpenIdConnectConfiguration configuration;
            configuration = await GetConfigurationFromMixedAsync(SharedData.OpenIdConnectMetadataString, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsTrue(IdentityComparer.AreEqual(configuration, SharedData.OpenIdConnectMetatdataWithKeys1));

            // jwt_uri is not reachable
            await GetConfigurationFromTextAsync(SharedData.OpenIdConnectMetadataBadUriKeysString, string.Empty, expectedException: ExpectedException.IOException());

            // stream is not well formated
            await GetConfigurationFromTextAsync(SharedData.OpenIdConnectMetadataBadFormatString, string.Empty, expectedException: new ExpectedException(typeExpected: typeof(ArgumentException)));

            configuration = await GetConfigurationFromMixedAsync(SharedData.OpenIdConnectMetadataSingleX509DataString, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsTrue(IdentityComparer.AreEqual(configuration, SharedData.OpenIdConnectMetadataSingleX509Data1));

            await GetConfigurationFromMixedAsync(SharedData.OpenIdConnectMetadataBadX509DataString, expectedException: new ExpectedException(typeExpected: typeof(CryptographicException)));
            await GetConfigurationFromMixedAsync(SharedData.OpenIdConnectMetadataBadBase64DataString, expectedException: new ExpectedException(typeExpected: typeof(FormatException)));
        }

        [TestMethod]
        public void OpenIdConnectConfiguration_Properties()
        {
            // ensure that each property can be set independently
            GetAndCheckConfiguration("authorization_endpoint", "AuthorizationEndpoint");
            GetAndCheckConfiguration("check_session_iframe", "CheckSessionIframe");
            GetAndCheckConfiguration("end_session_endpoint", "EndSessionEndpoint");
            GetAndCheckConfiguration("jwks_uri", "JwksUri", SharedData.AADCommonUrl);
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
                    new TestDocumentRetriever(primaryDocument, secondaryDocument), "primary", CancellationToken.None);
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
                openIdConnectConfiguration = await OpenIdConnectConfigurationRetriever.GetAsync(
                    new TestDocumentRetriever(primaryDocument, new GenericDocumentRetriever()), "primary", CancellationToken.None);
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
