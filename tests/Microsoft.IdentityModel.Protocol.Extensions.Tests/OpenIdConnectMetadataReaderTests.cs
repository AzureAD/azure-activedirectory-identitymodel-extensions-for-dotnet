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
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.IdentityModel.Test
{
    [TestClass]
    public class OpenIdConnectMetadataReaderTests
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
        public async Task OpenIdConnectMetadataReader_ReadFromNetwork()
        {
            ExpectedException expectedException = ExpectedException.ArgumentNullException();

            await GetMetadataFromNetworkAsync(SharedData.AADCommonUrl, expectedException: ExpectedException.NoExceptionExpected);

            await GetMetadataFromNetworkAsync(string.Empty, expectedException: ExpectedException.ArgumentNullException());

            OpenIdConnectMetadata metadata = await GetMetadataFromNetworkAsync(SharedData.AADCommonUrl, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsNotNull(metadata);
            // url is not reachable
            metadata = await GetMetadataFromNetworkAsync(SharedData.BadUri, expectedException: ExpectedException.IOException(inner: typeof(InvalidOperationException)));
        }
        
        [TestMethod]
        public async Task OpenIdConnectMetadataReader_ReadFromFile()
        {
            OpenIdConnectMetadata metadata;
            metadata = await GetMetadataFromFileAsync(SharedData.OpenIdConnectMetadataFile, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsTrue(IdentityComparer.AreEqual(metadata, SharedData.OpenIdConnectMetatdataWithKeys1));

            // jwt_uri points to bad formated JSON
            metadata = await GetMetadataFromFileAsync(SharedData.OpenIdConnectMetadataJsonWebKeysBadUriFile, expectedException: ExpectedException.IOException(inner: typeof(FileNotFoundException)));
        }

        [TestMethod]
        public async Task OpenIdConnectMetadataReader_ReadFromText()
        {
            OpenIdConnectMetadata metadata;
            metadata = await GetMetadataFromMixedAsync(SharedData.OpenIdConnectMetadataString, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsTrue(IdentityComparer.AreEqual(metadata, SharedData.OpenIdConnectMetatdataWithKeys1));

            // jwt_uri is not reachable
            metadata = await GetMetadataFromTextAsync(SharedData.OpenIdConnectMetadataBadUriKeysString, string.Empty, expectedException: ExpectedException.IOException());

            // stream is not well formated
            metadata = await GetMetadataFromTextAsync(SharedData.OpenIdConnectMetadataBadFormatString, string.Empty, expectedException: new ExpectedException(typeExpected: typeof(ArgumentException)));

            metadata = await GetMetadataFromMixedAsync(SharedData.OpenIdConnectMetadataSingleX509DataString, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsTrue(IdentityComparer.AreEqual(metadata, SharedData.OpenIdConnectMetadataSingleX509Data1));

            await GetMetadataFromMixedAsync(SharedData.OpenIdConnectMetadataBadX509DataString, expectedException: new ExpectedException(typeExpected: typeof(CryptographicException)));
            await GetMetadataFromMixedAsync(SharedData.OpenIdConnectMetadataBadBase64DataString, expectedException: new ExpectedException(typeExpected: typeof(FormatException)));
        }

        [TestMethod]
        public void OpenIdConnectMetadata_Properties()
        {
            // ensure that each property can be set independently
            GetAndCheckMetadata("authorization_endpoint", "AuthorizationEndpoint");
            GetAndCheckMetadata("check_session_iframe", "CheckSessionIframe");
            GetAndCheckMetadata("end_session_endpoint", "EndSessionEndpoint");
            GetAndCheckMetadata("jwks_uri", "JwksUri", SharedData.AADCommonUrl);
            GetAndCheckMetadata("token_endpoint", "TokenEndpoint");
            GetAndCheckMetadata("user_info_endpoint", "UserInfoEndpoint");
        }

        private async Task<OpenIdConnectMetadata> GetMetadataFromNetworkAsync(string uri, ExpectedException expectedException, OpenIdConnectMetadata expectedMetadata = null)
        {
            OpenIdConnectMetadata openIdConnectMetadata = null;
            try
            {
                OpenIdConnectMetadataReader reader = new OpenIdConnectMetadataReader();
                openIdConnectMetadata = await reader.ReadMetadataAysnc(new HttpDocumentRetriever(), uri, CancellationToken.None);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            if (expectedMetadata != null)
            {
                Assert.IsTrue(IdentityComparer.AreEqual(openIdConnectMetadata, expectedMetadata));
            }

            return openIdConnectMetadata;
        }

        private async Task<OpenIdConnectMetadata> GetMetadataFromFileAsync(string uri, ExpectedException expectedException, OpenIdConnectMetadata expectedMetadata = null)
        {
            OpenIdConnectMetadata openIdConnectMetadata = null;
            try
            {
                OpenIdConnectMetadataReader reader = new OpenIdConnectMetadataReader();
                openIdConnectMetadata = await reader.ReadMetadataAysnc(new FileDocumentRetriever(), uri, CancellationToken.None);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            if (expectedMetadata != null)
            {
                Assert.IsTrue(IdentityComparer.AreEqual(openIdConnectMetadata, expectedMetadata));
            }

            return openIdConnectMetadata;
        }

        private async Task<OpenIdConnectMetadata> GetMetadataFromTextAsync(string primaryDocument, string secondaryDocument, ExpectedException expectedException, OpenIdConnectMetadata expectedMetadata = null)
        {
            OpenIdConnectMetadata openIdConnectMetadata = null;
            try
            {
                OpenIdConnectMetadataReader reader = new OpenIdConnectMetadataReader();
                openIdConnectMetadata = await reader.ReadMetadataAysnc(new TestDocumentRetriever(primaryDocument, secondaryDocument), "primary", CancellationToken.None);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            if (expectedMetadata != null)
            {
                Assert.IsTrue(IdentityComparer.AreEqual(openIdConnectMetadata, expectedMetadata));
            }

            return openIdConnectMetadata;
        }

        private async Task<OpenIdConnectMetadata> GetMetadataFromMixedAsync(string primaryDocument, ExpectedException expectedException, OpenIdConnectMetadata expectedMetadata = null)
        {
            OpenIdConnectMetadata openIdConnectMetadata = null;
            try
            {
                OpenIdConnectMetadataReader reader = new OpenIdConnectMetadataReader();
                openIdConnectMetadata = await reader.ReadMetadataAysnc(new TestDocumentRetriever(primaryDocument, new FileDocumentRetriever()), "primary", CancellationToken.None);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            if (expectedMetadata != null)
            {
                Assert.IsTrue(IdentityComparer.AreEqual(openIdConnectMetadata, expectedMetadata));
            }

            return openIdConnectMetadata;
        }

        private void GetAndCheckMetadata(string jsonName, string propertyName, string propertyValue=null)
        {
            string jsonValue = propertyValue;
            if (jsonValue == null)
            {
                jsonValue = Guid.NewGuid().ToString();
            }

            string jsonString = @"{""" + jsonName + @""":""" + jsonValue + @"""}";
            try
            {
                OpenIdConnectMetadata openIdConnectMetadata = new OpenIdConnectMetadata(jsonString);
                OpenIdConnectMetadata expectedMetadata = new OpenIdConnectMetadata();
                TestUtilities.SetProperty(expectedMetadata, propertyName, jsonValue);
                Assert.IsTrue(IdentityComparer.AreEqual(openIdConnectMetadata, expectedMetadata));
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
