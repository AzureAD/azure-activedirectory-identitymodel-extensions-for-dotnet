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

using Microsoft.IdentityModel.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IdentityModel.Test;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Net;

namespace Microsoft.IdentityModel.Test
{
    [TestClass]
    public class OpenIdConnectMetadataRetrieverTests
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
        [TestProperty("TestCaseID", "436c5769-2eba-4ce6-9e6d-eb21862558b1")]
        [Description("Tests: Publics")]
        public async Task OpenIdConnectMetadataRetriever_Publics()
        {
            ExpectedException expectedException = ExpectedException.ArgumentNullException();
            await GetMetadataAsync(metadataUrl: null, httpClient: new HttpClient(), expectedException: expectedException);
            await GetMetadataAsync(metadataUrl: "bob", httpClient: null, expectedException: expectedException);
            // GetMetadata(document: null, expectedException: expectedException);
            await GetMetadataAsync(metadataUrl: SharedData.AADCommonUrl, httpClient: new HttpClient(), expectedException: ExpectedException.NoExceptionExpected);
            await GetMetadataAsync(metadataUrl: string.Empty, expectedException: ExpectedException.ArgumentNullException());
            OpenIdConnectMetadata metadata = await GetMetadataAsync(SharedData.AADCommonUrl, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsNotNull(metadata);

            metadata = await GetMetadataAsync(SharedData.OpenIdConnectMetadataFile, expectedException: ExpectedException.NoExceptionExpected);           
            Assert.IsTrue(IdentityComparer.AreEqual(metadata, SharedData.OpenIdConnectMetatdataWithKeys1));
            // TODO: Doesn't do the secondary resolve for keys
            metadata = GetMetadata(SharedData.OpenIdConnectMetadataString, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsTrue(IdentityComparer.AreEqual(metadata, SharedData.OpenIdConnectMetatdataWithKeys1));

            // url is not reachable
            metadata = await GetMetadataAsync(SharedData.BadUri, expectedException: ExpectedException.IOException(inner: typeof(WebException)));
            // TODO: Doesn't do the secondary resolve for keys
            // jwt_uri is not reachable
            metadata = GetMetadata(SharedData.OpenIdConnectMetadataBadUriKeysString, expectedException: ExpectedException.ArgumentException());

            // stream is not well formated
            metadata = GetMetadata(SharedData.OpenIdConnectMetadataBadFormatString, expectedException: new ExpectedException(typeExpected: typeof(ArgumentException)));    
            
            // jwt_uri points to bad formated JSON
            metadata = await GetMetadataAsync(SharedData.OpenIdConnectMetadataJsonWebKeysBadUriFile, expectedException: ExpectedException.IOException(inner: typeof(WebException)));

            metadata = GetMetadata(SharedData.OpenIdConnectMetadataSingleX509DataString, expectedException: ExpectedException.NoExceptionExpected);
            // TODO: Doesn't do the secondary resolve for keys
            Assert.IsTrue(IdentityComparer.AreEqual(metadata, SharedData.OpenIdConnectMetadataSingleX509Data1));

            GetMetadata(SharedData.OpenIdConnectMetadataBadX509DataString, expectedException: new ExpectedException(typeExpected: typeof(CryptographicException)));
            GetMetadata(SharedData.OpenIdConnectMetadataBadBase64DataString, expectedException: new ExpectedException(typeExpected: typeof(FormatException)));

            // ensure that each property can be set independently
            GetAndCheckMetadata("authorization_endpoint", "AuthorizationEndpoint");
            GetAndCheckMetadata("check_session_iframe", "CheckSessionIframe");
            GetAndCheckMetadata("end_session_endpoint", "EndSessionEndpoint");
            GetAndCheckMetadata("jwks_uri", "JwksUri", SharedData.AADCommonUrl);
            GetAndCheckMetadata("token_endpoint", "TokenEndpoint");
            GetAndCheckMetadata("user_info_endpoint", "UserInfoEndpoint");
        }

        private async Task<OpenIdConnectMetadata> GetMetadataAsync(string metadataUrl, HttpClient httpClient, ExpectedException expectedException)
        {
            OpenIdConnectMetadata openIdConnectMetadata = null;
            try
            {
                openIdConnectMetadata = await OpenIdConnectMetadataFactory.GetMetadataFromHttpAsync(metadataUrl, httpClient, CancellationToken.None);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return openIdConnectMetadata;
        }

        private async Task<OpenIdConnectMetadata> GetMetadataAsync(string metadataUrl, ExpectedException expectedException)
        {
            OpenIdConnectMetadata openIdConnectMetadata = null;
            try
            {
                openIdConnectMetadata = await OpenIdConnectMetadataFactory.GetMetadataAsync(metadataUrl, CancellationToken.None);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return openIdConnectMetadata;
        }

        private OpenIdConnectMetadata GetMetadata(string document, ExpectedException expectedException, OpenIdConnectMetadata expectedMetadata = null)
        {
            OpenIdConnectMetadata openIdConnectMetadata = null;
            try
            {
                openIdConnectMetadata = new OpenIdConnectMetadata(document);
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
    }
}
