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
        public void OpenIdConnectMetadataRetriever_Publics()
        {
            ExpectedException expectedException = ExpectedException.ArgumentNullException();
            GetMetadata(metadataUrl: null, httpClient: new HttpClient(), expectedException: expectedException);
            GetMetadata(metadataUrl: "bob", httpClient: null, expectedException: expectedException);
            GetMetadata(stream: null, expectedException: expectedException);
            GetMetadata(metadataUrl: SharedData.AADCommonUrl, httpClient: new HttpClient(), expectedException: ExpectedException.NoExceptionExpected);
            GetMetadata(metadataUrl: string.Empty, expectedException: ExpectedException.ArgumentNullException());
            OpenIdConnectMetadata metadata = GetMetadata(metadataUrl: SharedData.AADCommonUrl, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsNotNull(metadata);

            metadata = GetMetadata(SharedData.OpenIdConnectMetadataFile, expectedException: ExpectedException.NoExceptionExpected);           
            Assert.IsTrue(IdentityComparer.AreEqual(metadata, SharedData.OpenIdConnectMetatdataWithKeys1));

            Stream stream = new MemoryStream(Encoding.UTF8.GetBytes(SharedData.OpenIdConnectMetadataString));            
            metadata = GetMetadata(stream, expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsTrue(IdentityComparer.AreEqual(metadata, SharedData.OpenIdConnectMetatdataWithKeys1));

            // url is not reachable
            metadata = GetMetadata(SharedData.BadUri, expectedException: ExpectedException.ArgumentException());

            // jwt_uri is not reachable
            metadata = GetMetadata(new MemoryStream(Encoding.UTF8.GetBytes(SharedData.OpenIdConnectMetadataBadUriKeysString)), expectedException: ExpectedException.ArgumentException());

            // stream is not well formated
            metadata = GetMetadata(new MemoryStream(Encoding.UTF8.GetBytes(SharedData.OpenIdConnectMetadataBadFormatString)), expectedException: new ExpectedException(typeExpected: typeof(ArgumentException)));    
            
            // jwt_uri points to bad formated JSON
            metadata = GetMetadata(SharedData.OpenIdConnectMetadataJsonWebKeysBadUriFile, expectedException: new ExpectedException(typeExpected: typeof(ArgumentException)));

            metadata = GetMetadata(new MemoryStream(Encoding.UTF8.GetBytes(SharedData.OpenIdConnectMetadataSingleX509DataString)), expectedException: ExpectedException.NoExceptionExpected);
            Assert.IsTrue(IdentityComparer.AreEqual(metadata, SharedData.OpenIdConnectMetadataSingleX509Data1));
            GetMetadata(new MemoryStream(Encoding.UTF8.GetBytes(SharedData.OpenIdConnectMetadataBadX509DataString)), expectedException: new ExpectedException(typeExpected: typeof(CryptographicException)));
            GetMetadata(new MemoryStream(Encoding.UTF8.GetBytes(SharedData.OpenIdConnectMetadataBadBase64DataString)), expectedException: new ExpectedException(typeExpected: typeof(FormatException)));

            // ensure that each property can be set independently
            GetAndCheckMetadata("authorization_endpoint", "Authorization_Endpoint");
            GetAndCheckMetadata("check_session_iframe", "Check_Session_Iframe");
            GetAndCheckMetadata("end_session_endpoint", "End_Session_Endpoint");
            GetAndCheckMetadata("token_endpoint", "Token_Endpoint");
        }

        private OpenIdConnectMetadata GetMetadata(string metadataUrl, HttpClient httpClient, ExpectedException expectedException)
        {
            OpenIdConnectMetadata openIdConnectMetadata = null;
            try
            {
                openIdConnectMetadata = OpenIdConnectMetadataRetriever.GetMetadata(metadataUrl: metadataUrl, httpClient: httpClient);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return openIdConnectMetadata;
        }

        private OpenIdConnectMetadata GetMetadata(string metadataUrl, ExpectedException expectedException)
        {
            OpenIdConnectMetadata openIdConnectMetadata = null;
            try
            {
                openIdConnectMetadata = OpenIdConnectMetadataRetriever.GetMetadata(metadataUrl: metadataUrl);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return openIdConnectMetadata;
        }

        private OpenIdConnectMetadata GetMetadata(Stream stream, ExpectedException expectedException, OpenIdConnectMetadata expectedMetadata = null)
        {
            OpenIdConnectMetadata openIdConnectMetadata = null;
            try
            {
                openIdConnectMetadata = OpenIdConnectMetadataRetriever.GetMetadata(stream: stream);
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
                OpenIdConnectMetadata openIdConnectMetadata = OpenIdConnectMetadataRetriever.GetMetadata(stream: new MemoryStream(Encoding.UTF8.GetBytes(jsonString)));
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
