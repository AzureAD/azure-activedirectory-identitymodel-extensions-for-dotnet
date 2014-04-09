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
using System.Net.Http;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
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
        [TestProperty("TestCaseID", "e026184d-10e6-4e9f-aece-0e4b582abc4f")]
        [Description("Tests: Constructors")]
        public void OpenIdConnectMetadataRetriever_Constructors()
        {
            try
            {
                OpenIdConnectMetadataRetriever.GetMetatadata(metadataEndpoint: (string)null, httpClient: (HttpClient)null);
            }
            catch(Exception ex)
            {
                Assert.AreEqual(ex.GetType(), typeof(ArgumentNullException));
            }

            try
            {
                OpenIdConnectMetadataRetriever.GetMetatadata(metadataEndpoint: "bob", httpClient: (HttpClient)null);
            }
            catch (Exception ex)
            {
                Assert.AreEqual(ex.GetType(), typeof(ArgumentNullException));
            }

        }

        [TestMethod]
        [TestProperty("TestCaseID", "1f7e8a6e-fd10-4b64-8970-22b484a66f81")]
        [Description("Tests: Defaults")]
        public void OpenIdConnectMetadataRetriever_Defaults()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "77a379e2-3281-47fc-be59-0537a0cd2742")]
        [Description("Tests: GetSets")]
        public void OpenIdConnectMetadataRetriever_GetSets()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "436c5769-2eba-4ce6-9e6d-eb21862558b1")]
        [Description("Tests: Publics")]
        public void OpenIdConnectMetadataRetriever_Publics()
        {
        }
    }
}