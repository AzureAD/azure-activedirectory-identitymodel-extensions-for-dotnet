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

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class NamedKeyIssuerTokenResolverTests
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
        [TestProperty("TestCaseID", "089441a0-082c-4569-93c4-eeeba8494b7f")]
        [Description("Tests: Constructors")]
        public void NamedKeyIssuerTokenResolver_Constructors()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "04d25374-ee1c-4cb3-a5a6-7b257adf762e")]
        [Description("Tests: Defaults")]
        public void NamedKeyIssuerTokenResolver_Defaults()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "1da9b007-ecce-4c89-b62b-6b5566539807")]
        [Description("Tests: GetSets")]
        public void NamedKeyIssuerTokenResolver_GetSets()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "5815a8e6-031f-4def-80af-825ced3f1148")]
        [Description("Tests: Publics")]
        public void NamedKeyIssuerTokenResolver_Publics()
        {
            //NameKeyParametersVariation[] variations =
            //    {
            //        new NameKeyParametersVariation
            //            {
            //                TestCase = "LoadCustomConfiguration",
            //                TestAction =
            //                    () =>
            //                    ( new NamedKeyIssuerTokenResolver( new Dictionary<string, IList<SecurityKey>>() ) ).LoadCustomConfiguration( null )
            //            },
            //    };

        }
    }
}