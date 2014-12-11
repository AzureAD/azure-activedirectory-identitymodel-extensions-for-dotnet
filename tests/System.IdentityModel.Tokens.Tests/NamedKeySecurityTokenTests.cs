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
    public class NamedKeySecurityTokenTests
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
        [TestProperty("TestCaseID", "3906d92b-a4c6-4542-a44e-4bab889abffc")]
        [Description("Tests: Constructors")]
        public void NamedKeySecurityToken_Constructors()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "1d1fb6f9-4c54-44fb-bc9d-038715699ae4")]
        [Description("Tests: Defaults")]
        public void NamedKeySecurityToken_Defaults()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "61ed551c-6af1-4d0a-afa4-cbe3c2970251")]
        [Description("Tests: GetSets")]
        public void NamedKeySecurityToken_GetSets()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "59b51dd5-2a89-41cb-99a7-daf06a3f6c6b")]
        [Description("Tests: Publics")]
        public void NamedKeySecurityToken_Publics()
        {
                    //            new NameKeyParametersVariation
                    //    {
                    //        TestCase = "NamedKeySecurityTokenString",
                    //        TestAction =
                    //            () =>
                    //            new NamedKeySecurityToken( null,  null )
                    //    },
                    //new NameKeyParametersVariation
                    //    {
                    //        TestCase = "NamedKeySecurityTokenKeys",
                    //        TestAction =
                    //            () =>
                    //            new NamedKeySecurityToken( "bob", null )
                    //    },
                    //new NameKeyParametersVariation
                    //    {
                    //        TestCase = "ResolveKeyIdentifierClause",
                    //        TestAction =
                    //            () =>
                    //            ( new NamedKeySecurityToken( "bob", new List<SecurityKey>() ) ).MatchesKeyIdentifierClause( null )
                    //    },

        }
    }
}