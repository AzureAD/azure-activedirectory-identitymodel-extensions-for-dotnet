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

using Microsoft.IdentityModel.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Security.Claims;
using System.Xml;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class IdentitySerializerTests
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
        [TestProperty("TestCaseID", "IdentitySerializer-CFB7A712-9FA8-4A31-8446-2EA93CECC2AC")]
        [Description("Tests: Constructors")]
        public void TestTemplate_Constructors()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "IdentitySerializer-B644D6D6-26C0-4417-AF9C-F59CFC5E7903")]
        [Description("Tests: Defaults")]
        public void TestTemplate_Defaults()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "IdentitySerializer-E3499C32-5062-4F89-A209-3024613EB73B")]
        [Description("Tests: GetSets")]
        public void TestTemplate_GetSets()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "IdentitySerializer-38024A53-CF6A-48C4-8AF3-E9C97E2B86FC")]
        [Description("Tests: Publics")]
        public void TestTemplate_Publics()
        {
            ClaimsIdentity claimsIdentity = IdentityUtilities.SimpleClaimsIdentity;
            byte[] claimsPrincipalSerializerCompressed = ClaimsPrincipalSerializer.WriteClaimsIdentity(claimsIdentity);
            claimsIdentity = ClaimsPrincipalSerializer.ReadClaimsIdentity(claimsPrincipalSerializerCompressed);
            byte[] claimsPrincipalSerializer = ClaimsPrincipalSerializer.WriteClaimsIdentity(claimsIdentity, false);
            claimsIdentity = ClaimsPrincipalSerializer.ReadClaimsIdentity(claimsPrincipalSerializerCompressed, false);

            byte[] claimsIdentitySerializer = ClaimsIdentitySerializer.Serialize(claimsIdentity);
        }
    }
}

