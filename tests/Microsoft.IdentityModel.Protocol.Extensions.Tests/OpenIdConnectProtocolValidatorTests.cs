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
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class OpenIdConnectProtocolValidatorTests
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
        [TestProperty("TestCaseID", "ebe63b04-1a11-4cd7-8a8b-de07814ec85f")]
        [Description("Tests: Constructors")]
        public void OpenIdConnectProtocolValidator_Constructors()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "d120df74-7b5b-4ea2-b487-fa814d14e919")]
        [Description("Tests: Defaults")]
        public void OpenIdConnectProtocolValidator_Defaults()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "e905d825-a3ff-4461-a5a4-46d842d0c4ba")]
        [Description("Tests: GetSets")]
        public void OpenIdConnectProtocolValidator_GetSets()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "9a082558-f87e-4ae0-be80-852fbcf869d4")]
        [Description("Tests: Publics")]
        public void OpenIdConnectProtocolValidator_Publics()
        {
            ClaimsIdentity identity = new ClaimsIdentity();
        }

        [TestMethod]
        [TestProperty("TestCaseID", "9a082558-f87e-4ae0-be80-852fbcf869d4")]
        [Description("Tests: Validation of Nonce")]
        public void OpenIdConnectProtocolValidator_ValidateNonce()
        {
            ValidateNonce(jwt: null, nonce: null, ee: ExpectedException.ArgumentNullException());
            ValidateNonce(jwt: IdentityUtilities.CreateJwtSecurityToken(),  nonce: null, ee: ExpectedException.ArgumentNullException());
            ValidateNonce(jwt: IdentityUtilities.CreateJwtSecurityToken(), nonce: OpenIdConnectProtocolValidator.GenerateNonce(), ee: new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException)));

            ClaimsIdentity identity = new ClaimsIdentity();
        }

        private void ValidateNonce(JwtSecurityToken jwt, string nonce, ExpectedException ee)
        {
            try
            {
                OpenIdConnectProtocolValidator.ValidateNonce(jwt, nonce);
                ee.ProcessNoException();
            }
            catch(Exception ex)
            {
                ee.ProcessException(ex);
            }
        }
    }
}