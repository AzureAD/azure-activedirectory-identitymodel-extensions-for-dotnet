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
using System;
using System.IdentityModel;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class SecurityTokenHandlerCollectionExtensionsTests
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
        [TestProperty("TestCaseID", "603183b5-7716-4a8a-930c-22b809ea867e")]
        [Description("Tests: Constructors")]
        public void SecurityTokenHandlerCollectionExtensions_Constructors()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "d9d1d67a-dc5a-4f10-86ca-7c95ae1a3403")]
        [Description("Tests: Defaults")]
        public void SecurityTokenHandlerCollectionExtensions_Defaults()
        {
            SecurityTokenHandlerCollection securityTokenHandlerCollection = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers();
            foreach(SecurityTokenHandler tokenHandler in securityTokenHandlerCollection)
            {
                ISecurityTokenValidator tokenValidator = tokenHandler as ISecurityTokenValidator;
                Assert.IsNotNull(tokenValidator, "tokenHandler is not ISecurityTokenHandler, is" + tokenHandler.GetType().ToString());
                Assert.AreEqual(tokenValidator.AuthenticationType, AuthenticationTypes.Federation);
            }

            securityTokenHandlerCollection = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers(typeof(ISecurityTokenValidator).ToString());
            foreach (SecurityTokenHandler tokenHandler in securityTokenHandlerCollection)
            {
                ISecurityTokenValidator tokenValidator = tokenHandler as ISecurityTokenValidator;
                Assert.IsNotNull(tokenValidator, "tokenHandler is not ISecurityTokenHandler, is" + tokenHandler.GetType().ToString());
                Assert.AreEqual(tokenValidator.AuthenticationType, (typeof(ISecurityTokenValidator).ToString()));
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "1b96ccf4-bd97-4224-91cd-4b90fb3723fc")]
        [Description("Tests: GetSets")]
        public void SecurityTokenHandlerCollectionExtensions_GetSets()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "e5e10a35-574d-4f62-b80c-7ae6bb946639")]
        [Description("Tests: Publics")]
        public void SecurityTokenHandlerCollectionExtensions_Publics()
        {
            SecurityTokenHandlerCollection securityTokenHandlerCollection = new SecurityTokenHandlerCollection();
            string defaultSamlToken = IdentityUtilities.CreateSamlToken();

            ExpectedException expectedException = ExpectedException.ArgumentNullException("Parameter name: securityToken");
            ValidateToken(null, null, securityTokenHandlerCollection, expectedException);

            expectedException = ExpectedException.ArgumentNullException("Parameter name: validationParameters");
            ValidateToken(defaultSamlToken, null, securityTokenHandlerCollection, expectedException);

            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters();
            expectedException = ExpectedException.SecurityTokenValidationException("IDX10201");
            ValidateToken(defaultSamlToken, tokenValidationParameters, securityTokenHandlerCollection, expectedException);

            securityTokenHandlerCollection = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers();
            expectedException = new ExpectedException(typeExpected: typeof(SignatureVerificationFailedException), substringExpected: "ID4037");
            ValidateToken(IdentityUtilities.CreateSamlToken(), tokenValidationParameters, securityTokenHandlerCollection, expectedException);

            securityTokenHandlerCollection = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers();
            securityTokenHandlerCollection.RemoveAt(1);
            expectedException = new ExpectedException(typeExpected: typeof(SecurityTokenValidationException), substringExpected: "IDX10201");
            ValidateToken(IdentityUtilities.CreateSamlToken(), tokenValidationParameters, securityTokenHandlerCollection, expectedException);

        }

        private void ValidateToken(string securityToken, TokenValidationParameters tokenValidationParameters, SecurityTokenHandlerCollection securityTokenHandlerCollection, ExpectedException expectedException)
        {
            try
            {
                securityTokenHandlerCollection.ValidateToken(securityToken, tokenValidationParameters);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

        }
    }
}