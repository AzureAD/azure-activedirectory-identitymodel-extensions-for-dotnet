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
using System.Collections.Generic;
using System.IdentityModel;
using System.IdentityModel.Tokens;
using System.Security.Claims;

using IMSaml2TokenHandler = Microsoft.IdentityModel.Tokens.Saml2SecurityTokenHandler;
using IMSamlTokenHandler = Microsoft.IdentityModel.Tokens.SamlSecurityTokenHandler;

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
            SecurityTokenHandlerCollection securityTokenValidators = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers();
            foreach (var tokenHandler in securityTokenValidators)
            {
                ISecurityTokenValidator tokenValidator = tokenHandler as ISecurityTokenValidator;
                Assert.IsNotNull(tokenValidator, "tokenHandler is not ISecurityTokenHandler, is" + tokenHandler.GetType().ToString());
            }

            securityTokenValidators = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers();
            foreach (var tokenHandler in securityTokenValidators)
            {
                ISecurityTokenValidator tokenValidator = tokenHandler as ISecurityTokenValidator;
                Assert.IsNotNull(tokenValidator, "tokenHandler is not ISecurityTokenHandler, is" + tokenHandler.GetType().ToString());             
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
            SecurityTokenHandlerCollection securityTokenValidators = new SecurityTokenHandlerCollection();
            string defaultSamlToken = IdentityUtilities.CreateSamlToken();
            string defaultSaml2Token = IdentityUtilities.CreateSaml2Token();
            string defaultJwt = IdentityUtilities.DefaultAsymmetricJwt;

            ExpectedException expectedException = ExpectedException.ArgumentNullException("Parameter name: securityToken");
            ValidateToken(null, null, securityTokenValidators, expectedException);

            expectedException = ExpectedException.ArgumentNullException("Parameter name: validationParameters");
            ValidateToken(defaultSamlToken, null, securityTokenValidators, expectedException);

            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters();
            expectedException = ExpectedException.SecurityTokenValidationException("IDX10201");
            ValidateToken(defaultSamlToken, tokenValidationParameters, securityTokenValidators, expectedException);

            securityTokenValidators = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers();
            expectedException = ExpectedException.SignatureVerificationFailedException(substringExpected: "ID4037");
            ValidateToken(defaultSamlToken, tokenValidationParameters, securityTokenValidators, expectedException);

            securityTokenValidators.Clear();
            securityTokenValidators.Add(new IMSamlTokenHandler());
            ValidateToken(defaultSamlToken, tokenValidationParameters, securityTokenValidators, ExpectedException.SignatureVerificationFailedException(substringExpected: "ID4037:"));
            ValidateToken(defaultSamlToken, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, securityTokenValidators, ExpectedException.NoExceptionExpected);
            ValidateToken(defaultSaml2Token, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, securityTokenValidators, ExpectedException.SecurityTokenValidationException(substringExpected: "IDX10201:"));
            securityTokenValidators.Add(new IMSaml2TokenHandler());
            securityTokenValidators.Add(new System.IdentityModel.Tokens.JwtSecurityTokenHandler());
            ValidateToken(defaultSaml2Token, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, securityTokenValidators, ExpectedException.NoExceptionExpected);
            ValidateToken(defaultJwt, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, securityTokenValidators, ExpectedException.NoExceptionExpected);
        }

        private void ValidateToken(string securityToken, TokenValidationParameters validationParameters, SecurityTokenHandlerCollection tokenHandlers, ExpectedException expectedException)
        {
            try
            {
                SecurityToken validatedToken;
                tokenHandlers.ValidateToken(securityToken, validationParameters, out validatedToken);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

        }
    }
}