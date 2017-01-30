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

            // keyInfo in token doesn't match to signing key in validation parameters.
            tokenValidationParameters.IssuerSigningKey = KeyingMaterial.AsymmetricKey_1024;
            securityTokenValidators = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers();
            expectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException(substringExpected: "IDX10506:", innerTypeExpected: typeof(SignatureVerificationFailedException));
            ValidateToken(defaultSamlToken, tokenValidationParameters, securityTokenValidators, expectedException);
            ValidateToken(defaultSaml2Token, tokenValidationParameters, securityTokenValidators, expectedException);

            // keyInfo is null.
            const string startKeyInfo = "<KeyInfo>";
            const string endKeyInfo = "</KeyInfo>";
            int samlStart = defaultSamlToken.IndexOf(startKeyInfo);
            int samlEnd = defaultSamlToken.IndexOf(endKeyInfo);
            string nullKeyInfoSamlToken = defaultSamlToken.Remove(samlStart, samlEnd - samlStart + endKeyInfo.Length);
            int saml2Start = defaultSaml2Token.IndexOf(startKeyInfo);
            int saml2End = defaultSaml2Token.IndexOf(endKeyInfo);
            string nullKeyInfoSaml2Token = defaultSaml2Token.Remove(saml2Start, saml2End - saml2Start + endKeyInfo.Length);
            expectedException = ExpectedException.SignatureVerificationFailedException(substringExpected: "ID4037:");
            ValidateToken(nullKeyInfoSamlToken, tokenValidationParameters, securityTokenValidators, expectedException);
            ValidateToken(nullKeyInfoSaml2Token, tokenValidationParameters, securityTokenValidators, expectedException);

            // keyInfo is empty.
            string emptyKeyInfoSamlToken = defaultSamlToken.Remove(samlStart + startKeyInfo.Length, samlEnd - samlStart - startKeyInfo.Length);
            string emptyKeyInfoSaml2Token = defaultSaml2Token.Remove(saml2Start + startKeyInfo.Length, saml2End - saml2Start - startKeyInfo.Length);
            ValidateToken(emptyKeyInfoSamlToken, tokenValidationParameters, securityTokenValidators, expectedException);
            ValidateToken(emptyKeyInfoSaml2Token, tokenValidationParameters, securityTokenValidators, expectedException);

            // There is no any of SigningKey/SigningKeys/SigningToken/SigningTokens/IssuerSigningKeyResolver in validation parameters.
            tokenValidationParameters = new TokenValidationParameters();
            ValidateToken(defaultSamlToken, tokenValidationParameters, securityTokenValidators, expectedException);
            ValidateToken(defaultSaml2Token, tokenValidationParameters, securityTokenValidators, expectedException);

            securityTokenValidators.Clear();
            securityTokenValidators.Add(new IMSamlTokenHandler());
            ValidateToken(defaultSamlToken, tokenValidationParameters, securityTokenValidators, ExpectedException.SignatureVerificationFailedException(substringExpected: "ID4037:"));
            ValidateToken(defaultSamlToken, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, securityTokenValidators, ExpectedException.NoExceptionExpected);
            ValidateToken(defaultSaml2Token, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, securityTokenValidators, ExpectedException.SecurityTokenValidationException(substringExpected: "IDX10201:"));
            securityTokenValidators.Add(new IMSaml2TokenHandler());
            securityTokenValidators.Add(new System.IdentityModel.Tokens.JwtSecurityTokenHandler());
            ValidateToken(defaultSaml2Token, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, securityTokenValidators, ExpectedException.NoExceptionExpected);
            ValidateToken(defaultJwt, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, securityTokenValidators, ExpectedException.NoExceptionExpected);
            
            //Multiple SigningKeys
            tokenValidationParameters = new TokenValidationParameters();
            tokenValidationParameters.IssuerSigningKeys = new[] { KeyingMaterial.AsymmetricKey_1024, KeyingMaterial.DefaultAsymmetricKey_2048 };
            tokenValidationParameters.AudienceValidator = (audiences, token, parameters) => true;
            tokenValidationParameters.ValidIssuer = IdentityUtilities.DefaultIssuer;
            securityTokenValidators = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers();
            ValidateToken(defaultSamlToken, tokenValidationParameters, securityTokenValidators, ExpectedException.NoExceptionExpected);
            //support multiple keys in any order
            tokenValidationParameters.IssuerSigningKeys = new[] { KeyingMaterial.DefaultAsymmetricKey_2048, KeyingMaterial.AsymmetricKey_1024 };
            ValidateToken(defaultSamlToken, tokenValidationParameters, securityTokenValidators, ExpectedException.NoExceptionExpected);
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