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
using System;
using System.IdentityModel.Test;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using Saml2SecurityTokenHandler = Microsoft.IdentityModel.Extensions.Saml2SecurityTokenHandler;
using SamlSecurityTokenHandler = Microsoft.IdentityModel.Extensions.SamlSecurityTokenHandler;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// The purpose of these tests are to ensure that Saml, Saml2 and Jwt handling 
    /// results in the same exceptions, claims etc.
    /// </summary>
    [TestClass]
    public class CrossTokenTests
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
        [TestProperty("TestCaseID", "ADEFAC1A-07AC-4A0E-B49E-F7FF39CC2DD5")]
        [Description("Tests: Validates tokens")]
        public void CrossToken_ValidateToken()
        {
            string jwtToken = IdentityUtilities.DefaultAsymmetricJwt;
            string saml2Token = IdentityUtilities.CreateSaml2Token();
            string samlToken = IdentityUtilities.CreateSamlToken();

            JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();
            Saml2SecurityTokenHandler saml2Handler = new Saml2SecurityTokenHandler();
            SamlSecurityTokenHandler samlHandler = new SamlSecurityTokenHandler();

            ClaimsPrincipal jwtPrincipal = ValidateToken(jwtToken, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, jwtHandler, ExpectedException.NoExceptionExpected);
            ClaimsPrincipal saml2Principal = ValidateToken(samlToken, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, samlHandler, ExpectedException.NoExceptionExpected);
            ClaimsPrincipal samlPrincipal = ValidateToken(saml2Token, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, saml2Handler, ExpectedException.NoExceptionExpected);

            Assert.IsTrue(IdentityComparer.AreEqual(samlPrincipal, saml2Principal));

            // false = ignore type of objects, we expect all objects in the principal to be of same type (no derived types)
            // true = ignore subject, claims have a backpointer to their ClaimsIdentity.  Most of the time this will be different as we are comparing two different ClaimsIdentities.
            // true = ignore properties of claims, any mapped claims short to long for JWT's will have a property that represents the short type.
            Assert.IsTrue(IdentityComparer.AreEqual(jwtPrincipal, saml2Principal, false, true, true));
        }

        private ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, ISecurityTokenValidator tokenValidator, ExpectedException expectedException)
        {
            ClaimsPrincipal princiapl = null;
            try
            {
                princiapl = tokenValidator.ValidateToken(securityToken, validationParameters);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return princiapl;
        }


        [TestMethod]
        [TestProperty("TestCaseID", "c49e0f0a-decb-48a9-8695-25999ecfac59")]
        [Description("Tests: Validates Signatures")]
        public void CrossToken_ValidateSignature()
        {
            // TODO - when finalizing OM, ensure jwt, saml1 and saml2 work the same
        }

        [TestMethod]
        [TestProperty("TestCaseID", "fbed514b-d3ed-49ef-92ac-40a175cf6c6d")]
        [Description("Tests: Validate Audience")]
        public void CrossToken_ValidateAudience()
        {
            // TODO - when finalizing OM, ensure jwt, saml1 and saml2 work the same
        }

        [TestMethod]
        [TestProperty("TestCaseID", "a4d35cae-5312-4110-b2c0-325fbce4c085")]
        [Description("Tests: Validate Issuer")]
        public void CrossToken_ValidateIssuer()
        {
            // TODO - when finalizing OM, ensure jwt, saml1 and saml2 work the same
        }

        [TestMethod]
        [TestProperty("TestCaseID", "3f5f3a1f-49cc-495a-8198-7c321e870294")]
        [Description("Tests: ValidateLifetime")]
        public void CrossToken_ValidateLifetime()
        {
            // TODO - when finalizing OM, ensure jwt, saml1 and saml2 work the same
        }
    }
}