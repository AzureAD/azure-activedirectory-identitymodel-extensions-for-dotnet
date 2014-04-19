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
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Xml;
using Saml2SecurityTokenHandler = Microsoft.IdentityModel.Extensions.Saml2SecurityTokenHandler;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class Saml2SecurityTokenHandlerTests
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
        [TestProperty("TestCaseID", "f0b4edf5-e1bd-448f-9c0f-50b2a47bfd24")]
        [Description("Tests: Constructors")]
        public void Saml2SecurityTokenHandlerTests_Constructors()
        {
            Saml2SecurityTokenHandler saml2SecurityTokenHandler = new Saml2SecurityTokenHandler();
        }

        [TestMethod]
        [TestProperty("TestCaseID", "1832c430-b491-48db-86bb-59faf72304bd")]
        [Description("Tests: Defaults")]
        public void Saml2SecurityTokenHandlerTests_Defaults()
        {
            Saml2SecurityTokenHandler samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            Assert.IsTrue(samlSecurityTokenHandler.AuthenticationType == AuthenticationTypes.Federation, "AuthenticationType");
            Assert.IsTrue(samlSecurityTokenHandler.ClockSkewInSeconds == Saml2SecurityTokenHandler.DefaultClockSkewInSeconds, "ClockSkewInSeconds");
            Assert.IsTrue(samlSecurityTokenHandler.MaximumTokenSizeInBytes == Saml2SecurityTokenHandler.DefaultMaximumTokenSizeInBytes, "MaximumTokenSizeInBytes");
            Assert.IsTrue(Saml2SecurityTokenHandler.DefaultClockSkewInSeconds == 300, "DefaultClockSkewInSeconds");
            Assert.IsTrue(Saml2SecurityTokenHandler.DefaultMaximumTokenSizeInBytes == Saml2SecurityTokenHandler.DefaultMaximumTokenSizeInBytes, "Saml2SecurityTokenHandler");
            Int32 maximumTokenSizeInBytes = 1024 * 1024 * 2;
            Assert.IsTrue(Saml2SecurityTokenHandler.DefaultMaximumTokenSizeInBytes == maximumTokenSizeInBytes, "DefaultMaximumTokenSizeInBytes");
        }

        [TestMethod]
        [TestProperty("TestCaseID", "e40d2758-e36c-4b52-9ac9-31bcfc27c308")]
        [Description("Tests: GetSets")]
        public void Saml2SecurityTokenHandlerTests_GetSets()
        {
            Saml2SecurityTokenHandler samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            TestUtilities.GetSet(samlSecurityTokenHandler, "AuthenticationType", null, ExpectedException.ArgumentNullException(substringExpected: "AuthenticationType"));
            TestUtilities.GetSet(samlSecurityTokenHandler, "AuthenticationType", "   ", ExpectedException.ArgumentNullException(substringExpected: "AuthenticationType"));
            TestUtilities.GetSet(samlSecurityTokenHandler, "AuthenticationType", "AuthenticationType", ExpectedException.NoExceptionExpected);

            TestUtilities.GetSet(samlSecurityTokenHandler, "ClockSkewInSeconds", (object)0, ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10100"));
            TestUtilities.GetSet(samlSecurityTokenHandler, "ClockSkewInSeconds", (object)1, ExpectedException.NoExceptionExpected);

            TestUtilities.GetSet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)0, ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10101"));
            TestUtilities.GetSet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)1, ExpectedException.NoExceptionExpected);
        }

        [TestMethod]
        [TestProperty("TestCaseID", "617fb57a-9b95-40a3-8cf4-652b33450a54")]
        [Description("Tests: Publics")]
        public void Saml2SecurityTokenHandlerTests_Publics()
        {
            CanReadToken();
            ValidateAudience();
            ValidateIssuer();
            ValidateToken();
        }

        private void CanReadToken()
        {
            // CanReadToken
            Saml2SecurityTokenHandler samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            ExpectedException expectedException = ExpectedException.ArgumentNullException("securityToken");
            CanReadToken(securityToken: null, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            string samlString = new string('S', Saml2SecurityTokenHandler.DefaultMaximumTokenSizeInBytes + 1);
            expectedException = ExpectedException.NoExceptionExpected;
            Assert.IsFalse(CanReadToken(samlString, samlSecurityTokenHandler, expectedException));

            samlString = new string('S', Saml2SecurityTokenHandler.DefaultMaximumTokenSizeInBytes);
            expectedException = new ExpectedException(typeExpected: typeof(XmlException));
            CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            samlString = IdentityUtilities.CreateSamlToken();
            expectedException = ExpectedException.NoExceptionExpected;
            Assert.IsFalse(CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException));

            samlString = IdentityUtilities.CreateSamlToken();
            expectedException = ExpectedException.NoExceptionExpected;
            Assert.IsFalse(CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException));

        }

        private bool CanReadToken(string securityToken, Saml2SecurityTokenHandler samlSecurityTokenHandler, ExpectedException expectedException)
        {
            bool canReadToken = false;
            try
            {
                canReadToken = samlSecurityTokenHandler.CanReadToken(securityToken);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return canReadToken;
        }

        private void ValidateIssuer()
        {
            Saml2SecurityTokenHandler samlSecurityTokenHandler = new Saml2SecurityTokenHandler();

            ExpectedException expectedException = ExpectedException.ArgumentNullException(substringExpected: "Parameter name: validationParameters");
            ValidateIssuer(null, null, samlSecurityTokenHandler, expectedException);

            expectedException = ExpectedException.SecurityTokenInvalidIssuerException( substringExpected: "IDX10211");
            ValidateIssuer(null, new TokenValidationParameters { ValidateIssuer = false }, samlSecurityTokenHandler, expectedException);

            expectedException = ExpectedException.SecurityTokenInvalidIssuerException( substringExpected: "IDX10211");
            ValidateIssuer(null, new TokenValidationParameters(), samlSecurityTokenHandler, expectedException);

            expectedException = ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10204");
            ValidateIssuer("bob", new TokenValidationParameters { }, samlSecurityTokenHandler, expectedException);

            expectedException = ExpectedException.NoExceptionExpected;
            string issuer = ValidateIssuer("bob", new TokenValidationParameters { ValidIssuer = "bob" }, samlSecurityTokenHandler, expectedException);
            Assert.IsTrue(issuer == "bob", "issuer mismatch");

            expectedException = ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205");
            ValidateIssuer("bob", new TokenValidationParameters { ValidIssuer = "frank" }, samlSecurityTokenHandler, expectedException);

            List<string> validIssuers = new List<string> { "john", "paul", "george", "ringo" };
            expectedException = ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205");
            ValidateIssuer("bob", new TokenValidationParameters { ValidIssuers = validIssuers }, samlSecurityTokenHandler, expectedException);

            expectedException = ExpectedException.NoExceptionExpected;
            ValidateIssuer("bob", new TokenValidationParameters { ValidateIssuer = false }, samlSecurityTokenHandler, expectedException);

            validIssuers.Add("bob");
            expectedException = ExpectedException.NoExceptionExpected;
            issuer = ValidateIssuer("bob", new TokenValidationParameters { ValidIssuers = validIssuers }, samlSecurityTokenHandler, expectedException);
            Assert.IsTrue(issuer == "bob", "issuer mismatch");

            expectedException = ExpectedException.NoExceptionExpected;
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                IssuerValidator =
                    (tokenIssuer, token) =>
                    {
                        return true;
                    },
            };

            ValidateIssuer("bob", validationParameters, samlSecurityTokenHandler, expectedException);
                        
            // delegate returns false, secondary should still succeed
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidIssuers = validIssuers,
                IssuerValidator =
                    (tokenIssuer, token) =>
                    {
                        return false;
                    },
            };

            issuer = ValidateIssuer("bob", validationParameters, samlSecurityTokenHandler, expectedException);
            Assert.IsTrue(issuer == "bob", "issuer mismatch");

            // delegate returns false, secondary should fail
            validIssuers = new List<string> { "john", "paul", "george", "ringo" };
            expectedException = ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205");
            validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = new X509SecurityKey(KeyingMaterial.Cert_2048),
                ValidateAudience = false,
                ValidIssuer = "http://Bob",
                IssuerValidator =
                    (tokenIssuer, token) =>
                    {
                        return false;
                    },
            };

            ValidateIssuer("bob", validationParameters, samlSecurityTokenHandler, expectedException);
        }

        private string ValidateIssuer(string issuer, TokenValidationParameters validationParameters, Saml2SecurityTokenHandler samlSecurityTokenHandler, ExpectedException expectedException)
        {
            string returnVal = string.Empty;
            try
            {
                returnVal = samlSecurityTokenHandler.ValidateIssuer(issuer, validationParameters, new DerivedSaml2SecurityToken());
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return returnVal;
        }

        private void ValidateToken()
        {
            // parameter validation
            Saml2SecurityTokenHandler samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            ExpectedException expectedException = ExpectedException.ArgumentNullException(substringExpected: "name: securityToken");
            ValidateToken(securityToken: null, validationParameters: new TokenValidationParameters(), samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            expectedException = ExpectedException.ArgumentNullException(substringExpected: "name: validationParameters");
            ValidateToken(securityToken: "s", validationParameters: null, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            expectedException = ExpectedException.ArgumentException(substringExpected: "IDX10209");
            samlSecurityTokenHandler.MaximumTokenSizeInBytes = 1;
            ValidateToken(securityToken: "ss", validationParameters: new TokenValidationParameters(), samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            samlSecurityTokenHandler.MaximumTokenSizeInBytes = Saml2SecurityTokenHandler.DefaultMaximumTokenSizeInBytes;
            string samlToken = IdentityUtilities.CreateSaml2Token();
            TokenValidationParameters tokenValidationParameters =
                new TokenValidationParameters
                {
                    ValidAudience = IdentityUtilities.DefaultAudience,
                    ValidIssuer = IdentityUtilities.DefaultIssuer,
                    IssuerSigningToken = IdentityUtilities.DefaultSigningToken,
                };

            expectedException = ExpectedException.NoExceptionExpected;
            ValidateToken(samlToken, tokenValidationParameters, samlSecurityTokenHandler, expectedException);
        }

        private void ValidateAudience()
        {
            Saml2SecurityTokenHandler samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            ExpectedException expectedException;

            string samlString = IdentityUtilities.CreateSaml2Token();

            TokenValidationParameters tokenValidationParameters =
                new TokenValidationParameters
                {
                    ValidIssuer = IdentityUtilities.DefaultIssuer,
                    IssuerSigningToken = IdentityUtilities.DefaultSigningToken,
                };

            // Do not validate audience
            tokenValidationParameters.ValidateAudience = false;
            expectedException = ExpectedException.NoExceptionExpected;
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            tokenValidationParameters.ValidateAudience = true;
            expectedException = ExpectedException.ArgumentException(substringExpected: "IDX10208");
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            tokenValidationParameters.ValidateAudience = true;
            tokenValidationParameters.ValidAudience = "John";
            expectedException = new ExpectedException(typeExpected: typeof(AudienceUriValidationFailedException), substringExpected: "IDX10214");
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            // UriKind.Absolute, no match.
            tokenValidationParameters.ValidateAudience = true;
            tokenValidationParameters.ValidAudience = IdentityUtilities.NotDefaultAudience;
            expectedException = new ExpectedException(typeExpected: typeof(AudienceUriValidationFailedException), substringExpected: "IDX10214");
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            expectedException = ExpectedException.NoExceptionExpected;
            tokenValidationParameters.ValidAudience = IdentityUtilities.DefaultAudience;
            tokenValidationParameters.ValidAudiences = null;
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            // !UriKind.Absolute
            List<string> audiences = new List<string> { "John", "Paul", "George", "Ringo" };
            tokenValidationParameters.ValidAudience = null;
            tokenValidationParameters.ValidAudiences = audiences;
            tokenValidationParameters.ValidateAudience = false;
            expectedException = ExpectedException.NoExceptionExpected;
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            // UriKind.Absolute, no match
            audiences = new List<string> { "http://www.John.com", "http://www.Paul.com", "http://www.George.com", "http://www.Ringo.com", "    " };
            tokenValidationParameters.ValidAudience = null;
            tokenValidationParameters.ValidAudiences = audiences;
            tokenValidationParameters.ValidateAudience = false;
            expectedException = ExpectedException.NoExceptionExpected;
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            tokenValidationParameters.ValidateAudience = true;
            expectedException = new ExpectedException(typeExpected: typeof(AudienceUriValidationFailedException), substringExpected: "IDX10214");
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            tokenValidationParameters.ValidateAudience = true;
            expectedException = ExpectedException.NoExceptionExpected;
            audiences.Add(IdentityUtilities.DefaultAudience);
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);
        }

        private ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, Saml2SecurityTokenHandler samlSecurityTokenHandler, ExpectedException expectedException)
        {
            ClaimsPrincipal princiapl = null;
            try
            {
                princiapl = samlSecurityTokenHandler.ValidateToken(securityToken, validationParameters);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return princiapl;
        }

        private class DerivedSamlSecurityTokenHandler : Saml2SecurityTokenHandler
        {
            public ClaimsIdentity CreateClaims_public(Saml2SecurityToken samlToken)
            {
                return base.CreateClaims(samlToken);
            }

            public IEnumerable<SecurityKey> RetrieveIssuerSigningKeys_public(string securityToken, TokenValidationParameters validationParameters)
            {
                return base.RetrieveIssuerSigningKeys(securityToken, validationParameters);
            }
        }

        private class DerivedSaml2SecurityToken : Saml2SecurityToken
        {
            public Saml2Assertion SamlAssertion { get; set; }

            public DerivedSaml2SecurityToken()
                : base(new DerivedSaml2Assertion())
            { }

            public DerivedSaml2SecurityToken(Saml2Assertion samlAssertion)

                : base(samlAssertion)
            { }
        }

        private class DerivedSaml2Assertion : Saml2Assertion
        {
            public DerivedSaml2Assertion(string issuer = IdentityUtilities.DefaultIssuer)
                : base(new Saml2NameIdentifier(issuer))
            {
                Issuer = issuer;
            }

            new public string Issuer { get; set; }
        }
    }
}