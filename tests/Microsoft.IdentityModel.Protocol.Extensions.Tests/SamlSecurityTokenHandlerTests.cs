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
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Xml;

using Saml2SecurityTokenHandler = Microsoft.IdentityModel.Extensions.Saml2SecurityTokenHandler;
using SamlSecurityTokenHandler = Microsoft.IdentityModel.Extensions.SamlSecurityTokenHandler;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class SamlSecurityTokenHandlerTests
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
        [TestProperty("TestCaseID", "cc3fff9a-ef48-4818-8c25-b814a9888cfe")]
        [Description("Tests: Constructors")]
        public void SamlSecurityTokenHandler_Constructors()
        {
            SamlSecurityTokenHandler samlSecurityTokenHandler = new SamlSecurityTokenHandler();
        }

        [TestMethod]
        [TestProperty("TestCaseID", "c97d3f29-5032-4d63-88c3-9863be253b6d")]
        [Description("Tests: Defaults")]
        public void SamlSecurityTokenHandler_Defaults()
        {
            SamlSecurityTokenHandler samlSecurityTokenHandler = new SamlSecurityTokenHandler();
            Assert.IsTrue(samlSecurityTokenHandler.AuthenticationType == AuthenticationTypes.Federation, "AuthenticationType");
            Assert.IsTrue(samlSecurityTokenHandler.ClockSkewInSeconds == SamlSecurityTokenHandler.DefaultClockSkewInSeconds, "ClockSkewInSeconds");
            Assert.IsTrue(samlSecurityTokenHandler.MaximumTokenSizeInBytes == SamlSecurityTokenHandler.DefaultMaximumTokenSizeInBytes, "MaximumTokenSizeInBytes");
            Assert.IsTrue(SamlSecurityTokenHandler.DefaultClockSkewInSeconds == 300, "DefaultClockSkewInSeconds");
            Assert.IsTrue(SamlSecurityTokenHandler.DefaultMaximumTokenSizeInBytes == Saml2SecurityTokenHandler.DefaultMaximumTokenSizeInBytes, "Saml2SecurityTokenHandler");
            Int32 maximumTokenSizeInBytes = 1024 * 1024 * 2;
            Assert.IsTrue(SamlSecurityTokenHandler.DefaultMaximumTokenSizeInBytes == maximumTokenSizeInBytes, "DefaultMaximumTokenSizeInBytes");
        }

        [TestMethod]
        [TestProperty("TestCaseID", "d739cd25-b7fa-4191-b0be-e60fa8cf8651")]
        [Description("Tests: GetSets")]
        public void SamlSecurityTokenHandler_GetSets()
        {
            SamlSecurityTokenHandler samlSecurityTokenHandler = new SamlSecurityTokenHandler();
            TestUtilities.GetSet(samlSecurityTokenHandler, "AuthenticationType", null, ExpectedException.ArgumentNullException(substringExpected: "AuthenticationType"));
            TestUtilities.GetSet(samlSecurityTokenHandler, "AuthenticationType", "   ", ExpectedException.ArgumentNullException(substringExpected: "AuthenticationType"));
            TestUtilities.GetSet(samlSecurityTokenHandler, "AuthenticationType", "AuthenticationType", ExpectedException.NoExceptionExpected);

            TestUtilities.GetSet(samlSecurityTokenHandler, "ClockSkewInSeconds", (object)0, ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10100"));
            TestUtilities.GetSet(samlSecurityTokenHandler, "ClockSkewInSeconds", (object)1, ExpectedException.NoExceptionExpected);

            TestUtilities.GetSet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)0, ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10101"));
            TestUtilities.GetSet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)1, ExpectedException.NoExceptionExpected);
        }

        [TestMethod]
        [TestProperty("TestCaseID", "9D11B4D9-957F-4E30-9420-AD0683A5BF87")]
        [Description("Tests: Protected")]
        public void SamlSecurityTokenHandler_Protected()
        {
            CreateClaims();
        }

        private void CreateClaims()
        {
            DerivedSamlSecurityTokenHandler samlSecurityTokenHandler = new DerivedSamlSecurityTokenHandler();
            ExpectedException expectedException = ExpectedException.ArgumentNullException(substringExpected: "samlToken");
            CreateClaims(samlToken: null, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);
        }

        private void CreateClaims(SamlSecurityToken samlToken, DerivedSamlSecurityTokenHandler samlSecurityTokenHandler, ExpectedException expectedException)
        {
            try
            {
                samlSecurityTokenHandler.CreateClaims_public(samlToken: samlToken);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "82db9de3-7c75-4721-b1bb-b38fe097c398")]
        [Description("Tests: Publics")]
        public void SamlSecurityTokenHandler_Publics()
        {
            CanReadToken();
            ValidateIssuer();
            ValidateToken();
        }

        private void CanReadToken()
        {
            // CanReadToken
            SamlSecurityTokenHandler samlSecurityTokenHandler = new SamlSecurityTokenHandler();
            ExpectedException expectedException = ExpectedException.ArgumentNullException("securityToken");
            CanReadToken(securityToken: null, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            string samlString = new string('S', SamlSecurityTokenHandler.DefaultMaximumTokenSizeInBytes + 1);
            expectedException = ExpectedException.NoExceptionExpected;
            Assert.IsFalse(CanReadToken(samlString, samlSecurityTokenHandler, expectedException));

            samlString = new string('S', SamlSecurityTokenHandler.DefaultMaximumTokenSizeInBytes);
            expectedException = new ExpectedException(typeExpected: typeof(XmlException));
            CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            samlString = IdentityUtilities.CreateSamlToken();
            expectedException = ExpectedException.NoExceptionExpected;
            Assert.IsTrue(CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException));
        }
        private bool CanReadToken(string securityToken, SamlSecurityTokenHandler samlSecurityTokenHandler, ExpectedException expectedException)
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
            SamlSecurityTokenHandler samlSecurityTokenHandler = new SamlSecurityTokenHandler();

            ExpectedException expectedException = ExpectedException.ArgumentNullException(substringExpected: "name: validationParameters");
            ValidateIssuer(null, null, samlSecurityTokenHandler, expectedException);

            expectedException = ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10211");
            ValidateIssuer(null, new TokenValidationParameters{ ValidateIssuer = false}, samlSecurityTokenHandler, expectedException);

            expectedException = ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10211");
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
        }

        private string ValidateIssuer(string issuer, TokenValidationParameters validationParameters, SamlSecurityTokenHandler samlSecurityTokenHandler, ExpectedException expectedException)
        {
            string returnVal = string.Empty;
            try
            {
                returnVal = samlSecurityTokenHandler.ValidateIssuer(issuer, validationParameters, new DerivedSamlSecurityToken());
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
            SamlSecurityTokenHandler samlSecurityTokenHandler = new SamlSecurityTokenHandler();
            ExpectedException expectedException = ExpectedException.ArgumentNullException(substringExpected: "name: securityToken");
            ValidateToken(securityToken: null, validationParameters: new TokenValidationParameters(), samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            expectedException = ExpectedException.ArgumentNullException(substringExpected: "name: validationParameters");
            ValidateToken(securityToken: "s", validationParameters: null, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            expectedException = ExpectedException.ArgumentException(substringExpected: "IDX10209");
            samlSecurityTokenHandler.MaximumTokenSizeInBytes = 1;
            ValidateToken(securityToken: "ss", validationParameters: new TokenValidationParameters(), samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);

            samlSecurityTokenHandler.MaximumTokenSizeInBytes = SamlSecurityTokenHandler.DefaultMaximumTokenSizeInBytes;
            string samlString = IdentityUtilities.CreateSamlToken();
            TokenValidationParameters tokenValidationParameters = 
                new TokenValidationParameters
                {
                    ValidIssuer = IdentityUtilities.DefaultIssuer,
                    IssuerSigningToken = IdentityUtilities.DefaultSigningToken,
                };

            ValidateAudience();

        }

        private void ValidateAudience()
        {
            SamlSecurityTokenHandler samlSecurityTokenHandler = new SamlSecurityTokenHandler();
            ExpectedException expectedException;

            string samlString = IdentityUtilities.CreateSamlToken();

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

        private ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, SamlSecurityTokenHandler samlSecurityTokenHandler, ExpectedException expectedException)
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

        private class DerivedSamlSecurityTokenHandler : SamlSecurityTokenHandler
        {
            public ClaimsIdentity CreateClaims_public(SamlSecurityToken samlToken)
            {
                return base.CreateClaims(samlToken);
            }

            public IEnumerable<SecurityKey> RetrieveIssuerSigningKeys_public(string securityToken, TokenValidationParameters validationParameters)
            {
                return base.RetrieveIssuerSigningKeys(securityToken, validationParameters);
            }
        }

        private class DerivedSamlSecurityToken : SamlSecurityToken
        {
            public SamlAssertion SamlAssertion {get; set;}

            public DerivedSamlSecurityToken()
            { }

            public DerivedSamlSecurityToken(SamlAssertion samlAssertion)

                : base(samlAssertion)
            { }
        }

        private class DerivedSamlAssertion : SamlAssertion
        {
            public DerivedSamlAssertion(string issuer = null)
            {
                Issuer = issuer;
            }
            new public string Issuer { get; set; }
        }
    }
}