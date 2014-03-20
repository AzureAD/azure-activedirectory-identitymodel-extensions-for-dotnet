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
using SamlSecurityTokenHandler = Microsoft.IdentityModel.Extensions.SamlSecurityTokenHandler;
using Saml2SecurityTokenHandler = Microsoft.IdentityModel.Extensions.Saml2SecurityTokenHandler;

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
            TestUtilities.GetSet(samlSecurityTokenHandler, "AuthenticationType", null, ExceptionProcessor.ArgumentNullException(substringExpected: "AuthenticationType"));
            TestUtilities.GetSet(samlSecurityTokenHandler, "AuthenticationType", "   ", ExceptionProcessor.ArgumentNullException(substringExpected: "AuthenticationType"));
            TestUtilities.GetSet(samlSecurityTokenHandler, "AuthenticationType", "AuthenticationType", ExceptionProcessor.NoExceptionExpected);

            TestUtilities.GetSet(samlSecurityTokenHandler, "ClockSkewInSeconds", (object)0, ExceptionProcessor.ArgumentOutOfRangeException(substringExpected: "IDX10100"));
            TestUtilities.GetSet(samlSecurityTokenHandler, "ClockSkewInSeconds", (object)1, ExceptionProcessor.NoExceptionExpected);

            TestUtilities.GetSet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)0, ExceptionProcessor.ArgumentOutOfRangeException(substringExpected: "IDX10101"));
            TestUtilities.GetSet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)1, ExceptionProcessor.NoExceptionExpected);
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
            ExceptionProcessor exceptionProcessor = ExceptionProcessor.ArgumentNullException(substringExpected: "samlToken");
            CreateClaims(samlToken: null, samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);
        }

        private void CreateClaims(SamlSecurityToken samlToken, DerivedSamlSecurityTokenHandler samlSecurityTokenHandler, ExceptionProcessor exceptionProcessor)
        {
            try
            {
                samlSecurityTokenHandler.CreateClaims_public(samlToken: samlToken);
                exceptionProcessor.ProcessNoException();
            }
            catch (Exception exception)
            {
                exceptionProcessor.ProcessException(exception);
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
            ExceptionProcessor exceptionProcessor = ExceptionProcessor.ArgumentNullException("securityToken");
            CanReadToken(securityToken: null, samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);

            string samlString = new string('S', SamlSecurityTokenHandler.DefaultMaximumTokenSizeInBytes + 1);
            exceptionProcessor = ExceptionProcessor.NoExceptionExpected;
            Assert.IsFalse(CanReadToken(samlString, samlSecurityTokenHandler, exceptionProcessor));

            samlString = new string('S', SamlSecurityTokenHandler.DefaultMaximumTokenSizeInBytes);
            exceptionProcessor = new ExceptionProcessor(typeExpected: typeof(XmlException));
            CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);

            samlString = IdentityUtilities.CreateSamlToken();
            exceptionProcessor = ExceptionProcessor.NoExceptionExpected;
            Assert.IsTrue(CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor));
        }
        private bool CanReadToken(string securityToken, SamlSecurityTokenHandler samlSecurityTokenHandler, ExceptionProcessor exceptionProcessor)
        {
            bool canReadToken = false;
            try
            {
                canReadToken = samlSecurityTokenHandler.CanReadToken(securityToken);
                exceptionProcessor.ProcessNoException();
            }
            catch (Exception exception)
            {
                exceptionProcessor.ProcessException(exception);
            }

            return canReadToken;
        }

        private void ValidateIssuer()
        {
            SamlSecurityTokenHandler samlSecurityTokenHandler = new SamlSecurityTokenHandler();

            ExceptionProcessor exceptionProcessor = ExceptionProcessor.ArgumentNullException(substringExpected: "name: validationParameters");
            ValidateIssuer(null, null, samlSecurityTokenHandler, exceptionProcessor);

            exceptionProcessor = ExceptionProcessor.SecurityTokenInvalidIssuerException(substringExpected: "IDX10211");
            ValidateIssuer(null, new TokenValidationParameters{ ValidateIssuer = false}, samlSecurityTokenHandler, exceptionProcessor);

            exceptionProcessor = ExceptionProcessor.SecurityTokenInvalidIssuerException(substringExpected: "IDX10211");
            ValidateIssuer(null, new TokenValidationParameters(), samlSecurityTokenHandler, exceptionProcessor);

            exceptionProcessor = ExceptionProcessor.SecurityTokenInvalidIssuerException(substringExpected: "IDX10204");
            ValidateIssuer("bob", new TokenValidationParameters { }, samlSecurityTokenHandler, exceptionProcessor);

            exceptionProcessor = ExceptionProcessor.NoExceptionExpected;
            string issuer = ValidateIssuer("bob", new TokenValidationParameters { ValidIssuer = "bob" }, samlSecurityTokenHandler, exceptionProcessor);
            Assert.IsTrue(issuer == "bob", "issuer mismatch");

            exceptionProcessor = ExceptionProcessor.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205");
            ValidateIssuer("bob", new TokenValidationParameters { ValidIssuer = "frank" }, samlSecurityTokenHandler, exceptionProcessor);

            List<string> validIssuers = new List<string> { "john", "paul", "george", "ringo" };
            exceptionProcessor = ExceptionProcessor.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205");
            ValidateIssuer("bob", new TokenValidationParameters { ValidIssuers = validIssuers }, samlSecurityTokenHandler, exceptionProcessor);

            exceptionProcessor = ExceptionProcessor.NoExceptionExpected;
            ValidateIssuer("bob", new TokenValidationParameters { ValidateIssuer = false }, samlSecurityTokenHandler, exceptionProcessor);

            validIssuers.Add("bob");
            exceptionProcessor = ExceptionProcessor.NoExceptionExpected;
            issuer = ValidateIssuer("bob", new TokenValidationParameters { ValidIssuers = validIssuers }, samlSecurityTokenHandler, exceptionProcessor);
            Assert.IsTrue(issuer == "bob", "issuer mismatch");

            exceptionProcessor = ExceptionProcessor.NoExceptionExpected;
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                IssuerValidator =
                    (tokenIssuer, token) =>
                    {
                        return true;
                    },
            };

            ValidateIssuer("bob", validationParameters, samlSecurityTokenHandler, exceptionProcessor);

            // delegate returns false, secondary should still succeed
            exceptionProcessor = ExceptionProcessor.NoExceptionExpected;
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

            issuer = ValidateIssuer("bob", validationParameters, samlSecurityTokenHandler, exceptionProcessor);
            Assert.IsTrue(issuer == "bob", "issuer mismatch");

            // delegate returns false, secondary should fail
            validIssuers = new List<string> { "john", "paul", "george", "ringo" };
            exceptionProcessor = ExceptionProcessor.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205");
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

        private string ValidateIssuer(string issuer, TokenValidationParameters validationParameters, SamlSecurityTokenHandler samlSecurityTokenHandler, ExceptionProcessor exceptionProcessor)
        {
            string returnVal = string.Empty;
            try
            {
                returnVal = samlSecurityTokenHandler.ValidateIssuer(issuer, validationParameters, new DerivedSamlSecurityToken());
                exceptionProcessor.ProcessNoException();
            }
            catch (Exception exception)
            {
                exceptionProcessor.ProcessException(exception);
            }

            return returnVal;
        }

        private void ValidateToken()
        {
            // parameter validation
            SamlSecurityTokenHandler samlSecurityTokenHandler = new SamlSecurityTokenHandler();
            ExceptionProcessor exceptionProcessor = ExceptionProcessor.ArgumentNullException(substringExpected: "name: securityToken");
            ValidateToken(securityToken: null, validationParameters: new TokenValidationParameters(), samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);

            exceptionProcessor = ExceptionProcessor.ArgumentNullException(substringExpected: "name: validationParameters");
            ValidateToken(securityToken: "s", validationParameters: null, samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);

            exceptionProcessor = ExceptionProcessor.ArgumentException(substringExpected: "IDX10209");
            samlSecurityTokenHandler.MaximumTokenSizeInBytes = 1;
            ValidateToken(securityToken: "ss", validationParameters: new TokenValidationParameters(), samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);

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
            ExceptionProcessor exceptionProcessor;

            string samlString = IdentityUtilities.CreateSamlToken();

            TokenValidationParameters tokenValidationParameters =
                new TokenValidationParameters
                {
                    ValidIssuer = IdentityUtilities.DefaultIssuer,
                    IssuerSigningToken = IdentityUtilities.DefaultSigningToken,
                };

            // Do not validate audience
            tokenValidationParameters.ValidateAudience = false;
            exceptionProcessor = ExceptionProcessor.NoExceptionExpected;
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);

            tokenValidationParameters.ValidateAudience = true;
            exceptionProcessor = ExceptionProcessor.ArgumentException(substringExpected: "IDX10208");
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);

            tokenValidationParameters.ValidateAudience = true;
            tokenValidationParameters.ValidAudience = "John";
            exceptionProcessor = new ExceptionProcessor(typeExpected: typeof(AudienceUriValidationFailedException), substringExpected: "IDX10214");
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);

            // UriKind.Absolute, no match.
            tokenValidationParameters.ValidateAudience = true;
            tokenValidationParameters.ValidAudience = IdentityUtilities.NotDefaultAudience;
            exceptionProcessor = new ExceptionProcessor(typeExpected: typeof(AudienceUriValidationFailedException), substringExpected: "IDX10214");
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);

            exceptionProcessor = ExceptionProcessor.NoExceptionExpected;
            tokenValidationParameters.ValidAudience = IdentityUtilities.DefaultAudience;
            tokenValidationParameters.ValidAudiences = null;
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);

            // !UriKind.Absolute
            List<string> audiences = new List<string> { "John", "Paul", "George", "Ringo" };
            tokenValidationParameters.ValidAudience = null;
            tokenValidationParameters.ValidAudiences = audiences;
            tokenValidationParameters.ValidateAudience = false;
            exceptionProcessor = ExceptionProcessor.NoExceptionExpected;
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);

            // UriKind.Absolute, no match
            audiences = new List<string> { "http://www.John.com", "http://www.Paul.com", "http://www.George.com", "http://www.Ringo.com", "    " };
            tokenValidationParameters.ValidAudience = null;
            tokenValidationParameters.ValidAudiences = audiences;
            tokenValidationParameters.ValidateAudience = false;
            exceptionProcessor = ExceptionProcessor.NoExceptionExpected;
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);

            tokenValidationParameters.ValidateAudience = true;
            exceptionProcessor = new ExceptionProcessor(typeExpected: typeof(AudienceUriValidationFailedException), substringExpected: "IDX10214");
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);

            tokenValidationParameters.ValidateAudience = true;
            exceptionProcessor = ExceptionProcessor.NoExceptionExpected;
            audiences.Add(IdentityUtilities.DefaultAudience);
            ValidateToken(securityToken: samlString, validationParameters: tokenValidationParameters, samlSecurityTokenHandler: samlSecurityTokenHandler, exceptionProcessor: exceptionProcessor);

        }

        private ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, SamlSecurityTokenHandler samlSecurityTokenHandler, ExceptionProcessor exceptionProcessor)
        {
            ClaimsPrincipal princiapl = null;
            try
            {
                princiapl = samlSecurityTokenHandler.ValidateToken(securityToken, validationParameters);
                exceptionProcessor.ProcessNoException();
            }
            catch (Exception exception)
            {
                exceptionProcessor.ProcessException(exception);
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