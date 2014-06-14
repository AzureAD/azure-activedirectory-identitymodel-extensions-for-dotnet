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

using Microsoft.IdentityModel.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Security.Claims;
using System.Text;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class TokenValidationParametersTests
    {
        /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        protected TestContextProvider _testContextProvider;

        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void ClassSetup( TestContext testContext )
        {
            // Start local STS
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
            // Stop local STS
        }

        [TestInitialize]
        public void Initialize()
        {
            _testContextProvider = new TestContextProvider( TestContext );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "5763D198-1A0A-474D-A5D3-A5BBC496EE7B" )]
        [Description( "Tests: Publics" )]
        public void TokenValidationParameters_Publics()
        {
            TokenValidationParameters validationParameters = new TokenValidationParameters();
            Type type = typeof(TokenValidationParameters);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 30)
                Assert.Fail("Number of properties has changed from 30 to: " + properties.Length + ", adjust tests");

            SecurityKey issuerSigningKey = KeyingMaterial.DefaultSymmetricSecurityKey_256;
            SecurityKey issuerSigningKey2 = KeyingMaterial.SymmetricSecurityKey2_256;

            List<SecurityKey> issuerSigningKeys =
                new List<SecurityKey>
                {
                    KeyingMaterial.DefaultSymmetricSecurityKey_256,
                    KeyingMaterial.SymmetricSecurityKey2_256
                };

            List<SecurityKey> issuerSigningKeysDup =
                new List<SecurityKey>
                {
                    new InMemorySymmetricSecurityKey(KeyingMaterial.SymmetricKeyBytes2_256),
                    new InMemorySymmetricSecurityKey(KeyingMaterial.DefaultSymmetricKeyBytes_256)
                };

            string validAudience = "ValidAudience";
            List<string> validAudiences = new List<string>{ validAudience };
            string validIssuer = "ValidIssuer";
            List<string> validIssuers = new List<string>{ validIssuer };

            TokenValidationParameters validationParametersInline = new TokenValidationParameters()
            {
                AudienceValidator = IdentityUtilities.AudienceValidatorDoesNotThrow,
                IssuerSigningKey = issuerSigningKey,
                IssuerSigningKeyResolver = (token, securityToken, keyIdentifier, tvp) => { return issuerSigningKey; },
                IssuerSigningKeys = issuerSigningKeys,
                IssuerValidator = IdentityUtilities.IssuerValidatorEcho,
                LifetimeValidator = IdentityUtilities.LifetimeValidatorDoesNotThrow,
                SaveSigninToken = true,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidAudience = validAudience,
                ValidAudiences = validAudiences,
                ValidIssuer = validIssuer,
                ValidIssuers = validIssuers,
            };

            Assert.IsTrue(object.ReferenceEquals(validationParametersInline.IssuerSigningKey, issuerSigningKey));
            Assert.IsTrue(validationParametersInline.SaveSigninToken);
            Assert.IsFalse(validationParametersInline.ValidateAudience);
            Assert.IsFalse(validationParametersInline.ValidateIssuer);
            Assert.IsTrue(object.ReferenceEquals(validationParametersInline.ValidAudience, validAudience));
            Assert.IsTrue(object.ReferenceEquals(validationParametersInline.ValidAudiences, validAudiences));
            Assert.IsTrue(object.ReferenceEquals(validationParametersInline.ValidIssuer, validIssuer));

            TokenValidationParameters validationParametersSets = new TokenValidationParameters();
            validationParametersSets.AudienceValidator = IdentityUtilities.AudienceValidatorDoesNotThrow;
            validationParametersSets.IssuerSigningKey = new InMemorySymmetricSecurityKey(KeyingMaterial.DefaultSymmetricKeyBytes_256);
            validationParametersSets.IssuerSigningKeyResolver = (token, securityToken, keyIdentifier, tvp) => { return issuerSigningKey2; };
            validationParametersSets.IssuerSigningKeys = issuerSigningKeysDup;
            validationParametersSets.IssuerValidator = IdentityUtilities.IssuerValidatorEcho;
            validationParametersSets.LifetimeValidator = IdentityUtilities.LifetimeValidatorDoesNotThrow;
            validationParametersSets.SaveSigninToken = true;
            validationParametersSets.ValidateAudience = false;
            validationParametersSets.ValidateIssuer = false;
            validationParametersSets.ValidAudience = validAudience;
            validationParametersSets.ValidAudiences = validAudiences;
            validationParametersSets.ValidIssuer = validIssuer;
            validationParametersSets.ValidIssuers = validIssuers;

            Assert.IsTrue(IdentityComparer.AreEqual<TokenValidationParameters>(validationParametersInline, validationParametersSets));

            var tokenValidationParametersCloned = validationParametersInline.Clone();
            Assert.IsTrue(IdentityComparer.AreEqual<TokenValidationParameters>(tokenValidationParametersCloned, validationParametersInline));
            //tokenValidationParametersCloned.AudienceValidator(new string[]{"bob"}, JwtTestTokens.Simple();

            string id = Guid.NewGuid().ToString();
            DerivedTokenValidationParameters derivedValidationParameters = new DerivedTokenValidationParameters(id, validationParametersInline);
            DerivedTokenValidationParameters derivedValidationParametersCloned = derivedValidationParameters.Clone() as DerivedTokenValidationParameters;
            Assert.IsTrue(IdentityComparer.AreEqual<TokenValidationParameters>(derivedValidationParameters, derivedValidationParametersCloned));
            Assert.AreEqual(derivedValidationParameters.InternalString, derivedValidationParametersCloned.InternalString);
        }

        [TestMethod]
        [TestProperty("TestCaseID", "5C8D86B6-08C8-416D-995E-FE6856E70999")]
        [Description("Tests: GetSets, covers defaults")]
        public void TokenValidationParameters_GetSets()
        {
            TokenValidationParameters validationParameters = new TokenValidationParameters();
            Type type = typeof(TokenValidationParameters);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 30)
                Assert.Fail("Number of public fields has changed from 30 to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                    {
                        new KeyValuePair<string, List<object>>("AuthenticationType", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("CertificateValidator", new List<object>{(string)null, X509CertificateValidator.None, X509CertificateValidatorEx.None}),
                        new KeyValuePair<string, List<object>>("ClockSkew", new List<object>{TokenValidationParameters.DefaultClockSkew, TimeSpan.FromHours(2), TimeSpan.FromMinutes(1)}),
                        new KeyValuePair<string, List<object>>("IssuerSigningKey", new List<object>{(SecurityKey)null, KeyingMaterial.DefaultAsymmetricKey_Public_2048, KeyingMaterial.DefaultSymmetricSecurityKey_256}),
                        new KeyValuePair<string, List<object>>("IssuerSigningKeys", new List<object>{(IEnumerable<SecurityKey>)null, new List<SecurityKey>{KeyingMaterial.DefaultAsymmetricKey_Public_2048, KeyingMaterial.DefaultSymmetricSecurityKey_256}, new List<SecurityKey>()}),
                        new KeyValuePair<string, List<object>>("IssuerSigningToken", new List<object>{(SecurityToken)null, KeyingMaterial.DefaultSymmetricSecurityToken_256, KeyingMaterial.DefaultAsymmetricX509Token_2048}),
                        new KeyValuePair<string, List<object>>("IssuerSigningTokens", new List<object>{(IEnumerable<SecurityToken>)null, new List<SecurityToken>{KeyingMaterial.DefaultAsymmetricX509Token_2048, KeyingMaterial.DefaultSymmetricSecurityToken_256}, new List<SecurityToken>()}),
                        new KeyValuePair<string, List<object>>("NameClaimType", new List<object>{ClaimsIdentity.DefaultNameClaimType, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("RoleClaimType", new List<object>{ClaimsIdentity.DefaultRoleClaimType, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("RequireExpirationTime", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("RequireSignedTokens", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("SaveSigninToken", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("ValidateActor", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("ValidateAudience", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("ValidateIssuer", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("ValidateLifetime", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("ValidIssuer", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                    },
                    Object = validationParameters,
                };
            TestUtilities.GetSet(context);

            if (context.Errors.Count != 0)
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine(Environment.NewLine);
                foreach (string str in context.Errors)
                    sb.AppendLine(str);

                Assert.Fail(sb.ToString());
            }

            Assert.IsNull(validationParameters.AudienceValidator);
            Assert.IsNotNull(validationParameters.ClientDecryptionTokens);
            Assert.AreEqual(validationParameters.ClientDecryptionTokens.Count, 0);
            Assert.IsNull(validationParameters.LifetimeValidator);
            Assert.IsNull(validationParameters.IssuerSigningKeyResolver);
            Assert.IsNull(validationParameters.IssuerValidator);
            Assert.IsNull(validationParameters.ValidAudiences);
            Assert.IsNull(validationParameters.ValidIssuers);

        }

        class DerivedTokenValidationParameters : TokenValidationParameters
        {
            string _internalString;
            public DerivedTokenValidationParameters(string internalString, TokenValidationParameters validationParameters)
                : base(validationParameters)
            {
                _internalString = internalString;
            }

            protected DerivedTokenValidationParameters(DerivedTokenValidationParameters other)
                : base(other)
            {
                _internalString = other._internalString;
            }

            public string InternalString{ get {return _internalString; }}
            public override TokenValidationParameters Clone()
            {
                return new DerivedTokenValidationParameters(this);
            }
        }
    }
}

