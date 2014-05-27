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
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

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
            SecurityKey issuerSigningKey = KeyingMaterial.DefaultSymmetricSecurityKey_256;
            List<SecurityKey> issuerSigningKeys = new List<SecurityKey>() { KeyingMaterial.DefaultSymmetricSecurityKey_256, KeyingMaterial.SymmetricSecurityKey2_256};
            List<SecurityKey> issuerSigningKeysDup = new List<SecurityKey>() { new InMemorySymmetricSecurityKey(KeyingMaterial.SymmetricKeyBytes2_256), new InMemorySymmetricSecurityKey(KeyingMaterial.DefaultSymmetricKeyBytes_256) };

            string validAudience = "ValidAudience";
            List<string> validAudiences = new List<string>() { validAudience };
            string validIssuer = "ValidIssuer";
            List<string> validIssuers = new List<string>() { validIssuer };
            Func<IEnumerable<string>, SecurityToken, bool> audValidatorTrue = (str, token) => { return true; };
            Func<IEnumerable<string>, SecurityToken, bool> audValidatorTrue2 = (str, token) => { return true; };
            Func<string, SecurityToken, bool> issValidatorTrue = (str, token) => { return true; };
            Func<string, SecurityToken, bool> issValidatorTrue2 = (str, token) => { return true; };
            Func<string, SecurityToken, bool> lifetimeValidatorTrue = (str, token) => { return true; };
            Func<string, SecurityToken, bool> lifetimeValidatorTrue2 = (str, token) => { return true; };

            TokenValidationParameters validationParametersInline = new TokenValidationParameters()
            {               
                AudienceValidator = audValidatorTrue,
                IssuerSigningKey = issuerSigningKey,
                IssuerSigningKeyRetriever = (str) => { return issuerSigningKeys; },
                IssuerSigningKeys = issuerSigningKeys,
                IssuerValidator = issValidatorTrue,
                LifetimeValidator = lifetimeValidatorTrue,
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
            validationParametersSets.AudienceValidator = audValidatorTrue2;
            validationParametersSets.IssuerSigningKey = new InMemorySymmetricSecurityKey(KeyingMaterial.DefaultSymmetricKeyBytes_256);
            validationParametersSets.IssuerSigningKeyRetriever = (str) => { return issuerSigningKeysDup; };
            validationParametersSets.IssuerSigningKeys = issuerSigningKeysDup;
            validationParametersSets.IssuerValidator = issValidatorTrue2;
            validationParametersSets.LifetimeValidator = lifetimeValidatorTrue2;
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
            Assert.IsTrue(tokenValidationParametersCloned.AudienceValidator(new string[]{"bob"}, JwtTestTokens.Simple()));

            string id = Guid.NewGuid().ToString();
            DerivedTokenValidationParameters derivedValidationParameters = new DerivedTokenValidationParameters(id, validationParametersInline);
            DerivedTokenValidationParameters derivedValidationParametersCloned = derivedValidationParameters.Clone() as DerivedTokenValidationParameters;
            Assert.IsTrue(IdentityComparer.AreEqual<TokenValidationParameters>(derivedValidationParameters, derivedValidationParametersCloned));
            Assert.AreEqual(derivedValidationParameters.InternalString, derivedValidationParametersCloned.InternalString);
        }

        [TestMethod]
        [TestProperty("TestCaseID", "5C8D86B6-08C8-416D-995E-FE6856E70999")]
        [Description("Tests: Defaults")]
        public void TokenValidationParameters_Defaults()
        {
            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters();
            Assert.IsNull(tokenValidationParameters.AudienceValidator);
            Assert.IsNull(tokenValidationParameters.LifetimeValidator);
            Assert.IsNull(tokenValidationParameters.IssuerSigningKey);
            Assert.IsNull(tokenValidationParameters.IssuerSigningKeys);
            Assert.IsNull(tokenValidationParameters.IssuerSigningTokens);
            Assert.IsNull(tokenValidationParameters.IssuerSigningTokens);
            Assert.IsNull(tokenValidationParameters.IssuerSigningKeyRetriever);
            Assert.IsNull(tokenValidationParameters.IssuerValidator);
            Assert.IsFalse(tokenValidationParameters.SaveSigninToken);
            Assert.IsFalse(tokenValidationParameters.ValidateActor);
            Assert.IsTrue(tokenValidationParameters.ValidateAudience);
            Assert.IsTrue(tokenValidationParameters.ValidateIssuer);
            Assert.IsNull(tokenValidationParameters.ValidAudience);
            Assert.IsNull(tokenValidationParameters.ValidAudiences);
            Assert.IsNull(tokenValidationParameters.ValidIssuer);
            Assert.IsNull(tokenValidationParameters.ValidIssuers);
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

