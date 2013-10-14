// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.IdentityModel.Tokens;

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
        [Description( "ensures that set / gets are working" )]
        public void SetGet()
        {
            List<string> validAudiences = new List<string>() { "Audience1" };
            List<SecurityToken> signingTokens = new List<SecurityToken>(){ KeyingMaterial.AsymmetricX509Token_2048 };
            List<string> validIssuers =  new List<string>() { "ValidIssuer1" };

            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters()
            {
                AllowedAudience = "AllowedAudience",
                AudienceUriMode = Selectors.AudienceUriMode.Always,
                AllowedAudiences = validAudiences,
                SaveBootstrapContext = true,
                SigningToken = KeyingMaterial.BinarayToken56BitKey,
                SigningTokens = signingTokens,
                ValidateIssuer = false,
                ValidIssuer = "ValidIssuer",
                ValidIssuers = validIssuers,
            };

            Assert.IsFalse( tokenValidationParameters.AllowedAudience != "AllowedAudience" , string.Format( "Expecting: tokenValidationParameters.AllowedAudience == 'AllowedAudience'. Was: '{0}'", tokenValidationParameters.AllowedAudience ) );

            Assert.IsFalse( tokenValidationParameters.AudienceUriMode != Selectors.AudienceUriMode.Always , string.Format( "Expecting: tokenValidationParameters.AudienceUriMode == Selectors.AudienceUriMode.Always. Was: '{0}'", tokenValidationParameters.AudienceUriMode ) );

            Assert.IsFalse( tokenValidationParameters.AllowedAudiences == null , string.Format( "Expecting: tokenValidationParameters.AllowedAudiences != null.") );

            Assert.IsFalse( !object.ReferenceEquals( tokenValidationParameters.AllowedAudiences, validAudiences ) , "object.ReferenceEquals( tokenValidationParameters.AllowedAudiences,  validAudiences ) is false" );
            
            Assert.IsFalse( !tokenValidationParameters.SaveBootstrapContext , "tokenValidationParameters.SaveBootstrapContext != true" );

            Assert.IsFalse( tokenValidationParameters.SigningToken == null , string.Format( "Expecting: tokenValidationParameters.SigningToken != null." ) );

            Assert.IsFalse( !object.ReferenceEquals( tokenValidationParameters.SigningToken,  KeyingMaterial.BinarayToken56BitKey ) , "object.ReferenceEquals( tokenValidationParameters.SigningToken,  KeyingMaterial.BinarayToken56BitKey ) is false" );

            Assert.IsFalse( tokenValidationParameters.SigningTokens == null , string.Format( "Expecting: tokenValidationParameters.SigningTokens != null." ) );

            Assert.IsFalse( !object.ReferenceEquals( tokenValidationParameters.SigningTokens, signingTokens ) , "object.ReferenceEquals( tokenValidationParameters.SigningTokens, signingTokens ) is false" );

            Assert.IsFalse( tokenValidationParameters.ValidateIssuer , string.Format( "Expecting: tokenValidationParameters.ValidateIssuer to be false" ) );

            Assert.IsFalse( tokenValidationParameters.ValidIssuer == null , string.Format( "Expecting: tokenValidationParameters.ValidIssuer != null." ) );

            Assert.IsFalse( tokenValidationParameters.ValidIssuer != "ValidIssuer" , string.Format( "Expecting: tokenValidationParameters.ValidIssuer !== ValidIssuer. Was: '{0}'", tokenValidationParameters.ValidIssuer ) );

            Assert.IsFalse( tokenValidationParameters.ValidIssuers == null , string.Format( "Expecting: tokenValidationParameters.ValidIssuers != null." ) );

            Assert.IsFalse( !object.ReferenceEquals( tokenValidationParameters.SigningTokens, signingTokens ) , "object.ReferenceEquals( tokenValidationParameters.SigningTokens, signingTokens ) is false" );
        }

    }
}

