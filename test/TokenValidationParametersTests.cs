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
        [Description( "ensures that constructor / set / gets are working" )]
        public void SetGet()
        {
            Int32 clockSkewInSeconds = 600;
            SecurityKey issuerSigningKey = KeyingMaterial.SymmetricSecurityKey_256;
            List<SecurityKey> issuerSigningKeys = new List<SecurityKey>() { KeyingMaterial.SymmetricSecurityKey_256 };        
            Int32 maximumTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes * 2;
            string validAudience = "ValidAudience";
            List<string> validAudiences = new List<string>() { validAudience };
            string validIssuer = "ValidIssuer";
            List<string> validIssuers = new List<string>() { validIssuer };

            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters()
            {
                ClockSkewInSeconds = clockSkewInSeconds,
                IssuerSigningKey = issuerSigningKey,
                IssuerSigningKeys = issuerSigningKeys,
                MaximumTokenSizeInBytes = maximumTokenSizeInBytes,
                SaveSigninToken = true,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidAudience = validAudience,
                ValidAudiences = validAudiences,
                ValidIssuer = validIssuer,
                ValidIssuers = validIssuers,
            };

            Assert.IsTrue(tokenValidationParameters.ClockSkewInSeconds == clockSkewInSeconds);
            Assert.IsTrue(TokenValidationParameters.DefaultMaximumTokenSizeInBytes == 2 * 1024 * 1024);
            Assert.IsTrue(object.ReferenceEquals(tokenValidationParameters.IssuerSigningKey, issuerSigningKey));
            Assert.IsTrue(object.ReferenceEquals(tokenValidationParameters.IssuerSigningKeys, issuerSigningKeys));
            Assert.IsTrue(tokenValidationParameters.MaximumTokenSizeInBytes == maximumTokenSizeInBytes);
            Assert.IsTrue(tokenValidationParameters.SaveSigninToken);
            Assert.IsFalse(tokenValidationParameters.ValidateAudience);
            Assert.IsFalse(tokenValidationParameters.ValidateIssuer);
            Assert.IsTrue(object.ReferenceEquals(tokenValidationParameters.ValidAudience, validAudience));
            Assert.IsTrue(object.ReferenceEquals(tokenValidationParameters.ValidAudiences, validAudiences));
            Assert.IsTrue(object.ReferenceEquals(tokenValidationParameters.ValidIssuer, validIssuer));

            tokenValidationParameters = new TokenValidationParameters();
            tokenValidationParameters.ClockSkewInSeconds = clockSkewInSeconds;
            tokenValidationParameters.IssuerSigningKey = issuerSigningKey;
            tokenValidationParameters.IssuerSigningKeys = issuerSigningKeys;
            tokenValidationParameters.MaximumTokenSizeInBytes = maximumTokenSizeInBytes;
            tokenValidationParameters.SaveSigninToken = true;
            tokenValidationParameters.ValidateAudience = false;
            tokenValidationParameters.ValidateIssuer = false;
            tokenValidationParameters.ValidAudience = validAudience;
            tokenValidationParameters.ValidAudiences = validAudiences;
            tokenValidationParameters.ValidIssuer = validIssuer;
            tokenValidationParameters.ValidIssuers = validIssuers;

            Assert.IsTrue(tokenValidationParameters.ClockSkewInSeconds == clockSkewInSeconds);
            Assert.IsTrue(TokenValidationParameters.DefaultMaximumTokenSizeInBytes == 2 * 1024 * 1024);
            Assert.IsTrue(object.ReferenceEquals(tokenValidationParameters.IssuerSigningKey, issuerSigningKey));
            Assert.IsTrue(object.ReferenceEquals(tokenValidationParameters.IssuerSigningKeys, issuerSigningKeys));
            Assert.IsTrue(tokenValidationParameters.MaximumTokenSizeInBytes == maximumTokenSizeInBytes);
            Assert.IsTrue(tokenValidationParameters.SaveSigninToken);
            Assert.IsFalse(tokenValidationParameters.ValidateAudience);
            Assert.IsFalse(tokenValidationParameters.ValidateIssuer);
            Assert.IsTrue(object.ReferenceEquals(tokenValidationParameters.ValidAudience, validAudience));
            Assert.IsTrue(object.ReferenceEquals(tokenValidationParameters.ValidAudiences, validAudiences));
            Assert.IsTrue(object.ReferenceEquals(tokenValidationParameters.ValidIssuer, validIssuer));
        }
    }
}

