//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Xml;

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
        [TestProperty( "TestType", "CIT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "ensures that set / gets are working" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void SetGet()
        {
            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters()
            {
                AllowedAudience = "AllowedAudience",
                AudienceUriMode = Selectors.AudienceUriMode.Always,
                AllowedAudiences = new List<string>() { "Audience1" },
                SigningToken = KeyingMaterial.BinarayToken56BitKey,
                ValidIssuer = "ValidIssuer",
                ValidIssuers = new List<string>() { "ValidIssuer1" },
            };

            Assert.IsFalse( tokenValidationParameters.AllowedAudience != "AllowedAudience" , String.Format( "Expecting: tokenValidationParameters.AllowedAudience == 'AllowedAudience'. Was: '{0}'", tokenValidationParameters.AllowedAudience ) );

            Assert.IsFalse( tokenValidationParameters.AudienceUriMode != Selectors.AudienceUriMode.Always , String.Format( "Expecting: tokenValidationParameters.AudienceUriMode == Selectors.AudienceUriMode.Always. Was: '{0}'", tokenValidationParameters.AudienceUriMode ) );

            Assert.IsFalse( tokenValidationParameters.AllowedAudiences == null , String.Format( "Expecting: tokenValidationParameters.AllowedAudiences != null.") );

            foreach ( string str in tokenValidationParameters.AllowedAudiences )
            {
                Assert.IsFalse( str != "Audience1", String.Format( "Expecting: tokenValidationParameters.AllowedAudiences to have one audience: 'Audience1'. Was: '{0}'", str) );
            }

            Assert.IsFalse( tokenValidationParameters.SigningToken == null , String.Format( "Expecting: tokenValidationParameters.SigningToken != null." ) );
            Assert.IsFalse( tokenValidationParameters.SigningToken.GetType() != KeyingMaterial.BinarayToken56BitKey.GetType() , String.Format( "Expecting: tokenValidationParameters.SigningToken.GetType() == KeyingMaterial.BinarayToken56BitKey.GetType(). Was: '{0}'.", tokenValidationParameters.SigningToken.GetType() ) );

            Assert.IsFalse( tokenValidationParameters.ValidIssuer == null , String.Format( "Expecting: tokenValidationParameters.ValidIssuer != null." ) );
            Assert.IsFalse( tokenValidationParameters.ValidIssuer != "ValidIssuer" , String.Format( "Expecting: tokenValidationParameters.ValidIssuer !== ValidIssuer. Was: '{0}'", tokenValidationParameters.ValidIssuer ) );

            Assert.IsFalse( tokenValidationParameters.ValidIssuers == null , String.Format( "Expecting: tokenValidationParameters.ValidIssuers != null." ) );

            foreach ( string str in tokenValidationParameters.ValidIssuers )
            {
                Assert.IsFalse( str != "ValidIssuer1", String.Format( "Expecting: tokenValidationParameters.AllowedAudiences to have one audience: 'ValidIssuer1'. Was: '{0}'", str) );
            }
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "6A107933-13C9-4B55-9316-2B86C379A622" )]
        [TestProperty( "TestType", "CIT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "parameter checks for TokenValidationParameters" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void TokenValidationParametersParamChecks()
        {
            TokenValidationParameters validationParameters = new TokenValidationParameters();

            Assert.IsFalse( validationParameters.AllowedAudience != null , String.Format( "Expecting: validationParameters.AllowedAudience == null. Was: '{0}'", validationParameters.AllowedAudience ) );

            Assert.IsFalse( validationParameters.AllowedAudiences != null, String.Format( "Expecting: validationParameters.AllowedAudiences == null. Was: '{0}'", validationParameters.AllowedAudiences ) );

            Assert.IsFalse( validationParameters.AudienceUriMode != AudienceUriMode.BearerKeyOnly , String.Format( "Expecting: validationParameters.AudienceUriMode == AudienceUriMode.BearerKeyOnly. Was: '{0}'", validationParameters.AudienceUriMode ) );

            Assert.IsFalse( validationParameters.SigningToken != null , String.Format( "Expecting: validationParameters.SigningToken == null. Was: '{0}'", validationParameters.SigningToken ) );

            Assert.IsFalse( validationParameters.ValidIssuer != null , String.Format( "Expecting: validationParameters.ValidIssuer == null. Was: '{0}'", validationParameters.ValidIssuer ) );

            Assert.IsFalse( validationParameters.ValidIssuers != null , String.Format( "Expecting: validationParameters.ValidIssuers == null. Was: '{0}'", validationParameters.ValidIssuers ) );
        }
    }

    class CustomIssuerNameRegistry : IssuerNameRegistry
    {
        public override string GetIssuerName(SecurityToken securityToken)
        {
 	        throw new NotImplementedException();
        }
    }

}

