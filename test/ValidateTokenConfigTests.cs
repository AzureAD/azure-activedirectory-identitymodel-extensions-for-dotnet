//------------------------------------------------------------------------------
//     Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------------------------

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.IdentityModel.Configuration;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace System.IdentityModel.Test
{
    [TestClass]
    public class ValidateTokenConfigTest : ConfigurationTest
    {
        /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        protected TestContextProvider _testContextProvider;

        [ClassInitialize]
        public static void ClassSetup(TestContext testContext)
        {
        }

        [TestInitialize]
        public void Initialize()
        {
            _testContextProvider = new TestContextProvider(TestContext);
        }

        [TestMethod]
        [TestProperty("TestCaseID", "fdd176f7-2125-4df5-a53d-710fbd2a2923")]
        [TestProperty("TestType", "BVT")]
        [TestProperty("Environments", "ACSDevBox")]
        [Description("validate token using config")]
        [Priority(0)]
        [Owner("BrentSch")]
        [TestProperty("DisciplineOwner", "Dev")]
        [TestProperty("Feature", "ACS/AAL")]
        [TestProperty("Framework", "TAEF")]
        public void JwtHandlerDefinedInConfig()
        {
            RunTestCase(string.Empty);
        }

        /// <summary>
        /// The test context that is set by Visual Studio and TAEF - need to keep this exact signature
        /// </summary>
        public TestContext TestContext { get; set; }

        protected override string GetConfiguration( string testVariation )
        {
            return @"<system.identityModel>
                       <identityConfiguration>
                         <audienceUris>
                           <add value='http://localhost' />
                         </audienceUris>
                         <issuerNameRegistry type='System.IdentityModel.Tokens.ConfigurationBasedIssuerNameRegistry, System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'>
                           <trustedIssuers>
                             <add thumbprint='"+ KeyingMaterial.X509SigningCreds_1024_RsaSha2_Sha2.Certificate.Thumbprint + @"' name='https://wiftooling.accesscontrol.windows.net/' />
                           </trustedIssuers>
                         </issuerNameRegistry>
                      <certificateValidation certificateValidationMode='None' />
                      <securityTokenHandlers>
                        <add type='System.IdentityModel.Tokens.JwtSecurityTokenHandler, System.IdentityModel.Tokens.Jwt' />
                      </securityTokenHandlers>
                    </identityConfiguration>
                  </system.identityModel>";
        }

        protected override void ValidateTestCase( string testCase )
        {
            IdentityConfiguration identityConfig = new IdentityConfiguration(IdentityConfiguration.DefaultServiceName);

            JwtSecurityTokenHandler jwtHandler =   identityConfig.SecurityTokenHandlers[typeof(JwtSecurityToken)] as JwtSecurityTokenHandler;
            jwtHandler.RequireExpirationTime = false;
            Assert.IsNotNull(jwtHandler);

            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor()
            {
                TokenIssuerName = "https://wiftooling.accesscontrol.windows.net",
                AppliesToAddress = "http://localhost",
                SigningCredentials = KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2,
            };
                        
            try
            {
                SecurityToken jwtToken = jwtHandler.CreateToken(tokenDescriptor);
                string tokenString = jwtHandler.WriteToken(jwtToken);
                List<SecurityToken> tokens = new List<SecurityToken>(KeyingMaterial.AsymmetricTokens);
                jwtHandler.Configuration.IssuerTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver( tokens.AsReadOnly() , true );
                jwtToken = jwtHandler.ReadToken( tokenString );
                jwtHandler.CertificateValidator = X509CertificateValidator.None;
                jwtHandler.Configuration.IssuerNameRegistry = new  SetNameIssuerNameRegistry( "https://wiftooling.accesscontrol.windows.net" );
                ClaimsPrincipal cp = new ClaimsPrincipal(jwtHandler.ValidateToken( jwtToken ));
            }
            catch (Exception ex)
            {
                Assert.Fail(ex.Message);
            }           
        }      
    }
}
