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
        [Description("validate token using config")]
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
