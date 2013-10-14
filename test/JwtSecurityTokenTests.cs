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
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Reflection;

namespace System.IdentityModel.Test
{
    [TestClass]
    public class JwtSecurityTokenTests
    {
        /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        protected TestContextProvider _testContextProvider;

        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void ClassSetup( TestContext testContext )
        {}

        [ClassCleanup]
        public static void ClassCleanup()
        {}

        [TestInitialize]
        public void Initialize()
        {
            _testContextProvider = new TestContextProvider( TestContext );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "F5803908-4CFA-4038-B506-045CF65D39BD" )]
        [Description( "Tests JwtSecurityToken Constructor that takes an EncodedString" )]
        public void JwtSecurityToken_EncodedStringConstruction()
        {
            Console.WriteLine( "Entering: "+ MethodBase.GetCurrentMethod() );
            JwtSecurityToken jwt = null;
            foreach ( JwtSecurityTokenTestVariation variation in JwtEncodedStringVariations() )
            {
                Console.WriteLine( string.Format( "Variation: {0}", variation.Name ) );
                try
                {
                    jwt = new JwtSecurityToken( variation.EncodedString );
                    ExpectedException.ProcessNoException( variation.ExpectedException );
                }
                catch ( Exception ex )
                {
                    ExpectedException.ProcessException( variation.ExpectedException, ex );
                }

                // ensure we can get to every property
                if ( jwt != null && ( variation.ExpectedException == null || variation.ExpectedException.Thrown == null ) )
                {
                    JwtTestUtilities.CallAllPublicInstanceAndStaticPropertyGets( jwt, variation.Name );
                }

                if ( null != variation.ExpectedJwtSecurityToken )
                {
                    Assert.IsTrue(
                        IdentityComparer.AreEqual(variation.ExpectedJwtSecurityToken, jwt),
                        string.Format("Testcase: {0}.  JWTSecurityTokens are not equal.", variation.Name));
                }
            }
        }

        private List<JwtSecurityTokenTestVariation> JwtEncodedStringVariations()
        {
            string[] tokenParts = EncodedJwts.Asymmetric_LocalSts.Split('.');
            List<JwtSecurityTokenTestVariation> variationsencodedStringParams = new List<JwtSecurityTokenTestVariation>() 
            {
                new JwtSecurityTokenTestVariation
                { 
                    Name = "EncodedString: InvalidPayloadFormat",
                    EncodedString = EncodedJwts.InvalidPayload,
                    ExpectedException = ExpectedException.ArgEx( id: "Jwt10113" ),
                },                
                new JwtSecurityTokenTestVariation
                { 
                    Name = "EncodedString: null", 
                    EncodedString = null, 
                    ExpectedException = ExpectedException.ArgNull,
                },
                new JwtSecurityTokenTestVariation
                { 
                    Name = "EncodedString: string.Empty", 
                    EncodedString = string.Empty, 
                    ExpectedException = ExpectedException.ArgEx(id:"WIF10002"),
                },
                new JwtSecurityTokenTestVariation
                { 
                    Name = "EncodedString: single character: '1'", 
                    EncodedString = "1",
                    ExpectedException = ExpectedException.ArgEx( id:"Jwt10400"),
                },
                new JwtSecurityTokenTestVariation
                { 
                    Name = "EncodedString: two parts each a single character: '1.2'", 
                    EncodedString = "1.2", 
                    ExpectedException = ExpectedException.ArgEx( id:"Jwt10400"),
                },

                new JwtSecurityTokenTestVariation
                { 
                    Name = "EncodedString: header is not encoded properly: '123'", 
                    EncodedString = string.Format( "{0}.{1}.{2}", "123", tokenParts[1], tokenParts[2] ), 
                    ExpectedException = ExpectedException.ArgEx( id:"Jwt10113"),
                },
                new JwtSecurityTokenTestVariation
                { 
                    Name = "EncodedString: header is not encoded properly: '123=='", 
                    EncodedString = string.Format( "{0}.{1}.{2}", "123==", tokenParts[1], tokenParts[2] ),
                    ExpectedException = ExpectedException.ArgEx( id:"Jwt10400"),
                },
                new JwtSecurityTokenTestVariation
                { 
                    Name = "EncodedString: payload is not encoded correctly: '123'", 
                    EncodedString = string.Format( "{1}.{0}.{2}", "123", tokenParts[0], tokenParts[2] ),
                    ExpectedException = ExpectedException.ArgEx( id:"Jwt10113"),
                },                                
                new JwtSecurityTokenTestVariation
                { 
                    Name = "EncodedString: payload is not encoded properly: '123=='", 
                    EncodedString = string.Format( "{1}.{0}.{2}", "123==", tokenParts[0], tokenParts[2] ),
                    ExpectedException = ExpectedException.ArgEx( id:"Jwt10400"),
                },
                new JwtSecurityTokenTestVariation
                { 
                    Name = "EncodedString: valid encoding, NO signature (JWT_AsymmetricSigned_AcsV2)",
                    EncodedString = string.Format( "{0}.{1}.", tokenParts[0], tokenParts[1] ),
                    ExpectedException = ExpectedException.Null,
                },                
                new JwtSecurityTokenTestVariation
                { 
                    Name = "EncodedString: valid encoding, NO signature (JWT_AsymmetricSigned_AcsV2)",
                    EncodedString = string.Format( "{0}.{1}.", tokenParts[0], tokenParts[1] ),
                    ExpectedException = ExpectedException.Null,
                },                
            };

            return variationsencodedStringParams;
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "F5803908-4CFA-4038-B506-045CF65D39BD" )]
        [Description( "Tests JWTSecurityToken Constructor that takes .Net params. Claims, issuer, etc." )]
        public void JwtSecurityToken_ConstructionParams()
        {
            Console.WriteLine( string.Format( "Entering: '{0}'", MethodBase.GetCurrentMethod() ) );
            JwtSecurityToken jwt = null;
            foreach ( JwtSecurityTokenTestVariation param in JwtConstructionParamsVariations() )
            {
                Console.WriteLine( string.Format( "Testcase: {0}", param.Name ) );
                try
                {
                    //jwt = new JWTSecurityToken( issuer: param.Issuer, audience: param.Audience, claims: param.Claims, signingCredentials: param.SigningCredentials, lifetime: param.Lifetime, actor: param.Actor);
                    jwt = new JwtSecurityToken( param.Issuer, param.Audience, param.Claims, new Lifetime( param.ValidFrom, param.ValidTo ) );
                    ExpectedException.ProcessNoException( param.ExpectedException );
                }
                catch ( Exception ex )
                {
                    ExpectedException.ProcessException( param.ExpectedException, ex );
                }

                try
                {
                    // ensure we can get to every property
                    if ( jwt != null && ( param.ExpectedException == null || param.ExpectedException.Thrown == null ) )
                    {
                        JwtTestUtilities.CallAllPublicInstanceAndStaticPropertyGets( jwt, param.Name );
                    }

                    if ( null != param.ExpectedJwtSecurityToken )
                    {
                        Assert.IsFalse( !IdentityComparer.AreEqual( param.ExpectedJwtSecurityToken, jwt ) , string.Format( "Testcase: {0}.  JWTSecurityTokens are not equal.", param.Name ) );
                    }
                }
                catch ( Exception ex )
                {
                    Assert.Fail( string.Format( "Testcase: {0}. UnExpected when getting a properties: '{1}'", param.Name, ex.ToString() ) );
                }
            }
        }
        
        private List<JwtSecurityTokenTestVariation> JwtConstructionParamsVariations()
        {
            List<JwtSecurityTokenTestVariation> constructionParams = new List<JwtSecurityTokenTestVariation>() 
            {
                new JwtSecurityTokenTestVariation
                { 
                    Name = "ClaimsSet with all Reserved claim types, ensures that users can add as they see fit",
                    Claims = ClaimSets.AllReserved, 
                    ExpectedException = ExpectedException.Null,
                },
                new JwtSecurityTokenTestVariation
                { 
                    Name = "All null params",
                    Issuer = null,  
                    Audience =  null, 
                    Claims = null, 
                    SigningCredentials = null,
                },
                new JwtSecurityTokenTestVariation
                { 
                    Name = "ValidFrom > ValidTo, .Net datetime",
                    ValidFrom = DateTime.UtcNow + TimeSpan.FromHours(1),
                    ValidTo   = DateTime.UtcNow,
                    ExpectedException = ExpectedException.ArgEx( id: "ID2000" ),
                },
                new JwtSecurityTokenTestVariation
                { 
                    Name = "ValidFrom > ValidTo, UnixEpoch - 1 ms",
                    ValidTo = EpochTime.UnixEpoch - TimeSpan.FromMilliseconds(1), 
                    ValidFrom = DateTime.UtcNow, 
                    ExpectedException = ExpectedException.ArgEx( id: "ID2000" ),
                },
                new JwtSecurityTokenTestVariation
                { 
                    Name = "ValidFrom > ValidTo, UnixEpoch - 1 s",
                    ValidTo = EpochTime.UnixEpoch - TimeSpan.FromSeconds(1), 
                    ValidFrom = DateTime.UtcNow, 
                    ExpectedException = ExpectedException.ArgEx( id: "ID2000" ),
                },
                new JwtSecurityTokenTestVariation
                { 
                    Name = "ValidFrom == DateItime.MinValue",
                    ValidFrom = DateTime.MinValue, 
                    ValidTo = DateTime.UtcNow, 
                },
            };

            return constructionParams;
        }

        private List<JwtSecurityTokenTestVariation> GetConstructorsSameJWT()
        {
            string issuer = "GetJWTTypedConstructorsCases";
            
            List<JwtSecurityTokenTestVariation> constructionParams = new List<JwtSecurityTokenTestVariation>() 
            {
                // ensure format is not format is not checked
                new JwtSecurityTokenTestVariation
                { 
                    Name = "SimpleJwt",
                    Claims = ClaimSets.Simple(issuer,issuer),
                    ExpectedJwtSecurityToken = JwtTestTokens.Simple( issuer, issuer ),
                },
            };

            return constructionParams;
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "C04F947D-9CBB-4062-A522-4BC90E56C996" )]
        [TestProperty( "TestType", "BVT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Ensures that cascading constructors result in the same JWT" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void JWTSecurityToken_DifferentConstructorsSameJWT()
        {
            foreach ( JwtSecurityTokenTestVariation param in GetConstructorsSameJWT() )
            {
                var jwt = new JwtSecurityToken( param.Issuer, param.Audience );
            }
        }

        private List<JwtSecurityTokenTestVariation> GetJWTTypedConstructorsCases()
        {
            string issuer = "GetJWTTypedConstructorsCases";

            List<JwtSecurityTokenTestVariation> constructionParams = new List<JwtSecurityTokenTestVariation>() 
            {
                // ensure format is not format is not checked
                new JwtSecurityTokenTestVariation
                { 
                    Name = "SimpleJwt",
                    Claims = ClaimSets.Simple(issuer,issuer), 
                    ExpectedJwtSecurityToken = JwtTestTokens.Simple( issuer, issuer ),
                },
            };

            return constructionParams;
        }
    }
}
