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
using System.Reflection;
using Claim = System.Security.Claims.Claim;

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
        [TestProperty("TestCaseID", "EEA6CD8E-DC65-485E-9EC9-9037AC3382A4")]
        [Description("Ensures that JwtSecurityToken defaults are as expected")]
        public void JwtSecurityToken_Defaults()
        {
            JwtSecurityToken jwt = new JwtSecurityToken();

            List<Claim> claims = jwt.Claims as List<Claim>;
            Assert.IsNotNull(claims);

            foreach (Claim c in jwt.Claims)
            {
                Assert.Fail("claims.Count != 0");
                break;
            }

            Assert.IsNull(jwt.Actor);
            Assert.IsNotNull(jwt.Audiences);
            foreach (string aud in jwt.Audiences)
            {
                Assert.Fail("jwt.Audiences should be empty");
            }
            Assert.IsNull(jwt.Id);
            Assert.IsNull(jwt.Issuer);
            Assert.IsNotNull(jwt.SecurityKeys);
            Assert.IsNotNull(jwt.SignatureAlgorithm);
            Assert.AreEqual(jwt.SignatureAlgorithm, "none");
            Assert.IsNull(jwt.SigningCredentials);
            Assert.IsNull(jwt.SigningKey);
            Assert.IsNull(jwt.SigningToken);
            Assert.IsNull(jwt.Subject);
            Assert.AreEqual(jwt.ValidFrom, DateTime.MinValue);
            Assert.AreEqual(jwt.ValidTo, DateTime.MinValue);
            Assert.IsNull(jwt.RawData);
            Assert.IsNotNull(jwt.Header);
            Assert.IsNotNull(jwt.Payload);
            Assert.IsNotNull(jwt.EncodedHeader);
            Assert.IsNotNull(jwt.EncodedPayload);
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "F5803908-4CFA-4038-B506-045CF65D39BD" )]
        [Description( "Tests JwtSecurityToken Constructor that takes an EncodedString" )]
        public void JwtSecurityToken_EncodedStringConstruction()
        {
            Console.WriteLine( "Entering: "+ MethodBase.GetCurrentMethod() );

            string[] tokenParts = EncodedJwts.Asymmetric_LocalSts.Split('.');

            RunEncodedTest( new JwtSecurityTokenTestVariation
            { 
                Name = "EncodedString: InvalidPayloadFormat",
                EncodedString = EncodedJwts.InvalidPayload,
                ExpectedException = ExpectedException.ArgumentException( substringExpected: "IDX10703:", inner: typeof(FormatException) ),
            });                
            RunEncodedTest( new JwtSecurityTokenTestVariation
            { 
                Name = "EncodedString: null", 
                EncodedString = null, 
                ExpectedException = ExpectedException.ArgumentNullException(),
            });
            RunEncodedTest( new JwtSecurityTokenTestVariation
            { 
                Name = "EncodedString: string.Empty", 
                EncodedString = string.Empty, 
                ExpectedException = ExpectedException.ArgumentException(substringExpected:"IDX10002:"),
            });
            RunEncodedTest( new JwtSecurityTokenTestVariation
            { 
                Name = "EncodedString: single character: '1'", 
                EncodedString = "1",
                ExpectedException = ExpectedException.ArgumentException( substringExpected:"IDX10709:"),
            });
            RunEncodedTest( new JwtSecurityTokenTestVariation
            { 
                Name = "EncodedString: two parts each a single character: '1.2'", 
                EncodedString = "1.2",
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10709:"),
            });

            RunEncodedTest( new JwtSecurityTokenTestVariation
            { 
                Name = "EncodedString: header is not encoded properly: '123'", 
                EncodedString = string.Format( "{0}.{1}.{2}", "123", tokenParts[1], tokenParts[2] ),
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10703:", inner: typeof(ArgumentException)),
            });

            RunEncodedTest( new JwtSecurityTokenTestVariation
            { 
                Name = "EncodedString: header is not encoded properly: '123=='", 
                EncodedString = string.Format( "{0}.{1}.{2}", "123==", tokenParts[1], tokenParts[2] ),
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10709"),
            });

            RunEncodedTest( new JwtSecurityTokenTestVariation
            { 
                Name = "EncodedString: payload is not encoded correctly: '123'", 
                EncodedString = string.Format( "{1}.{0}.{2}", "123", tokenParts[0], tokenParts[2] ),
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10703:", inner: typeof(ArgumentException)),
            });                                

            RunEncodedTest( new JwtSecurityTokenTestVariation
            { 
                Name = "EncodedString: payload is not encoded properly: '123=='", 
                EncodedString = string.Format( "{1}.{0}.{2}", "123==", tokenParts[0], tokenParts[2] ),
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10709:"),
            });

            RunEncodedTest( new JwtSecurityTokenTestVariation
            { 
                Name = "EncodedString: valid encoding, NO signature (JWT_AsymmetricSigned_AcsV2)",
                EncodedString = string.Format( "{0}.{1}.", tokenParts[0], tokenParts[1] ),
                ExpectedException = ExpectedException.NoExceptionExpected,
            });                

            RunEncodedTest( new JwtSecurityTokenTestVariation
            { 
                Name = "EncodedString: valid encoding, NO signature (JWT_AsymmetricSigned_AcsV2)",
                EncodedString = string.Format( "{0}.{1}.{2}.{3}", tokenParts[0], tokenParts[1], tokenParts[2], tokenParts[2] ),
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10709:"),
            });                
        }

        private void RunEncodedTest(JwtSecurityTokenTestVariation variation)
        {
            JwtSecurityToken jwt = null;
            Console.WriteLine(string.Format("Variation: {0}", variation.Name));
            try
            {
                jwt = new JwtSecurityToken(variation.EncodedString);
                variation.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                variation.ExpectedException.ProcessException(ex);
            }

            // ensure we can get to every property
            if (jwt != null && (variation.ExpectedException == null || variation.ExpectedException.TypeExpected == null))
            {
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(jwt, variation.Name);
            }

            if (null != variation.ExpectedJwtSecurityToken)
            {
                Assert.IsTrue(
                    IdentityComparer.AreEqual(variation.ExpectedJwtSecurityToken, jwt),
                    string.Format("Testcase: {0}.  JWTSecurityTokens are not equal.", variation.Name));
            }
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "F5803908-4CFA-4038-B506-045CF65D39BD" )]
        [Description( "Tests: Constructor" )]
        public void JwtSecurityToken_Constructor()
        {
            Console.WriteLine( string.Format( "Entering: '{0}'", MethodBase.GetCurrentMethod() ) );
            RunConstructionTest(
                new JwtSecurityTokenTestVariation
                { 
                    Name = "ClaimsSet with all Reserved claim types, ensures that users can add as they see fit",
                    Claims = ClaimSets.AllReserved, 
                    ExpectedException = ExpectedException.NoExceptionExpected,
                });
                        
            RunConstructionTest(
                new JwtSecurityTokenTestVariation
                { 
                    Name = "All null params",
                    Issuer = null,  
                    Audience =  null, 
                    Claims = null, 
                    SigningCredentials = null,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                });

            RunConstructionTest(
                new JwtSecurityTokenTestVariation
                {
                    Name = "NotBefore > Expires, .Net datetime",
                    NotBefore = DateTime.UtcNow + TimeSpan.FromHours(1),
                    Expires   = DateTime.UtcNow,
                    ExpectedException = ExpectedException.ArgumentException( substringExpected: "IDX10401" ),
                });

            RunConstructionTest(
                new JwtSecurityTokenTestVariation
                {
                    Name = "NotBefore > Expires, UnixEpoch - 1 ms",
                    NotBefore = DateTime.UtcNow,
                    Expires = EpochTime.UnixEpoch - TimeSpan.FromMilliseconds(1),
                    ExpectedException = ExpectedException.ArgumentException( substringExpected: "IDX10401" ),
                });

            RunConstructionTest(
                new JwtSecurityTokenTestVariation
                {
                    Name = "NotBefore > Expires, UnixEpoch - 1 s",
                    NotBefore = DateTime.UtcNow,
                    Expires = EpochTime.UnixEpoch - TimeSpan.FromSeconds(1), 
                    ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10401"),
                });

            RunConstructionTest(
                new JwtSecurityTokenTestVariation
                {
                    Name = "NotBefore == DateItime.MinValue",
                    NotBefore = DateTime.MinValue, 
                    Expires = DateTime.UtcNow, 
                });
            }

        private void RunConstructionTest(JwtSecurityTokenTestVariation variation)
        {
            JwtSecurityToken jwt = null;
            try
            {
                jwt = new JwtSecurityToken(
                    issuer: variation.Issuer,
                    audience: variation.Audience,
                    claims: variation.Claims,
                    signingCredentials: variation.SigningCredentials,
                    notBefore: variation.NotBefore,
                    expires: variation.Expires);

                variation.ExpectedException.ProcessNoException();
            }
            catch ( Exception ex )
            {
                variation.ExpectedException.ProcessException(ex);
            }

            try
            {
                // ensure we can get to every property
                if ( jwt != null && ( variation.ExpectedException == null || variation.ExpectedException.TypeExpected == null ) )
                {
                    TestUtilities.CallAllPublicInstanceAndStaticPropertyGets( jwt, variation.Name );
                }

                if ( null != variation.ExpectedJwtSecurityToken )
                {
                    Assert.IsTrue(IdentityComparer.AreEqual( variation.ExpectedJwtSecurityToken, jwt ));
                }
            }
            catch ( Exception ex )
            {
                Assert.Fail( string.Format( "Testcase: {0}. UnExpected when getting a properties: '{1}'", variation.Name, ex.ToString() ) );
            }
        }
        
        [TestMethod]
        [TestProperty( "TestCaseID", "C04F947D-9CBB-4062-A522-4BC90E56C996" )]
        [TestProperty( "TestType", "BVT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Ensures that cascading constructors result in the same JWT" )]
        [Priority( 0 )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void JwtSecurityToken_DifferentConstructorsSameJWT()
        {
            string issuer = "JWTSecurityToken_DifferentConstructorsSameJWT";
            new JwtSecurityTokenTestVariation
            {
                Name = "SimpleJwt",
                Claims = ClaimSets.Simple(issuer, issuer),
                ExpectedJwtSecurityToken = JwtTestTokens.Simple(issuer, issuer),
            };
        }
    }
}
