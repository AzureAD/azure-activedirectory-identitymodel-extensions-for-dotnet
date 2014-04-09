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
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// Test some key extensibility scenarios
    /// </summary>
    [TestClass]
    public class ExtensibilityTests
    {
        /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        protected TestContextProvider _testContextProvider;

        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void ClassSetup( TestContext testContext )
        { }

        [ClassCleanup]
        public static void ClassCleanup()
        { }

        [TestInitialize]
        public void Initialize()
        {
            _testContextProvider = new TestContextProvider( TestContext );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "65A4AD1F-100F-41C3-AD84-4FE08C1F9A6D" )]
        [Description( "Extensibility tests for SecurityKeyIdentifier for JWT key identifiers" )]
        public void JwtSecurityTokenHandler_Extensibility()
        {
            DerivedJwtSecurityTokenHandler handler = new DerivedJwtSecurityTokenHandler() 
            { 
                DerivedTokenType = typeof( DerivedJwtSecurityToken ) 
            };

            JwtSecurityToken jwt = 
                new JwtSecurityToken
                ( 
                    issuer: Issuers.GotJwt, 
                    audience: Audiences.AuthFactors, 
                    claims: ClaimSets.Simple( Issuers.GotJwt, Issuers.GotJwt ), 
                    signingCredentials:KeyingMaterial.SymmetricSigningCreds_256_Sha2, 
                    lifetime: new Lifetime( DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours(10) )
                );

            string encodedJwt =  handler.WriteToken( jwt );
            JwtSecurityToken jwtReadAsDerived = handler.ReadToken( DerivedJwtSecurityToken.Prefix + encodedJwt ) as JwtSecurityToken;
            
            DerivedJwtSecurityToken jwtDerivedNotValidated = jwtReadAsDerived as DerivedJwtSecurityToken;

            TokenValidationParameters tvp = new TokenValidationParameters()
            {
                IssuerSigningKey = KeyingMaterial.SymmetricSecurityKey_256,
                ValidateAudience = false,
                ValidIssuer = Issuers.GotJwt,
            };

            ValidateDerived( jwtReadAsDerived, null, handler, tvp, ExpectedException.Null );
            ValidateDerived( null, DerivedJwtSecurityToken.Prefix + encodedJwt, handler, tvp, ExpectedException.Null );
            handler.Configuration = new SecurityTokenHandlerConfiguration() 
            {
                IssuerTokenResolver = new SetReturnSecurityTokenResolver( KeyingMaterial.BinarySecretToken_256, KeyingMaterial.SymmetricSecurityKey_256 ),
                SaveBootstrapContext = true,
                CertificateValidator = AlwaysSucceedCertificateValidator.New,
                IssuerNameRegistry = new SetNameIssuerNameRegistry( Audiences.AuthFactors ),
                AudienceRestriction = new AudienceRestriction( AudienceUriMode.Always ),                
            };

            handler.Configuration.AudienceRestriction.AllowedAudienceUris.Add( new Uri( Audiences.AuthFactors ) );

            ValidateDerived( null, DerivedJwtSecurityToken.Prefix + encodedJwt, handler, null, ExpectedException.Null );
            ValidateDerived( handler.ReadToken( DerivedJwtSecurityToken.Prefix + encodedJwt ) as JwtSecurityToken, null, handler, null, ExpectedException.Null );

            handler.DerivedTokenType = typeof( JwtSecurityToken );

            JwtSecurityToken jwtRead = handler.ReadToken( encodedJwt ) as JwtSecurityToken;

            ValidateDerived( jwtRead, null, handler, tvp, ExpectedException.Null );
            ValidateDerived( null, encodedJwt, handler, tvp, ExpectedException.Null );
            ValidateDerived( null, encodedJwt, handler, null, ExpectedException.Null );
            ValidateDerived( jwtRead as JwtSecurityToken, null, handler, null, ExpectedException.Null );
        }

        private void ValidateDerived( JwtSecurityToken jwt, string encodedJwt, DerivedJwtSecurityTokenHandler derivedHandler, TokenValidationParameters tvp, ExpectedException ee )
        {
            try
            {
                if ( tvp != null )
                {
                    if ( jwt != null )
                    {
                        derivedHandler.ValidateToken( jwt, tvp );
                    }
                    else
                    {
                        derivedHandler.ValidateToken( encodedJwt, tvp );
                    }
                }
                else
                {
                    if ( jwt != null )
                    {
                        derivedHandler.ValidateToken( jwt );
                    }
                    else
                    {
                        derivedHandler.ValidateToken( encodedJwt );
                    }
                }

                DerivedJwtSecurityToken jwtDerived = jwt as DerivedJwtSecurityToken;
                if ( jwtDerived == null && jwt != null )
                {
                    Assert.IsFalse( derivedHandler.DerivedTokenType == typeof( DerivedJwtSecurityToken ) , "Expected DerivedJwtSecurityToken type, got: " + jwt.GetType() );
                }
                else if ( jwtDerived != null )
                {
                    Assert.IsFalse( !jwtDerived.ValidateAudienceCalled , "!jwtDerived.ValidateAudienceCalled" );

                    Assert.IsFalse( !jwtDerived.ValidateIssuerCalled , "!jwtDerived.ValidateAudienceCalled" );

                    Assert.IsFalse( !jwtDerived.ValidateLifetimeCalled , "!jwtDerived.ValidateLifetimeCalled" );

                    Assert.IsFalse( !jwtDerived.ValidateSignatureCalled , "!jwtDerived.ValidateSignatureCalled" );

                    Assert.IsFalse( !jwtDerived.ValidateSigningTokenCalled , "!jwtDerived.ValidateSigningTokenCalled" );
                }

                ExpectedException.ProcessNoException( ee );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "65A4AD1F-100F-41C3-AD84-4FE08C1F9A6D" )]
        [Description( "Extensibility tests for SecurityKeyIdentifier for JWT key identifiers" )]
        public void JwtSecurityKeyIdentifyier_Extensibility()
        {
            string clauseName = "kid";
            string keyId    = Issuers.GotJwt;

            NamedKeySecurityKeyIdentifierClause clause = new NamedKeySecurityKeyIdentifierClause( clauseName, keyId );
            SecurityKeyIdentifier keyIdentifier = new SecurityKeyIdentifier( clause );
            SigningCredentials signingCredentials = new SigningCredentials( KeyingMaterial.SymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest, keyIdentifier );
            JwtHeader jwtHeader = new JwtHeader( signingCredentials );            
            SecurityKeyIdentifier ski = jwtHeader.SigningKeyIdentifier;
            Assert.IsFalse( ski.Count != 1, "ski.Count != 1 " );

            NamedKeySecurityKeyIdentifierClause clauseOut = ski.Find<NamedKeySecurityKeyIdentifierClause>();
            Assert.IsFalse( clauseOut == null , "NamedKeySecurityKeyIdentifierClause not found" );
            Assert.IsFalse( clauseOut.Name != clauseName , "clauseOut.Id != clauseId" );
            Assert.IsFalse( clauseOut.KeyIdentifier != keyId , "clauseOut.KeyIdentifier != keyId" );

            NamedKeySecurityToken NamedKeySecurityToken = new NamedKeySecurityToken( clauseName, new SecurityKey[]{ KeyingMaterial.SymmetricSecurityKey_256 } );
            Assert.IsFalse( !NamedKeySecurityToken.MatchesKeyIdentifierClause( clause ) , "NamedKeySecurityToken.MatchesKeyIdentifierClause( clause ), failed" );

            List<SecurityKey> list = new List<SecurityKey>() { KeyingMaterial.SymmetricSecurityKey_256 };
            Dictionary< string, IList<SecurityKey>> keys = new Dictionary< string, IList<SecurityKey>>() { { "kid", list }, };
            NamedKeyIssuerTokenResolver nkitr = new NamedKeyIssuerTokenResolver( keys: keys );
            SecurityKey sk =  nkitr.ResolveSecurityKey( clause );
            Assert.IsFalse( sk == null , "NamedKeySecurityToken.MatchesKeyIdentifierClause( clause ), failed" );

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwt = handler.CreateToken( issuer: Issuers.GotJwt, signingCredentials: signingCredentials ) as JwtSecurityToken;
            handler.Configuration = new SecurityTokenHandlerConfiguration() 
            { 
                IssuerTokenResolver = new NamedKeyIssuerTokenResolver( keys: keys ), 
                AudienceRestriction = new AudienceRestriction( AudienceUriMode.Never ),
                IssuerNameRegistry = new SetNameIssuerNameRegistry( "http://GotJwt.com" ),
            };

            handler.ValidateToken( jwt );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "E9A1AB3E-6AAE-4AC4-9DD4-1DDA5FAC70CF" )]
        [Description( "Extensibility tests for JwtSecurityTokenHandler" )]
        public void JwtSecurityTokenHandlerExtensibility()
        {
            // TODO: Review and fix.  Log.Warning( "Test not completed" );
            RunProtectedNullChecks();
        }

        private void RunProtectedNullChecks()
        {
            PublicJwtSecurityTokenHandler tokenHandler = new PublicJwtSecurityTokenHandler();

        }

        [TestMethod]
        [TestProperty( "TestCaseID", "C4FC2FC1-5AB0-4A73-A620-59D1FBF92D7A" )]
        [Description( "Extensibility tests for AsymmetricSignatureProvider" )]
        public void AsymmetricSignatureProvider_Extensibility_AlgorithmMapping()
        {            
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            Console.WriteLine( "Testvariation: " + "outbound signature algorithm - bobsYourUncle" );

            // tests that algorithm names can be mapped inbound and outbound
            // bobsYourUncle <=> RsaSha256Signature

            KeyValuePair<string, string> originalOutbound = new KeyValuePair<string,string>(null, null);
            if (JwtSecurityTokenHandler.OutboundAlgorithmMap.ContainsKey(SecurityAlgorithms.RsaSha256Signature))
            {
                originalOutbound = new KeyValuePair<string,string>(SecurityAlgorithms.RsaSha256Signature, JwtSecurityTokenHandler.OutboundAlgorithmMap[SecurityAlgorithms.RsaSha256Signature]);
                JwtSecurityTokenHandler.OutboundAlgorithmMap.Remove(SecurityAlgorithms.RsaSha256Signature);
            }

            JwtSecurityTokenHandler.OutboundAlgorithmMap.Add( new KeyValuePair<string,string>(SecurityAlgorithms.RsaSha256Signature, "bobsYourUncle"));
            JwtSecurityToken jwt = handler.CreateToken( issuer: Issuers.GotJwt,  signingCredentials: KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2 ) as JwtSecurityToken;
            JwtSecurityTokenHandler.OutboundAlgorithmMap.Remove(SecurityAlgorithms.RsaSha256Signature);
            if (originalOutbound.Key != null)
            {
                JwtSecurityTokenHandler.OutboundAlgorithmMap.Add(originalOutbound);
            }

            List<SecurityToken> tokens = new List<SecurityToken>(){ KeyingMaterial.X509Token_2048 };
            handler.Configuration = new SecurityTokenHandlerConfiguration() 
                                    {
                                        AudienceRestriction = new AudienceRestriction(AudienceUriMode.Never),
                                        CertificateValidator = AlwaysSucceedCertificateValidator.New,
                                        IssuerNameRegistry = new SetNameIssuerNameRegistry("bobsYourUncle"),
                                        IssuerTokenResolver =  SecurityTokenResolver.CreateDefaultSecurityTokenResolver( tokens.AsReadOnly(), true ), 
                                        SaveBootstrapContext = true,
                                    };

            // inbound unknown algorithm
            ExpectedException expectedException = new ExpectedException(thrown: typeof(SecurityTokenInvalidSignatureException), id: "Jwt10316");
            try
            {
                handler.ValidateToken( jwt );
                ExpectedException.ProcessNoException( expectedException );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( expectedException, ex );
            }

            // inbound is mapped
            KeyValuePair<string, string> originalInbound = new KeyValuePair<string, string>(null, null);
            if (JwtSecurityTokenHandler.InboundAlgorithmMap.ContainsKey("bobsYourUncle"))
            {
                originalInbound = new KeyValuePair<string, string>("bobsYourUncle", JwtSecurityTokenHandler.InboundAlgorithmMap["bobsYourUncle"]);
                JwtSecurityTokenHandler.InboundAlgorithmMap.Remove("bobsYourUncle");
            }

            JwtSecurityTokenHandler.InboundAlgorithmMap.Add(new KeyValuePair<string, string>("bobsYourUncle", SecurityAlgorithms.RsaSha256Signature));
            expectedException = ExpectedException.Null;
            try
            {
                handler.ValidateToken(jwt);
                ExpectedException.ProcessNoException(expectedException);
            }
            catch (Exception ex)
            {
                ExpectedException.ProcessException(expectedException, ex);
            }
            finally
            {
                if (originalInbound.Key != null)
                {
                    JwtSecurityTokenHandler.InboundAlgorithmMap.Remove(originalInbound.Key);
                    JwtSecurityTokenHandler.InboundAlgorithmMap.Add(originalInbound);
                }
            }
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "A8068888-87D8-49D6-919F-CDF9AAC26F57" )]
        [Description( "Extensibility tests for SymmetricSignatureProvider" )]
        public void SymmetricSignatureProvider_Extensibility_AlgorithmMapping()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            Console.WriteLine( "Testvariation: " + "outbound signature algorithm - bobsYourUncle" );

            KeyValuePair<string, string> originalOutbound = new KeyValuePair<string, string>(null, null);
            if (JwtSecurityTokenHandler.OutboundAlgorithmMap.ContainsKey(SecurityAlgorithms.HmacSha256Signature))
            {
                originalOutbound = new KeyValuePair<string, string>(SecurityAlgorithms.HmacSha256Signature, JwtSecurityTokenHandler.OutboundAlgorithmMap[SecurityAlgorithms.HmacSha256Signature]);
                JwtSecurityTokenHandler.OutboundAlgorithmMap.Remove(SecurityAlgorithms.HmacSha256Signature);
            }

            JwtSecurityTokenHandler.OutboundAlgorithmMap.Add(new KeyValuePair<string, string>(SecurityAlgorithms.HmacSha256Signature, "bobsYourUncle"));
            JwtSecurityToken jwt = handler.CreateToken(issuer: Issuers.GotJwt, signingCredentials: KeyingMaterial.SymmetricSigningCreds_256_Sha2) as JwtSecurityToken;
            JwtSecurityTokenHandler.OutboundAlgorithmMap.Remove(SecurityAlgorithms.HmacSha256Signature);
            if (originalOutbound.Key != null)
            {
                JwtSecurityTokenHandler.OutboundAlgorithmMap.Add(originalOutbound);
            }

            List<SecurityToken> tokens = new List<SecurityToken>() { KeyingMaterial.BinarySecretToken_256 };

            TokenValidationParameters tvp = new TokenValidationParameters()
            {
                IssuerSigningKey = KeyingMaterial.SymmetricSecurityKey_256,
                ValidateAudience = false,
                ValidIssuer = Issuers.GotJwt,
            };

            // inbound unknown algorithm
            ExpectedException expectedException = new ExpectedException(thrown: typeof(SecurityTokenInvalidSignatureException), id: "Jwt10316" );
            try
            {
                ClaimsPrincipal principal = handler.ValidateToken( jwt, tvp );
                ExpectedException.ProcessNoException( expectedException );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( expectedException, ex );
            }

            // inbound is mapped
            KeyValuePair<string, string> originalInbound = new KeyValuePair<string, string>(null, null);
            if (JwtSecurityTokenHandler.InboundAlgorithmMap.ContainsKey("bobsYourUncle"))
            {
                originalInbound = new KeyValuePair<string, string>("bobsYourUncle", JwtSecurityTokenHandler.InboundAlgorithmMap["bobsYourUncle"]);
                JwtSecurityTokenHandler.InboundAlgorithmMap.Remove("bobsYourUncle");
            }

            JwtSecurityTokenHandler.InboundAlgorithmMap.Add(new KeyValuePair<string, string>("bobsYourUncle", SecurityAlgorithms.HmacSha256Signature));
            expectedException = ExpectedException.Null;
            try
            {
                handler.ValidateToken(jwt.RawData, tvp);
                ExpectedException.ProcessNoException(expectedException);
            }
            catch (Exception ex)
            {
                ExpectedException.ProcessException(expectedException, ex);
            }
            finally
            {
                if (originalInbound.Key != null)
                {
                    JwtSecurityTokenHandler.InboundAlgorithmMap.Remove(originalInbound.Key);
                    JwtSecurityTokenHandler.InboundAlgorithmMap.Add(originalInbound);
                }
            }
        }
    }
}
