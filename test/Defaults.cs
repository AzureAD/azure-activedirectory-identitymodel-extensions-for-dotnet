//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.ObjectModel;
using System.Security.Claims;
using System.IdentityModel.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.Reflection;

namespace System.IdentityModel.Test
{

    /// <summary>
    /// This module is responsible for ensuring that defaults are as expected for all types in the Jwt deliverable.
    /// </summary>
    [TestClass]
    public class Defaults
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
        [TestProperty( "TestCaseID", "FC949834-617F-4C57-8643-C30F160E309D" )]
        [TestProperty( "TestType", "CIT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Ensures that AsymmetricSignatureProvider defaults are as expected" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void AsymmetricSignatureProvider_Defaults()
        {

            try
            {
                AsymmetricSignatureProvider asymmetricSignatureProvider = new AsymmetricSignatureProvider( KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2.SigningKey as AsymmetricSecurityKey, KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2.SignatureAlgorithm, false );
            }
            catch ( Exception )
            {
                Assert.Fail( "AsymmetricSignatureProvider creation should not throw" );
            }

            try
            {
                AsymmetricSignatureProvider asymmetricSignatureProvider = new AsymmetricSignatureProvider( KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2.SigningKey as AsymmetricSecurityKey, KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2.SignatureAlgorithm, true );
            }
            catch ( Exception )
            {
                Assert.Fail( "AsymmetricSignatureProvider creation should not throw" );
            }
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "E01771B7-2D9E-435E-A933-09FAB429881E" )]
        [TestProperty( "TestType", "CIT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Ensures that JwtHeader defaults are as expected" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void JwtHeader_Defaults()
        {
            JwtHeader jwtHeader = new JwtHeader();
            Assert.IsFalse( jwtHeader.ContainsValue( JwtConstants.HeaderType ) , "jwtHeader.ContainsValue( JwtConstants.HeaderType )" );

            Assert.IsFalse( jwtHeader.ContainsValue( JwtConstants.ReservedHeaderParameters.Type ) , "jwtHeader.ContainsValue( JwtConstants.ReservedHeaderParameters.Type )" );

            Assert.IsFalse( jwtHeader.ContainsKey( JwtConstants.ReservedHeaderParameters.Algorithm ) , "!jwtHeader.ContainsKey( JwtConstants.ReservedHeaderParameters.Algorithm )" );

            Assert.IsFalse( jwtHeader.SignatureAlgorithm != null , "jwtHeader.SignatureAlgorithm == null" );

            Assert.IsFalse( jwtHeader.SigningCredentials != null , "jwtHeader.SigningCredentials != null" );

            Assert.IsFalse( jwtHeader.SigningKeyIdentifier == null , "jwtHeader.SigningKeyIdentifier == null" );

            Assert.IsFalse( jwtHeader.SigningKeyIdentifier.Count != 0 , "jwtHeader.SigningKeyIdentifier.Count !== 0" );

            Assert.IsFalse( jwtHeader.Comparer.GetType() != StringComparer.Ordinal.GetType() , "jwtHeader.Comparer.GetType() != StringComparer.Ordinal.GetType()" );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "0B55BD6C-40F7-4C82-A0B7-D0B799EA3289" )]
        [TestProperty( "TestType", "CIT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Ensures that JwtPayload defaults are as expected" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void JwtPayload_Defaults()
        {
            JwtPayload jwtPayload = new JwtPayload();

            Assert.IsFalse( jwtPayload.Comparer.GetType() != StringComparer.Ordinal.GetType() , "jwtPayload.Comparer.GetType() != StringComparer.Ordinal.GetType()" );

            List<Claim> claims = jwtPayload.Claims as List<Claim>;            
            Assert.IsFalse( claims == null , "claims as List<Claim> == null" );

            foreach ( Claim c in jwtPayload.Claims )
            {
                Assert.Fail( "claims.Count != 0" );
                break;
            }

            Assert.IsFalse( jwtPayload.Actor != null , "jwtPayload.Actor != null" );

            Assert.IsFalse( jwtPayload.Audience != null , "jwtPayload.Audience != null" );

            Assert.IsFalse( jwtPayload.Expiration != null , "jwtPayload.Expiration != null" );

            Assert.IsFalse( jwtPayload.Id != null , "jwtPayload.Id != null" );

            Assert.IsFalse( jwtPayload.IssuedAt != null , "jwtPayload.IssuedAt != null" );

            Assert.IsFalse( jwtPayload.Issuer != null , "jwtPayload.Issuer != null" );

            Assert.IsFalse( jwtPayload.Subject != null , "jwtPayload.Subject != null" );

            Assert.IsFalse( jwtPayload.ValidFrom != DateTime.MinValue , "jwtPayload.ValidFrom != DateTime.MinValue" );

            Assert.IsFalse( jwtPayload.ValidTo != DateTime.MinValue , "jwtPayload.ValidTo != DateTime.MinValue" );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "EEA6CD8E-DC65-485E-9EC9-9037AC3382A4" )]
        [TestProperty( "TestType", "BVT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Ensures that JwtSecurityToken defaults are as expected" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void JwtSecurityToken_Defaults()
        {
            JwtSecurityToken jwt = new JwtSecurityToken();

            List<Claim> claims = jwt.Claims as List<Claim>;
            Assert.IsFalse( claims == null , "claims as List<Claim> == null" );

            foreach ( Claim c in jwt.Claims )
            {
                Assert.Fail( "claims.Count != 0" );
                break;
            }

            Assert.IsFalse( jwt.Actor != null , "jwt.Actor != null" );

            Assert.IsFalse( jwt.Audience != null , "jwt.Audience != null" );

            Assert.IsFalse( jwt.Expiration != null , "jwt.Expiration != null" );

            Assert.IsFalse( jwt.Id != null , "jwt.Id != null" );

            Assert.IsFalse( jwt.Issuer != null , "jwt.Issuer != null" );

            Assert.IsFalse( jwt.SecurityKeys == null , "jwt.SecurityKeys == null" );

            Assert.IsFalse( jwt.SignatureAlgorithm == null , "jwt.SignatureAlgorithm == null" );

            Assert.IsFalse( !string.Equals( jwt.SignatureAlgorithm, "none", StringComparison.Ordinal ) , "jwt.SignatureAlgorithm != none" );

            Assert.IsFalse( jwt.SigningCredentials != null , "jwt.SigningCredentials != null" );

            Assert.IsFalse( jwt.SigningKey != null , "jwt.SigningKey != null" );

            Assert.IsFalse( jwt.SigningToken != null , "jwt.SigningToken != null" );

            Assert.IsFalse( jwt.Subject != null , "jwt.Subject != null" );

            Assert.IsFalse( jwt.ValidFrom != DateTime.MinValue , "jwt.ValidFrom != DateTime.MinValue" );

            Assert.IsFalse( jwt.ValidTo != DateTime.MinValue , "jwt.ValidTo != DateTime.MinValue" );

            Assert.IsFalse( jwt.RawData != null , "jwt.RawData != null" );

            Assert.IsFalse( jwt.Header == null , "jwt.Header == null" );

            Assert.IsFalse( jwt.Payload == null , "jwt.Payload == null" );

            Assert.IsFalse( jwt.EncodedHeader == null , "jwt.EncodedHeader == null" );

            Assert.IsFalse( jwt.EncodedPayload == null , "jwt.EncodedPayload == null" );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "7F6372F7-36A7-47AE-8C1E-A4EF230194D5" )]
        [TestProperty( "TestType", "CIT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Ensures that JwtSecurityTokenHandler defaults are as expected" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void JwtSecurityTokenHandler_Defaults()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            Assert.IsFalse( !handler.CanValidateToken , "!handler.CanValidateToken" );

            Assert.IsFalse( !handler.CanWriteToken , "!handler.CanWriteToken" );

            Assert.IsFalse( handler.DefaultTokenLifetimeInMinutes != 600 , "handler.DefaultTokenLifetimeInMinutes != 600" );

            Assert.IsFalse( handler.JwtSecurityTokenRequirement == null , "handler.JwtSecurityTokenRequirement == null" );

            Assert.IsFalse( handler.NameClaimType != ClaimsIdentity.DefaultNameClaimType , "handler.NameClaimType != ClaimsIdentity.DefaultNameClaimType" );

            Assert.IsFalse( handler.MaxClockSkew != SecurityTokenHandlerConfiguration.DefaultMaxClockSkew , "handler.MaxClockSkew != SecurityTokenHandlerConfiguration.DefaultMaxClockSkew" );

            Assert.IsFalse( handler.MaxTokenSizeInBytes != 2 * 1024 * 1024 , "handler.MaxTokenSizeInBytes != 2 * 1024 * 1024" );
            
            Assert.IsFalse( handler.RoleClaimType != ClaimsIdentity.DefaultRoleClaimType , "handler.RoleClaimType != ClaimsIdentity.DefaultRoleClaimType" );
            
            Assert.IsFalse( !handler.RequireExpirationTime , "!handler.RequireExpirationTime" );
            
            Assert.IsFalse( !handler.RequireSignedTokens , "!handler.RequireSignedTokens" );
            
            Assert.IsFalse( handler.SignatureProviderFactory == null , "handler.SignatureProviderFactory == null" );
            
            Assert.IsFalse( handler.TokenType != typeof(JwtSecurityToken) , "handler.TokenType != typeof(JwtSecurityToken)" );
            
            Assert.IsFalse( handler.CreateSecurityTokenReference(new JwtSecurityToken(), false ) != null , "handler.CreateSecurityTokenReference(new JwtSecurityToken(), false ) != nul" );
            
            Assert.IsFalse( handler.CreateSecurityTokenReference(new JwtSecurityToken(), true ) != null , "handler.CreateSecurityTokenReference(new JwtSecurityToken(), true ) != null " );

            string[] tokenIdentifiers = handler.GetTokenTypeIdentifiers();

            Assert.IsFalse( tokenIdentifiers.Length != 2  , "tokenIdentifiers.Length != 2 " );

            // this seemly simple order will break WebSSO if the first type is not an absolute URI
            Assert.IsFalse( tokenIdentifiers[0] != JwtConstants.TokenTypeAlt  , "tokenIdentifiers[0] != JwtConstants.TokenTypeAlt " );
            
            Uri result = null;
            Assert.IsFalse( !Uri.TryCreate( tokenIdentifiers[0], UriKind.Absolute, out result ) , "tokenIdentifiers[0] must be able to create an UriKind.Absolute" );

            Assert.IsFalse( tokenIdentifiers[1] != JwtConstants.TokenType  , "tokenIdentifiers[1] != JwtConstants.TokenType" );

            Assert.IsFalse( handler.CertificateValidator == null , "handler.CertificateValidator == null" );

            Type type = handler.CertificateValidator.GetType();

            FieldInfo fi = type.GetField( "validator", BindingFlags.NonPublic | BindingFlags.Instance );
            X509CertificateValidator validator = (X509CertificateValidator)fi.GetValue( handler.CertificateValidator );
            Assert.IsFalse( validator.GetType() != X509CertificateValidator.PeerOrChainTrust.GetType() , "validator.GetType() != X509CertificateValidator.PeerOrChainTrust.GetType() " );
        }

#if false
        [TestMethod]
        [TestProperty( "TestCaseID", "D540296C-BEFD-4D37-BC94-6E3FD9DBBC31" )]
        [TestProperty( "TestType", "CIT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Ensures that JwtSecurityTokenRequirement defaults are as expected" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void JwtSecurityTokenRequirement_Defaults()
        {
            Log.Warning( "Test not written" );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "A922C76A-1313-49BC-9234-96A1A422293F" )]
        [TestProperty( "TestType", "CIT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Ensures that NamedKeyIssuerTokenResolver defaults are as expected" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void NamedKeyIssuerTokenResolver_Defaults()
        {
            Log.Warning( "Test not written" );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "7A4A417C-551F-4DF7-A3FB-85EA2D6E2B20" )]
        [TestProperty( "TestType", "CIT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Ensures that NamedSecurityKeyIdentifierClause defaults are as expected" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void NamedSecurityKeyIdentifierClause_Defaults()
        {
            Log.Warning( "Test not written" );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "B510063E-991F-42C5-B275-866CC530C315" )]
        [TestProperty( "TestType", "CIT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Ensures that NamedKeySecurityToken defaults are as expected" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void NamedKeySecurityToken_Defaults()
        {
            Log.Warning( "Test not written" );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "A418CC58-AB19-49AA-A03D-5E29FE1AD62D" )]
        [TestProperty( "TestType", "CIT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Ensures that SignatureProviderFactory defaults are as expected" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void SignatureProviderFactory_Defaults()
        {
            Log.Warning( "Test not written" );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "2E9E7437-D97E-43F9-8711-CD3A81D0F03B" )]
        [TestProperty( "TestType", "CIT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Ensures that SymmetricSignatureProvider defaults are as expected" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void SymmetricSignatureProvider_Defaults()
        {
            Log.Warning( "Test not written" );
        }
#endif
        [TestMethod]
        [TestProperty( "TestCaseID", "606DF40C-2B55-4DA2-A4F1-521E9BDF2A1E" )]
        [TestProperty( "TestType", "BVT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Ensures that TokenValidationParameters defaults are as expected" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void TokenValidationParameters_Defaults()
        {
            TokenValidationParameters tvp = new TokenValidationParameters();

            Assert.IsFalse( tvp.AllowedAudience != null , string.Format( "Expecting: validationParameters.AllowedAudience == null. Was: '{0}'", tvp.AllowedAudience ) );

            Assert.IsFalse( tvp.AllowedAudiences != null , string.Format( "Expecting: validationParameters.AllowedAudiences == null. Was: '{0}'", tvp.AllowedAudiences ) );

            Assert.IsFalse( tvp.AudienceUriMode != AudienceUriMode.BearerKeyOnly , string.Format( "Expecting: validationParameters.AudienceUriMode == AudienceUriMode.BearerKeyOnly. Was: '{0}'", tvp.AudienceUriMode ) );

            Assert.IsFalse( tvp.SaveBootstrapContext , string.Format( "Expecting: validationParameters.SaveBootstrapContext == false. Was: '{0}'", tvp.SaveBootstrapContext ) );

            Assert.IsFalse( tvp.SigningToken != null , string.Format( "Expecting: validationParameters.SigningToken == null. Was: '{0}'", tvp.SigningToken ) );

            Assert.IsFalse( !tvp.ValidateIssuer , string.Format( "Expecting: validationParameters.ValidateIssuer == true. Was: '{0}'", tvp.ValidateIssuer ) );

            Assert.IsFalse( tvp.ValidIssuer != null , string.Format( "Expecting: validationParameters.ValidIssuer == null. Was: '{0}'", tvp.ValidIssuer ) );

            Assert.IsFalse( tvp.ValidIssuers != null , string.Format( "Expecting: validationParameters.ValidIssuers == null. Was: '{0}'", tvp.ValidIssuers ) );
        }        
    }
}
