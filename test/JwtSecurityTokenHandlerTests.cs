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
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Claims;
using System.Text;
using System.Xml;

using ReservedClaims = System.IdentityModel.Tokens.JwtConstants.ReservedClaims;

namespace System.IdentityModel.Test
{
    public class XmlReaderVariation
    {
        public const string  WsuId                    = "c9b6b6b4-bd35-46ae-8146-15d6b00d22ed";
        private const string _templateWithEncoding    = @"<wsse:{0}  xmlns:wsu='{1}' xmlns:wsse='{2}' ValueType='{3}' EncodingType='{4}' wsu:Id='c9b6b6b4-bd35-46ae-8146-15d6b00d22ed' >{5}</wsse:{0}>";
        private const string _templateWithoutEncoding = @"<wsse:{0}  xmlns:wsu='{1}' xmlns:wsse='{2}' ValueType='{3}'>{4}</wsse:{0}>";
        private const string _templateWithoutns       = @"<{0}  ValueType='{1}' EncodingType='{2}'>{3}<{0}>";

        public static XmlReader JwtTokenType
        {
            get
            {
                string bst = string.Format( _templateWithEncoding,
                                            WSSecurity10Constants.Elements.BinarySecurityToken,
                                            WSSecurityUtilityConstants.Namespace,
                                            WSSecurity10Constants.Namespace,
                                            JwtConstants.TokenType,
                                            WSSecurity10Constants.Base64EncodingType,
                                            EncodedJwts.Asymmetric_LocalSts );

                XmlReader reader = XmlReader.Create( new MemoryStream( UTF8Encoding.UTF8.GetBytes( bst ) ) );
                reader.MoveToContent();
                return reader;
            }
        }

        public static XmlReader JwtTokenTypeAlt
        {
            get
            {
                string bst = string.Format( _templateWithEncoding,
                                            WSSecurity10Constants.Elements.BinarySecurityToken,
                                            WSSecurityUtilityConstants.Namespace,
                                            WSSecurity10Constants.Namespace,
                                            JwtConstants.TokenTypeAlt,
                                            WSSecurity10Constants.Base64EncodingType,
                                            EncodedJwts.Asymmetric_LocalSts );

                XmlReader reader = XmlReader.Create( new MemoryStream( UTF8Encoding.UTF8.GetBytes( bst ) ) );
                reader.MoveToContent();
                return reader;
            }
        }

        public static XmlReader WithoutEncodingType
        {
            get
            {
                string bst = string.Format( _templateWithoutEncoding,
                                            WSSecurity10Constants.Elements.BinarySecurityToken,
                                            WSSecurityUtilityConstants.Namespace,
                                            WSSecurity10Constants.Namespace,
                                            JwtConstants.TokenType,
                                            EncodedJwts.Asymmetric_LocalSts );

                XmlReader reader = XmlReader.Create( new MemoryStream( UTF8Encoding.UTF8.GetBytes( bst ) ) );
                reader.MoveToContent();
                return reader;
            }
        }

        public static XmlReader WithWrongEncodingType
        {
            get
            {
                string bst = string.Format( _templateWithEncoding,
                                            WSSecurity10Constants.Elements.BinarySecurityToken,
                                            WSSecurityUtilityConstants.Namespace,
                                            WSSecurity10Constants.Namespace,
                                            JwtConstants.TokenType,
                                            "BadEncoding",
                                            EncodedJwts.Asymmetric_LocalSts );

                XmlReader reader = XmlReader.Create( new MemoryStream( UTF8Encoding.UTF8.GetBytes( bst ) ) );
                reader.MoveToContent();
                return reader;
            }
        }

        public static XmlReader WithWrongTokenType
        {
            get
            {
                string bst = string.Format( _templateWithoutEncoding,
                                            WSSecurity10Constants.Elements.BinarySecurityToken,
                                            WSSecurityUtilityConstants.Namespace,
                                            WSSecurity10Constants.Namespace,
                                            "JwtConstants.TokenTypeShort",
                                            EncodedJwts.Asymmetric_LocalSts );

                XmlReader reader = XmlReader.Create( new MemoryStream( UTF8Encoding.UTF8.GetBytes( bst ) ) );
                reader.MoveToContent();
                return reader;
            }
        }

        public static XmlReader WithoutNS
        {
            get
            {
                string bst = string.Format( _templateWithoutns,
                                            WSSecurity10Constants.Elements.BinarySecurityToken,
                                            JwtConstants.TokenType,
                                            WSSecurity10Constants.Base64EncodingType,
                                            EncodedJwts.Asymmetric_LocalSts );

                XmlReader reader = XmlReader.Create( new MemoryStream( UTF8Encoding.UTF8.GetBytes( bst ) ) );
                reader.MoveToContent();
                return reader;
            }
        }

    }

    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class JwtSecurityTokenHandlerTests
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
        [TestProperty( "TestCaseID", "B237EA9D-0453-4717-8870-E6A49DE04F0E" )]
        [Description( "Actor Tests.  Ensure that 'actors' work correctly inbound and outbound.  Signed, with and without bootstrap context" )]
        public void JwtSecurityTokenHandler_Actor()
        {
            // Set up tests artifacts here.
            List<SecurityToken> tokens = new List<SecurityToken>() { KeyingMaterial.X509Token_2048 };
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            SignatureProvider asymmetricProvider = ( new SignatureProviderFactory().CreateForSigning( KeyingMaterial.AsymmetricKey_2048, SecurityAlgorithms.RsaSha256Signature ) );
            SigningCredentials signingCreds = KeyingMaterial.AsymmetricSigningCreds_2048_RsaSha2_Sha2;

            SecurityTokenHandlerConfiguration configSaveBootstrap = new SecurityTokenHandlerConfiguration()
            {
                IssuerTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver( tokens.AsReadOnly(), true ),
                SaveBootstrapContext = true,
                CertificateValidator = AlwaysSucceedCertificateValidator.New,
                AudienceRestriction = new AudienceRestriction( AudienceUriMode.Never ),
                IssuerNameRegistry = new SetNameIssuerNameRegistry( "http://GotJwt.com" ),
            };

            SecurityTokenHandlerConfiguration configDontSaveBootstrap = new SecurityTokenHandlerConfiguration()
            {
                IssuerTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver( tokens.AsReadOnly(), true ),
                SaveBootstrapContext = false,
                CertificateValidator = AlwaysSucceedCertificateValidator.New,
                AudienceRestriction = new AudienceRestriction( AudienceUriMode.Never ),
                IssuerNameRegistry = new SetNameIssuerNameRegistry( "http://GotJwt.com" ),
            };

            // Create the Jwts
            JwtSecurityToken jwtSignedRawData = handler.CreateToken( issuer: Issuers.Actor, signatureProvider: asymmetricProvider, signingCredentials: signingCreds ) as JwtSecurityToken;
            JwtSecurityToken jwtUnsignedWithRawData = handler.CreateToken( issuer: Issuers.Actor ) as JwtSecurityToken;

            // Create the ClaimsIdentities
            handler.Configuration = configSaveBootstrap;

            ClaimsIdentity identitySignedBootstrapRawData = handler.ValidateToken( jwtSignedRawData ).Identity as ClaimsIdentity;
            handler.Configuration.SaveBootstrapContext = false;

            ClaimsIdentity identitySignedRawData = handler.ValidateToken( jwtSignedRawData ).Identity as ClaimsIdentity;
            ClaimsIdentity identity = new ClaimsIdentity( ClaimSets.Simple( Issuers.GotJwt, Issuers.GotJwtOriginal ) );

            // =============================
            // outbound

            // 
            // Variation: 
            // ClaimsIdentity.Actor:    Bootstrapcontext == jwtEncodedString
            //                          Actor == identitySignedRawData

            Console.WriteLine( "actor with rawdata, signed, ClaimsIdentity with BootstrapContext" );

            identity.Actor = identitySignedBootstrapRawData;
            identity.Actor.Actor = identitySignedRawData;
            SerializeAndDeserialize( identity );


            JwtSecurityToken jwtFromClaimsIdentityWithActor = handler.CreateToken( issuer: Issuers.Actor, subject: identity, signatureProvider: asymmetricProvider, signingCredentials: signingCreds) as JwtSecurityToken;
            JwtSecurityToken jwt = new JwtSecurityToken( jwtFromClaimsIdentityWithActor.RawData );
            IdentityComparer.AreEqual( jwt, jwtFromClaimsIdentityWithActor );
            
            // value of { actort, 'value' } should be rawdata of the identity.Actor
            Assert.IsFalse( jwt.Actor != jwtSignedRawData.RawData , "jwt.Actor != jwtActor.RawData" );

            // ClaimsIdentity.Actor != null and == identitySignedBootstrapRawData
            handler.Configuration.SaveBootstrapContext = true;
            ClaimsPrincipal cp = handler.ValidateToken( jwtFromClaimsIdentityWithActor );
            ClaimsIdentity actor = ( ( cp.Identity ) as ClaimsIdentity ).Actor;
            Assert.IsFalse( actor == null , "actor == null" );

            string actorAsEncodedString = actor.BootstrapContext as string;
            Assert.IsFalse( actorAsEncodedString == null , "actorAsEncodedString = actor.BootstrapContext(== null)" );
            Assert.IsFalse( actorAsEncodedString != jwtSignedRawData.RawData , "actorAsEncodedString = actor.BootstrapContext(== null)" );

            SerializeAndDeserialize( identity );

            Console.WriteLine( "actor with rawdata, signed, ClaimsIdentity without BootstrapContext" );
            handler.Configuration.SaveBootstrapContext = false;
            identity.Actor = identitySignedBootstrapRawData;
            jwtFromClaimsIdentityWithActor = handler.CreateToken( issuer: Issuers.Actor, subject: identity, signatureProvider: asymmetricProvider, signingCredentials: signingCreds ) as JwtSecurityToken;
            jwt = new JwtSecurityToken( jwtFromClaimsIdentityWithActor.RawData );

            // value of { actort, 'value' } should be rawdata of the identity.Actor
            Assert.IsFalse( jwt.Actor != jwtSignedRawData.RawData , "jwt.Actor != jwtSignedRawData.RawData" );

            // ClaimsIdentity.Actor != null and == identitySignedBootstrapRawData
            cp = handler.ValidateToken( jwtFromClaimsIdentityWithActor );
            actor = ( ( cp.Identity ) as ClaimsIdentity ).Actor;
            Assert.IsFalse( actor == null , "actor == null" );

            actorAsEncodedString = actor.BootstrapContext as string;
            Assert.IsFalse( actor.BootstrapContext != null , "actor.BootstrapContext != null" );

            SerializeAndDeserialize( identity );

            //  actor without rawdata
            //  jwt set actor directly on Payload by adding actor claim
            //  multiple actors


            // inbound           
            // Actor claim, cannot parse,
            // multiple actors

            // save bootstrap


            Console.WriteLine( "Catch Circular actor" );
            // circular logic here.
            ExpectedException ee = ExpectedException.InvalidOp();
            try
            {
                identity.Actor = identity;
                ExpectedException.ProcessNoException( ee );
            }
            catch ( InvalidOperationException ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }            
        }

        private void SerializeAndDeserialize( ClaimsIdentity identity )
        {
            // ensure that deserialized picks up bootstrap actor etc.
            MemoryStream ms = new MemoryStream();
            BinaryFormatter bf = new BinaryFormatter();
            bf.Serialize( ms, identity );
            ms.Seek( 0, SeekOrigin.Begin );
            ClaimsIdentity identityDeserialized = bf.Deserialize( ms ) as ClaimsIdentity;
            Assert.IsFalse( !IdentityComparer.AreEqual( identity, identityDeserialized ) , "!IdentityComparer.AreEqual( identity, identityDeserialized )" );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "63193E6B-CF8A-4EA5-B9E0-EF4760B5CEEB" )]
        [Description( "Claim Type Mapping - Inbound and Outbound" )]
        public void JwtSecurityTokenHandler_BootstrapContextSerialize()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            List<SecurityToken> tokens = new List<SecurityToken>() { KeyingMaterial.X509Token_2048 };
            handler.Configuration = new SecurityTokenHandlerConfiguration()
            {
                IssuerTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver( tokens.AsReadOnly(), true ),
                SaveBootstrapContext = true,
                CertificateValidator = AlwaysSucceedCertificateValidator.New,
                AudienceRestriction = new AudienceRestriction( AudienceUriMode.Never ),
                IssuerNameRegistry = new SetNameIssuerNameRegistry( "http://GotJwt.com" ),
            };

            JwtSecurityToken jwt = handler.CreateToken( issuer: "http://GotJwt.com", signingCredentials: KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2 ) as JwtSecurityToken;
            ClaimsPrincipal principal = handler.ValidateToken( jwt );
            ClaimsIdentity identity = principal.Identity as ClaimsIdentity;

            BinaryFormatter bf = new BinaryFormatter();
            MemoryStream ms = new MemoryStream();
            bf.Serialize( ms, identity );

            ms.Seek( 0, SeekOrigin.Begin );

            ClaimsIdentity identityDeserialized = bf.Deserialize( ms ) as ClaimsIdentity;

            IdentityComparer.AreEqual( identity, identityDeserialized );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "A1976E06-F5D5-4DDB-88F8-E57B86B4EC64" )]
        [Description( "Claim Type Mapping - Inbound and Outbound" )]
        public void JwtSecurityTokenHandler_ClaimTypeMapping()
        {
            List<KeyValuePair<string, string>> aadStrings = new List<KeyValuePair<string, string>>();
            aadStrings.Add( new KeyValuePair<string, string>( "amr", "http://schemas.microsoft.com/claims/authnmethodsreferences" ) );
            aadStrings.Add( new KeyValuePair<string, string>( "deviceid", "http://schemas.microsoft.com/2012/01/devicecontext/claims/identifier" ) );
            aadStrings.Add( new KeyValuePair<string, string>( "family_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" ) );
            aadStrings.Add( new KeyValuePair<string, string>( "given_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" ) );
            aadStrings.Add( new KeyValuePair<string, string>( "idp", "http://schemas.microsoft.com/identity/claims/identityprovider" ) );
            aadStrings.Add( new KeyValuePair<string, string>( "oid", "http://schemas.microsoft.com/identity/claims/objectidentifier" ) );
            aadStrings.Add( new KeyValuePair<string, string>( "scp", "http://schemas.microsoft.com/identity/claims/scope" ) );
            aadStrings.Add( new KeyValuePair<string, string>( "tid", "http://schemas.microsoft.com/identity/claims/tenantid" ) );
            aadStrings.Add( new KeyValuePair<string, string>( "unique_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" ) );
            aadStrings.Add( new KeyValuePair<string, string>( "upn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" ) );

            foreach ( var kv in aadStrings )
            {
                Assert.IsFalse( !JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( kv.Key ) , "Inbound short type missing: " + kv.Key );
                Assert.IsFalse( JwtSecurityTokenHandler.InboundClaimTypeMap[kv.Key] != kv.Value , "Inbound mapping wrong: key " + kv.Key + " expected: " + JwtSecurityTokenHandler.InboundClaimTypeMap[kv.Key] + ", received: " + kv.Value );
            }

            List<KeyValuePair<string, string>> adfsStrings = new List<KeyValuePair<string, string>>();
            adfsStrings.Add( new KeyValuePair<string, string>( "pwdexptime", "http://schemas.microsoft.com/ws/2012/01/passwordexpirationtime" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "pwdexpdays", "http://schemas.microsoft.com/ws/2012/01/passwordexpirationdays" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "pwdchgurl", "http://schemas.microsoft.com/ws/2012/01/passwordchangeurl" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "clientip", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-ip" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "forwardedclientip", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-forwarded-client-ip" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "clientapplication", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-application" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "clientuseragent", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-user-agent" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "endpointpath", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "proxy", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-proxy" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "relyingpartytrustid", "http://schemas.microsoft.com/2012/01/requestcontext/claims/relyingpartytrustid" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "insidecorporatenetwork", "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "isregistereduser", "http://schemas.microsoft.com/2012/01/devicecontext/claims/isregistereduser" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "deviceowner", "http://schemas.microsoft.com/2012/01/devicecontext/claims/userowner" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "deviceid", "http://schemas.microsoft.com/2012/01/devicecontext/claims/identifier" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "deviceregid", "http://schemas.microsoft.com/2012/01/devicecontext/claims/registrationid" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "devicedispname", "http://schemas.microsoft.com/2012/01/devicecontext/claims/displayname" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "deviceosver", "http://schemas.microsoft.com/2012/01/devicecontext/claims/osversion" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "deviceismanaged", "http://schemas.microsoft.com/2012/01/devicecontext/claims/ismanaged" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "deviceostype", "http://schemas.microsoft.com/2012/01/devicecontext/claims/ostype" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "auth_time", "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "authmethod", "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "given_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "unique_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "upn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "commonname", "http://schemas.xmlsoap.org/claims/CommonName" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "adfs1email", "http://schemas.xmlsoap.org/claims/EmailAddress" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "group", "http://schemas.xmlsoap.org/claims/Group" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "adfs1upn", "http://schemas.xmlsoap.org/claims/UPN" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "role", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "family_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "ppid", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "nameid", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "denyonlysid", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/denyonlysid" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "denyonlyprimarysid", "http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarysid" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "denyonlyprimarygroupsid", "http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarygroupsid" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "groupsid", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "primarygroupsid", "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "primarysid", "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "winaccountname", "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certapppolicy", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/applicationpolicy" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certauthoritykeyidentifier", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/authoritykeyidentifier" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certbasicconstraints", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/basicconstraints" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certeku", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/eku" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certissuer", "http://schemas.microsoft.com/2012/12/certificatecontext/field/issuer" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certissuername", "http://schemas.microsoft.com/2012/12/certificatecontext/field/issuername" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certkeyusage", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/keyusage" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certnotafter", "http://schemas.microsoft.com/2012/12/certificatecontext/field/notafter" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certnotbefore", "http://schemas.microsoft.com/2012/12/certificatecontext/field/notbefore" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certpolicy", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatepolicy" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certpublickey", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/rsa" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certrawdata", "http://schemas.microsoft.com/2012/12/certificatecontext/field/rawdata" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certsubjectaltname", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/san" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certserialnumber", "http://schemas.microsoft.com/ws/2008/06/identity/claims/serialnumber" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certsignaturealgorithm", "http://schemas.microsoft.com/2012/12/certificatecontext/field/signaturealgorithm" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certsubject", "http://schemas.microsoft.com/2012/12/certificatecontext/field/subject" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certsubjectkeyidentifier", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/subjectkeyidentifier" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certsubjectname", "http://schemas.microsoft.com/2012/12/certificatecontext/field/subjectname" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certtemplateinformation", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatetemplateinformation" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certtemplatename", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatetemplatename" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certthumbprint", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/thumbprint" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "certx509version", "http://schemas.microsoft.com/2012/12/certificatecontext/field/x509version" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "acr", "http://schemas.microsoft.com/claims/authnclassreference" )  );
            adfsStrings.Add( new KeyValuePair<string, string>( "amr", "http://schemas.microsoft.com/claims/authnmethodsreferences" )  );


            foreach ( var kv in adfsStrings )
            {
                Assert.IsFalse( !JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( kv.Key ) , "Inbound short type missing: " + kv.Key );
                Assert.IsFalse( JwtSecurityTokenHandler.InboundClaimTypeMap[kv.Key] != kv.Value , "Inbound mapping wrong: key " + kv.Key + " expected: " + JwtSecurityTokenHandler.InboundClaimTypeMap[kv.Key] + ", received: " + kv.Value );
            }

            JwtSecurityToken jwt = new JwtSecurityToken( issuer: Issuers.GotJwt, audience: Audiences.AuthFactors, claims: ClaimSets.AllInboundShortClaimTypes( Issuers.GotJwt, Audiences.AuthFactors ) );

            // These should not be translated.            
            Assert.IsFalse( !IdentityComparer.AreEqual( jwt.Claims, ClaimSets.AllInboundShortClaimTypes( Issuers.GotJwt, Issuers.GotJwt, new List<Claim>() { new Claim( "iss", Issuers.GotJwt, ClaimValueTypes.String, Issuers.GotJwt ), new Claim( "aud", Audiences.AuthFactors, ClaimValueTypes.String, Issuers.GotJwt ) } ) ) , "!IdentityComparer.AreEqual( jwt.Claims, ClaimSets.AllInboundShortClaimTypes( Issuers.GotJwt, AppliesTo.AuthFactors ) )" );

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler()
            {
                RequireSignedTokens = false,
                RequireExpirationTime = false,
                Configuration = new SecurityTokenHandlerConfiguration()
                {
                    IssuerNameRegistry = new SetNameIssuerNameRegistry( Issuers.GotJwt ),
                    AudienceRestriction = new AudienceRestriction( AudienceUriMode.Never ),
                },
            };

            // ValidateToken will map claims according to the InboundClaimTypeMap
            ValidateClaimMapping( jwt, handler, null, null, "Jwt with all ShortClaimTypes, InboundClaimTypeMap default" );

            JwtSecurityTokenHandler.InboundClaimTypeMap.Clear();
            ValidateClaimMapping( jwt, handler, null, null, "Jwt with all ShortClaimTypes, InboundClaimTypeMap.Clear()" );

            // test that setting the NameClaimType override works.
            handler.NameClaimType = ClaimTypes.Email;
            List<Claim> claims = new List<Claim>()
            {
                new Claim( ClaimTypes.GivenName, "Bob", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                new Claim( ClaimTypes.Spn, "spn", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                new Claim( ReservedClaims.Subject, "Subject1", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                new Claim( ReservedClaims.Principal, "Principal1", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                new Claim( ReservedClaims.Subject, "Subject2", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                new Claim( ReservedClaims.Principal, "Principal2", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                new Claim( ReservedClaims.Subject, "Subject3", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
            };

            jwt = new JwtSecurityToken( issuer: Issuers.GotJwt, audience: Audiences.AuthFactors, claims: claims );
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>()
            {
                { ReservedClaims.Email,     "Mapped_" + ReservedClaims.Email },
                { ReservedClaims.GivenName, "Mapped_" + ReservedClaims.GivenName },
                { ReservedClaims.Principal, "Mapped_" + ReservedClaims.Principal },
                { ReservedClaims.Subject,   "Mapped_" + ReservedClaims.Subject },
            };

            List<Claim> expectedClaims = new List<Claim>()
            {
                new Claim( ReservedClaims.Issuer, Issuers.GotJwt, ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                new Claim( ReservedClaims.Audience, Audiences.AuthFactors, ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                new Claim( "Mapped_" + ReservedClaims.Email, "Bob", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                new Claim( ClaimTypes.Spn,   "spn", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                new Claim( "Mapped_" + ReservedClaims.Subject, "Subject1", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                new Claim( "Mapped_" + ReservedClaims.Principal, ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                new Claim( "Mapped_" + ReservedClaims.Subject, "Subject2", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                new Claim( "Mapped_" + ReservedClaims.Principal, "Principal2", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                new Claim( "Mapped_" + ReservedClaims.Subject, "Subject3", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
            };
        }

        private void ValidateClaimMapping( JwtSecurityToken jwt, JwtSecurityTokenHandler handler, IEnumerable<Claim> expectedClaims, string identityName, string variation )
        {
            Console.WriteLine( "ValidateClaimMapping: variation: " + variation );

            ClaimsPrincipal cp = handler.ValidateToken( jwt );
            ClaimsIdentity identity = cp.Identity as ClaimsIdentity;

            Assert.IsFalse( expectedClaims != null &&  !IdentityComparer.AreEqual( identity.Claims, expectedClaims ) , "identity.Claims != expectedClaims" );

            Assert.IsFalse( identityName != null && identity.Name != identityName , "identity.Name != identityName" );


            // This checks that all claims that should have been mapped.
            foreach ( Claim claim in identity.Claims )
            {
                // if it was mapped, make sure the shortname is found in the mapping and equals the claim.Type
                if ( claim.Properties.ContainsKey( JwtSecurityTokenHandler.ShortClaimTypeProperty ) )
                {
                    Assert.IsFalse( !JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( claim.Properties[JwtSecurityTokenHandler.ShortClaimTypeProperty] ) , "!JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( claim.Properties[JwtSecurityTokenHandler.ShortClaimTypeProperty] ): " + claim.Type );
                }
                // there was no short property.
                Assert.IsFalse( JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( claim.Type ) , "JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( claim.Type ), wasn't mapped claim.Type: " + claim.Type );
            }

            foreach ( Claim claim in jwt.Claims )
            {
                string claimType = claim.Type;

                if ( JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( claimType ) )
                {
                    claimType = JwtSecurityTokenHandler.InboundClaimTypeMap[claim.Type];
                }

                Claim firstClaim = identity.FindFirst( claimType );
                Assert.IsFalse( firstClaim == null , "Claim firstClaim = identity.FindFirst( claimType ), firstClaim == null. claim.Type: " + claim.Type + " claimType: " + claimType );
            }
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "2CADC17D-D1F4-4A20-B54A-44FE37445348" )]
        [Description( "Public calls into JwtSecurityTokenHandler" )]
        public void JwtSecurityTokenHandler_PublicCalls()
        {
            string methodToCall = _testContextProvider.GetValue<string>( "Method" );

            foreach ( JwtSecurityTokenTestVariation variation in  PublicMethodVariations() )
            {
                Console.WriteLine( "Variation: " + variation.Name );
                try
                {
                    if ( variation.Name.StartsWith("CanReadToken_XmlReader") )
                    {
                        bool retval = variation.JwtSecurityTokenHandler.CanReadToken( variation.XmlReader );
                        Assert.IsFalse( retval != variation.BoolRetVal, string.Format( "variation.JwtSecurityTokenHandler.CanReadToken: expected: '{0}', received: '{1}'", variation.BoolRetVal, retval ) );

                    }
                    else if ( variation.Name.StartsWith( "CanReadToken_String" ) )
                    {

                        Assert.IsFalse( variation.JwtSecurityTokenHandler.CanReadToken( variation.EncodedString ) != variation.BoolRetVal, string.Format( "variation.JwtSecurityTokenHandler.CanReadToken: expected: '{0}', received: '{1}'", variation.BoolRetVal, variation.JwtSecurityTokenHandler.CanReadToken( variation.EncodedString ) ) );
                    }
                    else if ( variation.Name.StartsWith( "CanValidateToken" ) )
                    {
                        Assert.IsFalse( variation.JwtSecurityTokenHandler.CanValidateToken != variation.BoolRetVal, string.Format( "variation.JwtSecurityTokenHandler.CanValidateToken: expected: '{0}', received: '{1}'", variation.BoolRetVal, variation.JwtSecurityTokenHandler.CanValidateToken ) );
                    }
                    else if ( variation.Name.StartsWith( "CanWriteToken" ) )
                    {
                        Assert.IsFalse( variation.JwtSecurityTokenHandler.CanWriteToken != variation.BoolRetVal, string.Format( "variation.JwtSecurityTokenHandler.CanWriteToken: expected: '{0}', received: '{1}'", variation.BoolRetVal, variation.JwtSecurityTokenHandler.CanWriteToken ) );
                    }
                    else if ( variation.Name.StartsWith( "CreateToken_SecurityTokenDescriptor" ) )
                    {
                        SecurityToken retval = variation.JwtSecurityTokenHandler.CreateToken( variation.SecurityTokenDescriptor );
                        if ( variation.JwtSecurityToken != null )
                        {
                            Assert.IsFalse( IdentityComparer.AreEqual( retval as JwtSecurityToken, variation.JwtSecurityToken ), string.Format( "variation.JwtSecurityTokenHandler.CreateToken: expected: '{0}', received: '{1}'", variation.JwtSecurityToken, retval ) );
                        }
                    }
                    else if ( variation.Name.StartsWith( "LoadCustomConfiguration" ) )
                    {
                        variation.JwtSecurityTokenHandler.LoadCustomConfiguration( variation.XmlNodeList );
                    }
                    else if ( variation.Name.StartsWith( "ReadToken_Reader" ) )
                    {
                        variation.JwtSecurityTokenHandler.ReadToken( variation.XmlReader );
                    }
                    else if ( variation.Name.StartsWith( "ReadToken_String" ) )
                    {
                        variation.JwtSecurityTokenHandler.ReadToken( variation.EncodedString );
                    }
                    else if ( variation.Name.StartsWith( "ValidateToken_SecurityToken" ) )
                    {
                        variation.JwtSecurityTokenHandler.ValidateToken( variation.SecurityToken );
                    }
                    else if ( variation.Name.StartsWith( "ValidateToken_String_Only" ) )
                    {
                        variation.JwtSecurityTokenHandler.ValidateToken( variation.EncodedString );
                    }
                    else if ( variation.Name.StartsWith( "ValidateToken_String_TVP" ) )
                    {
                        variation.JwtSecurityTokenHandler.ValidateToken( variation.EncodedString, variation.TokenValidationParameters );
                    }
                    else if ( variation.Name.StartsWith( "ValidateToken_Jwt_Only" ) )
                    {
                        variation.JwtSecurityTokenHandler.ValidateToken( variation.JwtSecurityToken );
                    }
                    else if ( variation.Name.StartsWith( "ValidateToken_Jwt_TVP" ) )
                    {
                        variation.JwtSecurityTokenHandler.ValidateToken( variation.JwtSecurityToken, variation.TokenValidationParameters );
                    }
                    else if ( variation.Name.StartsWith( "WriteToken_XmlWriter" ) )
                    {
                        variation.JwtSecurityTokenHandler.WriteToken(variation.XmlWriter, variation.SecurityToken );
                    }
                    else if ( variation.Name.StartsWith( "WriteToken_Token" ) )
                    {
                        variation.JwtSecurityTokenHandler.WriteToken( variation.SecurityToken );
                    }                        
                    else
                    {
                        Assert.Fail( "unknown variation: " + variation.Name );
                    }

                    if ( ExpectedException.ProcessNoException( variation.ExpectedException ) )
                    {
                        Assert.Fail( string.Format("Test variation {0} was expected to generate an exception and did not.", variation.Name));
                    }
                }
                catch( Exception ex )
                {
                    if ( ExpectedException.ProcessException( variation.ExpectedException, ex ) )
                    {
                        Assert.Fail( string.Format("Test variation {0} was not expected to generate an exception.  Caught exception:\n{1}", variation.Name, ex.ToString()));
                    }
                }
            }
        }

        private List<JwtSecurityTokenTestVariation> PublicMethodVariations()
        {
            List<JwtSecurityTokenTestVariation> variations = new List<JwtSecurityTokenTestVariation>()
            {
                new JwtSecurityTokenTestVariation
                {
                    Name = "CanReadToken_XmlReader_WithoutNS",
                    XmlReader = XmlReaderVariation.WithoutNS,
                    BoolRetVal = false,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "CanReadToken_XmlReader_ArgNull",
                    XmlReader = null,
                    ExpectedException = ExpectedException.ArgNull
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "CanReadToken_XmlReader_JwtTokenTypeShortName",
                    XmlReader = XmlReaderVariation.JwtTokenType,
                    BoolRetVal = true,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "CanReadToken_XmlReader_JwtTokenTypeAltName",
                    XmlReader = XmlReaderVariation.JwtTokenTypeAlt,
                    BoolRetVal = true,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "CanReadToken_XmlReader_WithoutEncoding",
                    XmlReader = XmlReaderVariation.WithoutEncodingType,
                    BoolRetVal = true,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "CanReadToken_XmlReader_WithWrongEncoding",
                    XmlReader = XmlReaderVariation.WithWrongEncodingType,
                    BoolRetVal = false,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "CanReadToken_XmlReader_WithWrongTokenType",
                    XmlReader = XmlReaderVariation.WithWrongTokenType,
                    BoolRetVal = false,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "CanReadToken_String_ArgNull",
                    EncodedString = null,
                    ExpectedException = ExpectedException.ArgNull
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "CanReadToken_String_IllFormed",
                    EncodedString = "bob",
                    BoolRetVal = false,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "CreateToken_SecurityTokenDescriptor_Null",
                    SecurityTokenDescriptor = null,
                    ExpectedException = ExpectedException.ArgNull,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "LoadCustomConfiguration_ArgNull",
                    ExpectedException = ExpectedException.ArgNull
                },
#region ReadTokenVariations
                new JwtSecurityTokenTestVariation
                {
                    Name = "ReadToken_Reader_Null",
                    XmlReader = null,
                    ExpectedException = ExpectedException.ArgNull,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ReadToken_Reader_XmlNotWellExpected",
                    XmlReader = XmlReaderVariation.WithWrongEncodingType,
                    ExpectedException = ExpectedException.ArgEx( id: "Jwt10203"),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ReadToken_String_Null",
                    EncodedString = null,
                    ExpectedException = ExpectedException.ArgNull,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ReadToken_String_TooLarge",
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler() { MaxTokenSizeInBytes = 100 },
                    EncodedString = EncodedJwts.Asymmetric_LocalSts,
                    ExpectedException = ExpectedException.ArgEx(id:"Jwt10206"),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ReadToken_String_IllFormed",
                    EncodedString = "SignedEncodedJwts.Asymmetric_LocalSts",
                    ExpectedException = ExpectedException.ArgEx(id:"Jwt10204"),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ReadToken_String_Valid",
                    EncodedString = EncodedJwts.Asymmetric_LocalSts,
                    ExpectedException = ExpectedException.Null,
                },
#endregion

#region ValidateToken
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_String_Only_Null",
                    EncodedString = null,
                    ExpectedException = ExpectedException.ArgNull,
                    TokenValidationParameters = new TokenValidationParameters(),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_String_Only_TooLarge",
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler() { MaxTokenSizeInBytes = 100 },
                    EncodedString = EncodedJwts.Asymmetric_LocalSts,
                    ExpectedException = ExpectedException.ArgEx(id:"Jwt10206"),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_String_Only_IllFormed",
                    EncodedString = "ValidateToken_String_Only_IllFormed",
                    ExpectedException = ExpectedException.ArgEx(id:"Jwt10204"),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_String_TVP_WhitespaceString",
                    EncodedString = "    ",
                    ExpectedException = ExpectedException.ArgEx("Jwt10204"),
                    TokenValidationParameters = new TokenValidationParameters(),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_String_TVP_String_IllFormed",
                    EncodedString = "SignedEncodedJwts.Asymmetric_LocalSts",
                    TokenValidationParameters = new TokenValidationParameters(),
                    ExpectedException = ExpectedException.ArgEx("Jwt10204"),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_String_TVP_NullTVP",
                    EncodedString = EncodedJwts.Asymmetric_LocalSts,
                    TokenValidationParameters = null,
                    ExpectedException = ExpectedException.ArgNull,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_String_TVP_EncodingTooLarge",
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler() { MaxTokenSizeInBytes = 100, Configuration = new SecurityTokenHandlerConfiguration() },
                    EncodedString = EncodedJwts.Asymmetric_LocalSts,
                    ExpectedException = ExpectedException.ArgEx(id:"Jwt10206"),
                    TokenValidationParameters = new TokenValidationParameters(),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_String_TVP_Encoding_NULL",
                    EncodedString = null,
                    ExpectedException = ExpectedException.ArgNull,
                    TokenValidationParameters = new TokenValidationParameters(),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_String_TVP_TVP_NULL",
                    EncodedString = EncodedJwts.Asymmetric_LocalSts,
                    ExpectedException = ExpectedException.ArgNull,
                    TokenValidationParameters = null,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_Jwt_Only_Null",
                    JwtSecurityToken = null,
                    ExpectedException = ExpectedException.ArgNull,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_Jwt_TVP_Jwt_NULL",
                    EncodedString = EncodedJwts.Asymmetric_LocalSts,
                    ExpectedException = ExpectedException.ArgNull,
                    TokenValidationParameters = null,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_Jwt_TVP_Null_TVP",
                    JwtSecurityToken = new JwtSecurityToken( EncodedJwts.Asymmetric_2048 ),
                    TokenValidationParameters = null,
                    ExpectedException = ExpectedException.ArgNull,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_SecurityToken_Null",
                    SecurityToken = null,
                    ExpectedException = ExpectedException.ArgNull,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_SecurityToken_NotJWT",                    
                    SecurityToken = new UserNameSecurityToken( "foo", "bar" ),
                    ExpectedException = ExpectedException.ArgEx(id:"Jwt10308"),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "ValidateToken_SecurityToken_Config_Null",
                    SecurityToken = new JwtSecurityToken( EncodedJwts.Asymmetric_LocalSts ),
                    ExpectedException = ExpectedException.SecVal(id:"Jwt10315"),
                },
#endregion

#region WriteToken
                new JwtSecurityTokenTestVariation
                {
                    Name = "WriteToken_XmlWriter_WriterNull",
                    XmlWriter = null,
                    SecurityToken = new JwtSecurityToken( EncodedJwts.Asymmetric_2048 ), 
                    ExpectedException = ExpectedException.ArgNull,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "WriteToken_XmlWriter_Token_Null",
                    XmlWriter = XmlDictionaryWriter.CreateTextWriter( new MemoryStream() ),
                    SecurityToken = null,
                    ExpectedException = ExpectedException.ArgNull,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "WriteToken_XmlWriter_Token_NotJwt",
                    XmlWriter = XmlDictionaryWriter.CreateTextWriter( new MemoryStream() ),
                    SecurityToken = new UserNameSecurityToken( "Foo", "Bar"),
                    ExpectedException = ExpectedException.ArgEx(id:"Jwt10200" ),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "WriteToken_Token_TokenNull",
                    SecurityToken = null,
                    ExpectedException = ExpectedException.ArgNull,
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "WriteToken_Token_TokenNotJwt",
                    XmlWriter = XmlDictionaryWriter.CreateTextWriter( new MemoryStream() ),
                    SecurityToken = new UserNameSecurityToken("Foo", "Bar"),
                    ExpectedException = ExpectedException.ArgEx(id:"Jwt10200"),
                },
#endregion
            };

            return variations;
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "18BBAFC8-52F8-4A51-8182-8EB192BF5FA5" )]
        [Description( "JWTSecurityTokenHandler - Tampering tests" )]
        public void JwtSecurityTokenHandler_TamperingTests()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            // CreateToken using config
            JwtSecurityToken jwt = handler.CreateToken( issuer: "http://GotJwt.com", signingCredentials: KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2 ) as JwtSecurityToken;
            List<SecurityToken> tokens = new List<SecurityToken>() { KeyingMaterial.X509Token_2048 };
            handler.Configuration = new SecurityTokenHandlerConfiguration()
            {
                IssuerTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver( tokens.AsReadOnly(), true ),
                SaveBootstrapContext = true,
                CertificateValidator = AlwaysSucceedCertificateValidator.New,
                AudienceRestriction = new AudienceRestriction( AudienceUriMode.Never ),
                IssuerNameRegistry = new SetNameIssuerNameRegistry( "http://GotJwt.com" ),
            };
            ClaimsPrincipal principal = handler.ValidateToken( jwt );
            jwt.Payload.AddClaim( new Claim( "foo", "bar" ) );
            ExpectedException ee = ExpectedException.SecVal( id: "Jwt10315" );
            try
            {
                handler.ValidateToken( jwt );
                ExpectedException.ProcessNoException( ee );
            }
            catch( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }

            // add claim to payload directly
            jwt = handler.CreateToken( issuer: "http://GotJwt.com", signingCredentials: KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2 ) as JwtSecurityToken;
            jwt.Payload.Add( "key", "value" );
            try
            {
                handler.ValidateToken( jwt );
                ExpectedException.ProcessNoException( ee );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }

            // add claim to header directly
            jwt = handler.CreateToken( issuer: "http://GotJwt.com", signingCredentials: KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2 ) as JwtSecurityToken;
            jwt.Header.Add( "key", "value" );
            try
            {
                handler.ValidateToken( jwt );
                ExpectedException.ProcessNoException( ee );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }

            // validate through TVP
            jwt = handler.CreateToken( issuer: "http://GotJwt.com", signingCredentials: KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2 ) as JwtSecurityToken;
            TokenValidationParameters tvp = new TokenValidationParameters()
            {
                AudienceUriMode = Selectors.AudienceUriMode.Never,
                ValidateIssuer = false,
                SigningToken = KeyingMaterial.AsymmetricX509Token_2048,
            };

            ClaimsPrincipal principalValidated = handler.ValidateToken( jwt, tvp );

            jwt.Payload.Add( "key", "value" );
            try
            {
                handler.ValidateToken( jwt, tvp );
                ExpectedException.ProcessNoException( ee );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "B6C1D4D1-3CF9-4281-B024-39FCBD03160E" )]
        [Description( "JWTSecurityTokenHandler - BootstrapContext tests" )]
        public void JwtSecurityTokenHandler_BootstrapTokenTests()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            // save bootstrap
            //JwtSecurityToken actor = handler.CreateToken( issuer: "http://GotJwt.com",  signingCredentials: KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2 ) as JwtSecurityToken;

            //ClaimsIdentity actorIdentity = new ClaimsIdentity( ClaimSets.Simple( Issuers.GotJwt, Issuers.GotJwtOriginal ) );
            JwtSecurityToken jwt = handler.CreateToken( issuer: "http://GotJwt.com", signingCredentials: KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2 ) as JwtSecurityToken;

            List<SecurityToken> tokens = new List<SecurityToken>(){ KeyingMaterial.X509Token_2048 };
            handler.Configuration = new SecurityTokenHandlerConfiguration() 
                                        {
                                            IssuerTokenResolver =  SecurityTokenResolver.CreateDefaultSecurityTokenResolver( tokens.AsReadOnly(), true ), 
                                            SaveBootstrapContext = true,
                                            CertificateValidator = AlwaysSucceedCertificateValidator.New,
                                            AudienceRestriction = new AudienceRestriction( AudienceUriMode.Never ),
                                            IssuerNameRegistry = new SetNameIssuerNameRegistry( "http://GotJwt.com" ),
                                        };
            ClaimsPrincipal principal = handler.ValidateToken( jwt );
            ClaimsIdentity identity = principal.Identity as ClaimsIdentity;
            CheckBootstrapContext( identity, true, jwt.RawData );

            principal = handler.ValidateToken( jwt.RawData );

            Console.WriteLine( "SaveBootstrapContext = false, jwt, tvp (default)" );
            CheckBootstrapContext( principal.Identity as ClaimsIdentity, true, jwt.RawData );
            TokenValidationParameters tvp = new TokenValidationParameters
                                                {
                                                    AudienceUriMode = AudienceUriMode.Never,
                                                    SigningToken = KeyingMaterial.X509Token_2048,
                                                    ValidIssuer = "http://GotJwt.com",
                                                };

            principal = handler.ValidateToken( jwt, tvp );
            CheckBootstrapContext( principal.Identity as ClaimsIdentity, false, jwt.RawData );

            Console.WriteLine( "SaveBootstrapContext = true, jwt, tvp" );
            tvp = new TokenValidationParameters
            {
                AudienceUriMode = AudienceUriMode.Never,
                SigningToken = KeyingMaterial.X509Token_2048,
                ValidIssuer = "http://GotJwt.com",
                SaveBootstrapContext = true,
            };

            principal = handler.ValidateToken( jwt, tvp );
            CheckBootstrapContext( principal.Identity as ClaimsIdentity, true, jwt.RawData );

            Console.WriteLine( "SaveBootstrapContext = false, jwt" );
            // don't save bootstrap
            handler.Configuration = new SecurityTokenHandlerConfiguration()
            {
                IssuerTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver( tokens.AsReadOnly(), true ),
                SaveBootstrapContext = false,
                CertificateValidator = AlwaysSucceedCertificateValidator.New,
                AudienceRestriction = new AudienceRestriction( AudienceUriMode.Never ),
                IssuerNameRegistry = new SetNameIssuerNameRegistry( "http://GotJwt.com" ),
            };
            principal = handler.ValidateToken( jwt );
            CheckBootstrapContext( principal.Identity as ClaimsIdentity, false, jwt.RawData );


            Console.WriteLine( "SaveBootstrapContext = false, jwt, tvp" );
            tvp = new TokenValidationParameters
            {
                AudienceUriMode = AudienceUriMode.Never,
                SigningToken = KeyingMaterial.X509Token_2048,
                ValidIssuer = "http://GotJwt.com",
                SaveBootstrapContext = false,
            };

            principal = handler.ValidateToken( jwt, tvp );
            CheckBootstrapContext( principal.Identity as ClaimsIdentity, false, jwt.RawData );
        }

        private void CheckBootstrapContext( ClaimsIdentity identity, bool expectBC, string rawData )
        {
            // should have bootstrapContext with token as string
            if ( identity.BootstrapContext == null )
            {
                Assert.IsFalse( expectBC , "identity.BootstrapContext == null, was expected to be non null" );
            }
            else
            {
                Assert.IsFalse( !expectBC , "identity.BootstrapContext != null, but wasn't expected" );
                string jwtEncoding = ( identity.BootstrapContext as BootstrapContext ).Token;
                Assert.IsFalse( jwtEncoding == null , "( identity.BootstrapContext.Token ) == null" );

                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                Assert.IsFalse( !handler.CanReadToken( jwtEncoding ) , " !handler.CanReadToken( jwtEncoding )" );
                JwtSecurityToken jwt = new JwtSecurityToken( jwtEncoding );
            }
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "D540296C-BEFD-4D37-BC94-6E3FD9DBBC31" )]
        [Description( "JWTSecurityTokenHandler - ReadToken" )]
        public void JwtSecurityTokenHandler_ReadTokenTests()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            ExpectedException expectedException = ExpectedException.ArgRange();
            try
            {
                handler.MaxTokenSizeInBytes = 0;
                ExpectedException.ProcessNoException( expectedException );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( expectedException, ex );
            }

            Assert.IsFalse( handler.CanReadToken( "1" ) , string.Format( "Expected JWTSecurityTokenHandler.CanReadToken to be false" ) );

            expectedException = ExpectedException.ArgEx( id: "Jwt10204" );
            try
            {
                handler.ReadToken( "1" );
                ExpectedException.ProcessNoException( expectedException );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( expectedException, ex );
            }
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "00E34491-C6F0-40FA-AA66-090729F46927" )]
        [Description( "Test Signature Validation" )]
        public void JwtSecurityTokenHandler_SignatureValidation_Config()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            NamedKeySecurityKeyIdentifierClause clause = new NamedKeySecurityKeyIdentifierClause( "kid", KeyingMaterial.SymmetricKeyEncoded_256 );
            SecurityKeyIdentifier ski = new SecurityKeyIdentifier( new NamedKeySecurityKeyIdentifierClause[] { clause } );
            SigningCredentials sc = new SigningCredentials( KeyingMaterial.SymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest, ski );
            JwtSecurityToken jwt = handler.CreateToken( issuer: "http://www.GotJwt.com",
                                                        audience: "http://audience",
                                                        lifetime: new Lifetime( DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours( 2 ) ),
                                                        subject: new ClaimsIdentity( ClaimSets.Simple( "http://idp", "http://origIdp" ) ),
                                                        signingCredentials: sc );

            AudienceRestriction audr = new AudienceRestriction( AudienceUriMode.BearerKeyOnly );
            audr.AllowedAudienceUris.Add( new Uri( "http://audience" ) );
            IssuerTokenResolver itr = IssuerTokenResolver.CreateDefaultSecurityTokenResolver( ( new List<SecurityToken>() { KeyingMaterial.AsymmetricX509Token_2048 } ).AsReadOnly(), true ) as IssuerTokenResolver;
            SetNameIssuerNameRegistry ninr = new SetNameIssuerNameRegistry( Issuers.GotJwt );
            NamedKeyIssuerTokenResolver nkitr = new NamedKeyIssuerTokenResolver();
            nkitr.SecurityKeys.Add( "kid", new List<SecurityKey>() { KeyingMaterial.SymmetricSecurityKey_256 } );

            handler.Configuration = new SecurityTokenHandlerConfiguration()
            {
                AudienceRestriction = audr,
                IssuerNameRegistry = ninr,
                IssuerTokenResolver = nkitr,
                CertificateValidator = AlwaysSucceedCertificateValidator.New,
            };

            Console.WriteLine( "Test variation: Using 'kid'" );
            ExpectedException ee = ExpectedException.Null;
            try
            {
                ClaimsPrincipal cp = handler.ValidateToken( jwt );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }

            Console.WriteLine( "Test variation: Using 'iss', is added as default, but not resolved" );
            nkitr.SecurityKeys.Clear();
            ee = ExpectedException.SecVal( id: "Jwt10315" );
            try
            {
                ClaimsPrincipal cp = handler.ValidateToken( jwt );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }

            Console.WriteLine( "Test variation: Using 'iss', is added as default, will not be resolved" );
            nkitr.SecurityKeys.Add( "", new List<SecurityKey>() { KeyingMaterial.SymmetricSecurityKey_256 } );
            ee = ExpectedException.SecVal( id: "Jwt10315" );
            try
            {
                ClaimsPrincipal cp = handler.ValidateToken( jwt );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }

        }

        [TestMethod]
        [TestProperty( "TestCaseID", "00E34491-C6F0-40FA-AA66-090729F46927" )]
        [Description( "Test Signature Validation using Token Validation Parameters" )]
        public void JwtSecurityTokenHandler_SignatureValidation_TVP()
        {
            Console.WriteLine( "Method: JWT SignatureValidation TVP" );
            foreach ( JwtSecurityTokenTestVariation variation in SignatureValidationTVPVariations() )
            {

                Console.WriteLine( string.Format( "Variation: '{0}'", variation.Name ) );
                try
                {
                    variation.JwtSecurityTokenHandler.CertificateValidator = X509CertificateValidator.None;
                    variation.JwtSecurityTokenHandler.ValidateToken( variation.EncodedString, variation.TokenValidationParameters );
                    ExpectedException.ProcessNoException( variation.ExpectedException );
                }
                catch ( Exception ex )
                {
                    ExpectedException.ProcessException( variation.ExpectedException, ex );
                }
            }

            Console.WriteLine( "\n***========================================\nAdditional tests required\n***========================================" );
        }

        private List<JwtSecurityTokenTestVariation> SignatureValidationTVPVariations()
        {
            List<JwtSecurityTokenTestVariation> constructionParams = new List<JwtSecurityTokenTestVariation>() 
            {
                new JwtSecurityTokenTestVariation
                { 
                    TokenValidationParameters = JwtTestUtilities.SignatureValidationParameters( KeyingMaterial.X509Token_LocalSts ),
                    Name = "Asymmetric_LocalSts",
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler(){ RequireExpirationTime = false },
                    ExpectedException = ExpectedException.Null,
                    EncodedString = JwtTestUtilities.GetJwtParts( EncodedJwts.Asymmetric_LocalSts, "ALLParts" ),
                },
                new JwtSecurityTokenTestVariation
                { 
                    TokenValidationParameters = JwtTestUtilities.SignatureValidationParameters( KeyingMaterial.X509Token_1024 ),
                    Name = "Asymmetric_1024",
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler(){ RequireExpirationTime = false },
                    ExpectedException = ExpectedException.Null,
                    EncodedString = JwtTestUtilities.GetJwtParts( EncodedJwts.Asymmetric_1024, "ALLParts" ),
                },
                new JwtSecurityTokenTestVariation
                { 
                    TokenValidationParameters = JwtTestUtilities.SignatureValidationParameters( KeyingMaterial.X509Token_2048 ),
                    Name = "Asymmetric_2048",
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler(){ RequireExpirationTime = false },
                    ExpectedException = ExpectedException.Null,
                    EncodedString = JwtTestUtilities.GetJwtParts( EncodedJwts.Asymmetric_2048, "ALLParts" ),
                },
                new JwtSecurityTokenTestVariation
                { 
                    TokenValidationParameters = JwtTestUtilities.SignatureValidationParameters( KeyingMaterial.BinarySecretToken_256 ),
                    Name = "Symmetric_256",
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler(){ RequireExpirationTime = false },
                    ExpectedException = ExpectedException.Null,
                    EncodedString = JwtTestUtilities.GetJwtParts( EncodedJwts.Symmetric_256, "ALLParts" ),
                },                
                new JwtSecurityTokenTestVariation
                { 
                    TokenValidationParameters = JwtTestUtilities.SignatureValidationParameters( KeyingMaterial.X509Token_2048 ),
                    Name = "Signature missing, just two parts",
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler(){ RequireExpirationTime = false },
                    ExpectedException = ExpectedException.SecVal( "Jwt10312" ),
                    EncodedString = JwtTestUtilities.GetJwtParts( EncodedJwts.Asymmetric_2048, "Parts-0-1"),
                },
                new JwtSecurityTokenTestVariation
                { 
                    TokenValidationParameters = JwtTestUtilities.SignatureValidationParameters(),
                    Name = "SigningToken and SigningTokens both null",
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler(){ RequireExpirationTime = false },
                    ExpectedException = ExpectedException.SecVal( id:"Jwt10315" ),
                    EncodedString = JwtTestUtilities.GetJwtParts( EncodedJwts.Asymmetric_2048, "ALLParts"),
                },
                new JwtSecurityTokenTestVariation
                { 
                    TokenValidationParameters = JwtTestUtilities.SignatureValidationParameters( signingTokens: new List<SecurityToken> { KeyingMaterial.X509Token_2048 } ),
                    Name = "SigningToken null, SigningTokens valid",
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler(){ RequireExpirationTime = false },
                    ExpectedException = ExpectedException.Null,
                    EncodedString = JwtTestUtilities.GetJwtParts( EncodedJwts.Asymmetric_2048, "ALLParts"),
                },
                new JwtSecurityTokenTestVariation
                { 
                    TokenValidationParameters = JwtTestUtilities.SignatureValidationParameters( signingToken: new UserNameSecurityToken( "username", "password" ) ),
                    Name = "SigningToken no keys",
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler(){ RequireExpirationTime = false },
                    ExpectedException = ExpectedException.SecVal( id:"Jwt10315" ),
                    EncodedString = JwtTestUtilities.GetJwtParts( EncodedJwts.Asymmetric_2048, "ALLParts"),
                },
                new JwtSecurityTokenTestVariation
                { 
                    TokenValidationParameters = JwtTestUtilities.SignatureValidationParameters( signingToken: KeyingMaterial.RsaToken_2048 ),
                    Name = "RSA signingtoken.",
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler(){ RequireExpirationTime = false },
                    ExpectedException = ExpectedException.Null,
                    EncodedString = JwtTestUtilities.GetJwtParts( EncodedJwts.Asymmetric_2048, "ALLParts"),
                },
                new JwtSecurityTokenTestVariation
                { 
                    TokenValidationParameters = JwtTestUtilities.SignatureValidationParameters( signingToken: new NamedKeySecurityToken( "keys", new List<SecurityKey>(){ KeyingMaterial.RsaToken_2048.SecurityKeys[0], KeyingMaterial.SymmetricSecurityKey_256} ) ),
                    Name = "NamedKey SecurityToken",
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler(){ RequireExpirationTime = false },
                    ExpectedException = ExpectedException.Null,
                    EncodedString = JwtTestUtilities.GetJwtParts( EncodedJwts.Asymmetric_2048, "ALLParts"),
                },
                new JwtSecurityTokenTestVariation
                { 
                    TokenValidationParameters = JwtTestUtilities.SignatureValidationParameters( signingToken: KeyingMaterial.BinarayToken56BitKey ),
                    Name = "BinaryKey 56Bits",
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler(){ RequireExpirationTime = false },
                    ExpectedException = ExpectedException.SecVal("Jwt10316"),
                    EncodedString = JwtTestUtilities.GetJwtParts( EncodedJwts.Asymmetric_2048, "ALLParts"),
                },
            };

            return constructionParams;
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "35870865-9DA5-45A8-9D6D-B7CAF03A50D3" )]
        [Description( "Test Issuer Validation using SecurityTokenConfiguration" )]
        public void JwtSecurityTokenHandler_IssuerValidationTests_Config()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwt = handler.CreateToken( issuer:   "http://www.GotJwt.com",
                                                        audience: "http://audience",
                                                        lifetime:  new Lifetime( DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours( 2 ) ),
                                                        subject:   new ClaimsIdentity( ClaimSets.Simple( "http://idp", "http://origIdp" ) ),
                                                        signingCredentials: KeyingMaterial.AsymmetricSigningCreds_2048_RsaSha2_Sha2 );
            
            ConfigurationBasedIssuerNameRegistry cbinr = new ConfigurationBasedIssuerNameRegistry();
            cbinr.AddTrustedIssuer( KeyingMaterial.AsymmetricCert_2048.Thumbprint, "http://www.GotJwt.com" );
            AudienceRestriction audr = new AudienceRestriction( AudienceUriMode.BearerKeyOnly );
            audr.AllowedAudienceUris.Add( new Uri("http://audience" ) );
            SecurityTokenResolver itr = SecurityTokenResolver.CreateDefaultSecurityTokenResolver( ( new List<SecurityToken>() { KeyingMaterial.AsymmetricX509Token_2048 } ).AsReadOnly(), true );
            handler.Configuration = new SecurityTokenHandlerConfiguration()
                                        {
                                            AudienceRestriction = audr,                                          
                                            IssuerNameRegistry  = cbinr,
                                            IssuerTokenResolver = itr,
                                            CertificateValidator = AlwaysSucceedCertificateValidator.New,
                                        };

            Console.WriteLine( "Test variation: Issuer should validate using ConfigurationBasedIssuerNameRegistry" );
            ExpectedException ee = ExpectedException.Null;
            try
            {
                ClaimsPrincipal cp = handler.ValidateToken( jwt );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }

            Console.WriteLine( "Test variation: Issuer should Fail to validate using ConfigurationBasedIssuerNameRegistry" );
            cbinr.ConfiguredTrustedIssuers.Clear();
            ee = ExpectedException.SecVal( id: "Jwt10318" );
            try
            {
                ClaimsPrincipal cp = handler.ValidateToken( jwt );
                ExpectedException.ProcessNoException( ee );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }

            Console.WriteLine( "Test variation: jwt.Signing token null" );
            cbinr.AddTrustedIssuer( KeyingMaterial.AsymmetricCert_2048.Thumbprint, "http://www.GotJwt.com" );
            handler.RequireSignedTokens = false;
            ee = ExpectedException.ArgNull;
            try
            {
                ClaimsPrincipal cp = handler.ValidateToken( string.Concat( jwt.EncodedHeader + "." + jwt.EncodedPayload + "." ) );
                ExpectedException.ProcessNoException( ee );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }
        }
        [TestMethod]
        [TestProperty( "TestCaseID", "6356C21F-280C-4A9E-875C-F6543DF0A5E3" )]
        [Description( "Test Issuer Validation with TVP" )]
        public void JwtSecurityTokenHandler_IssuerValidationTests_TVP()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            handler.CertificateValidator = X509CertificateValidator.None;
            JwtSecurityToken jwt = handler.CreateToken(issuer: "http://www.GotJwt.com",
                                                       audience: "http://audience",
                                                       lifetime: new Lifetime(DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours(2)),
                                                       subject: new ClaimsIdentity(ClaimSets.Simple("http://idp", "http://origIdp")),
                                                       signingCredentials: KeyingMaterial.AsymmetricSigningCreds_2048_RsaSha2_Sha2);

            TokenValidationParameters jwtParams = new TokenValidationParameters
            {
                AudienceUriMode = AudienceUriMode.Never,
                SigningToken = KeyingMaterial.X509Token_2048,
                AllowedAudience = "urn:InteractiveAuthentication",
                ValidIssuer = "http://Simple.CertData_2048",
            };

            // validIssuer null, validIssuers null
            jwtParams.ValidIssuer = null;
            jwtParams.ValidIssuers = null;
            ExpectedException ee = ExpectedException.ArgEx(id:"Jwt10317");
            try
            {
                handler.ValidateToken( jwt.RawData, jwtParams );
                ExpectedException.ProcessNoException( ee );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }

            // no issuers should fail.
            ee = ExpectedException.SecVal(id:"Jwt10311");
            try
            {
                List<string> issuers = new List<string>();
                jwtParams.ValidIssuers = issuers;
                jwtParams.ValidIssuer = string.Empty;
                handler.ValidateToken( jwt.RawData, jwtParams );
                ExpectedException.ProcessNoException( ee );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }

            // no issuers should NOT fail. vaidate issuer is not needed.
            ee = ExpectedException.Null;
            try
            {
                List<string> issuers = new List<string>();
                jwtParams.ValidateIssuer = false;
                jwtParams.ValidIssuers = issuers;
                jwtParams.ValidIssuer = string.Empty;
                handler.ValidateToken( jwt.RawData, jwtParams );
                ExpectedException.ProcessNoException( ee );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }

            // no issuers should NOT fail. vaidate issuer is not needed.
            ee = ExpectedException.Null;
            try
            {
                List<string> issuers = new List<string>(){"http://Simple.CertData_2049"};
                jwtParams.ValidateIssuer = false;
                jwtParams.ValidIssuers = issuers;
                jwtParams.ValidIssuer = "http://Simple.CertData_2049";
                handler.ValidateToken( jwt.RawData, jwtParams );
                ExpectedException.ProcessNoException( ee );
            }
            catch ( Exception ex )
            {
                ExpectedException.ProcessException( ee, ex );
            }


            // issuer matches
            jwtParams.ValidIssuer = "http://www.GotJwt.com";
            handler.ValidateToken( jwt.RawData, jwtParams );

            // issuer matches
            jwtParams.ValidIssuers = new string[] { "http://Simple.CertData_2048", "http://www.GotJwt.com" };
            jwtParams.ValidIssuer = null;
            handler.ValidateToken( jwt.RawData, jwtParams );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "6356C21F-280C-4A9E-875C-F6543DF0A5E3" )]
        [Description( "Test Audience Validation" )]
        public void JwtSecurityTokenHandler_AudienceValidationTests()
        {
            foreach ( JwtSecurityTokenTestVariation variation in AudienceValidationVariations() )
            {
                try
                {
                    Console.WriteLine( "Testvariation: " + variation.Name );
                    variation.JwtSecurityTokenHandler.ValidateToken( variation.JwtSecurityToken, variation.TokenValidationParameters );
                    ExpectedException.ProcessNoException( variation.ExpectedException );
                }
                catch ( Exception ex )
                {
                    ExpectedException.ProcessException( variation.ExpectedException, ex );
                }
            }
        }

        private static List<JwtSecurityTokenTestVariation> AudienceValidationVariations( )
        {
            List<JwtSecurityTokenTestVariation> testVariations = new List<JwtSecurityTokenTestVariation>
            {
                new JwtSecurityTokenTestVariation
                { 
                   Name = "Jwt.Audience == null",                   
                   ExpectedException = ExpectedException.Aud( id: "Jwt10300" ),
                   JwtSecurityTokenHandler = new JwtSecurityTokenHandler() { RequireExpirationTime = false, RequireSignedTokens = false },
                   JwtSecurityToken = new JwtSecurityToken(issuer: "http://GotJwt.com", audience: null ),
                   TokenValidationParameters = new TokenValidationParameters(){ AudienceUriMode = AudienceUriMode.BearerKeyOnly }, 
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "jwt.Audience == EmptyString",
                    ExpectedException = ExpectedException.Aud( id: "Jwt10300" ),
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler() { RequireExpirationTime = false, RequireSignedTokens = false },
                    JwtSecurityToken = new JwtSecurityToken( issuer: "http://GotJwt.com" , audience: string.Empty),
                    TokenValidationParameters = new TokenValidationParameters() { AudienceUriMode = AudienceUriMode.BearerKeyOnly },
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "jwt.Audience == whitespace",
                    ExpectedException = ExpectedException.Aud( id: "Jwt10300" ),
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler() { RequireExpirationTime = false, RequireSignedTokens = false },
                    JwtSecurityToken = new JwtSecurityToken( "http://GotJwt.com", audience: "    " ),
                    TokenValidationParameters = new TokenValidationParameters() { AudienceUriMode = AudienceUriMode.BearerKeyOnly },
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "jwtParams.AllowedAudience jwtParams.AllowedAudiences both null",
                    ExpectedException = ExpectedException.ArgEx( id: "Jwt10301" ),
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler() { RequireExpirationTime = false, RequireSignedTokens = false },
                    JwtSecurityToken = new JwtSecurityToken( "http://GotJwt.com", audience: "http://GotJwt.com" ),
                    TokenValidationParameters = new TokenValidationParameters() { AudienceUriMode = AudienceUriMode.BearerKeyOnly },
                },
                new JwtSecurityTokenTestVariation()
                {
                    Name = "jwtParams.AllowedAudience empty jwtParams.AllowedAudiences empty",
                    ExpectedException = ExpectedException.Aud( id: "Jwt10303" ),
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler() { RequireExpirationTime = false, RequireSignedTokens = false },
                    JwtSecurityToken = new JwtSecurityToken( "http://GotJwt.com", audience: "http://GotJwt.com" ),
                    TokenValidationParameters = new TokenValidationParameters() { AudienceUriMode = AudienceUriMode.BearerKeyOnly, AllowedAudience = string.Empty, AllowedAudiences = new List<string>() },
                },
                new JwtSecurityTokenTestVariation()
                {
                    Name = "jwtParams.AllowedAudience whitespace jwtParams.AllowedAudiences empty",
                    ExpectedException = ExpectedException.Aud( id: "Jwt10303" ),
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler() { RequireExpirationTime = false, RequireSignedTokens = false },
                    JwtSecurityToken = new JwtSecurityToken( "http://GotJwt.com", audience: "http://GotJwt.com" ),
                    TokenValidationParameters = new TokenValidationParameters() { AudienceUriMode = AudienceUriMode.BearerKeyOnly, AllowedAudience = "   ", AllowedAudiences = new List<string>() },
                },
                new JwtSecurityTokenTestVariation()
                {
                    Name = "jwtParams.AllowedAudience empty jwtParams.AllowedAudiences one null string",
                    ExpectedException = ExpectedException.Aud( id: "Jwt10303" ),
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler() { RequireExpirationTime = false, RequireSignedTokens = false },
                    JwtSecurityToken = new JwtSecurityToken( "http://GotJwt.com", audience: "http://GotJwt.com" ),
                    TokenValidationParameters = new TokenValidationParameters() { AudienceUriMode = AudienceUriMode.BearerKeyOnly, AllowedAudience = "", AllowedAudiences = new List<string>(){ null } },
                },
                new JwtSecurityTokenTestVariation()
                {
                    Name = "jwtParams.AllowedAudience empty jwtParams.AllowedAudiences one empty string",
                    ExpectedException = ExpectedException.Aud( id: "Jwt10303" ),
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler() { RequireExpirationTime = false, RequireSignedTokens = false },
                    JwtSecurityToken = new JwtSecurityToken( "http://GotJwt.com", audience: "http://GotJwt.com" ),
                    TokenValidationParameters = new TokenValidationParameters() { AudienceUriMode = AudienceUriMode.BearerKeyOnly, AllowedAudience = "", AllowedAudiences = new List<string>(){ string.Empty } },
                },
                new JwtSecurityTokenTestVariation()
                {
                    Name = "jwtParams.AllowedAudience empty jwtParams.AllowedAudiences one string whitespace",
                    ExpectedException = ExpectedException.Aud( id: "Jwt10303" ),
                    JwtSecurityTokenHandler = new JwtSecurityTokenHandler() { RequireExpirationTime = false, RequireSignedTokens = false },
                    JwtSecurityToken = new JwtSecurityToken( "http://GotJwt.com", audience: "http://GotJwt.com" ),
                    TokenValidationParameters = new TokenValidationParameters() { AudienceUriMode = AudienceUriMode.BearerKeyOnly, AllowedAudience = "", AllowedAudiences = new List<string>(){ "     " } },
                }
            };

            return testVariations;
        }

        private static void AudienceValidationLoop( IEnumerable<string> audiences, IEnumerable<string> allowedAudiences, bool expectException )
        {
            JwtSecurityToken jwt;
            TokenValidationParameters jwtParams = new TokenValidationParameters();
            JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();

            foreach ( string aud in audiences )
            {
                foreach ( string allowed in audiences )
                {
                    try
                    {
                        jwt = AudienceValidationTestSetUp( jwtParams, aud, AudienceUriMode.BearerKeyOnly, allowed, null );
                        jwtHandler.ValidateToken( jwt, jwtParams );
                        Assert.IsFalse( expectException , string.Format( "Expected to throw: aud: '{0}', allowedUri: '{1}'", aud, allowed ) );
                    }
                    catch ( SecurityTokenValidationException )
                    {
                        Assert.IsFalse( !expectException , string.Format( "Did not Expect to throw: aud: '{0}', allowedUri: '{1}'", aud, allowed ) );
                    }
                }

                try
                {
                    jwt = AudienceValidationTestSetUp( jwtParams, aud, AudienceUriMode.BearerKeyOnly, null, allowedAudiences );
                    jwtHandler.ValidateToken( jwt, jwtParams );
                    Assert.IsFalse( expectException , string.Format( "Expected to throw: aud: '{0}', allowedUri: '{1}'", aud, JwtTestUtilities.SerializeAsSingleCommaDelimitedString( allowedAudiences ) ) );

                }
                catch ( SecurityTokenValidationException )
                {
                    Assert.IsFalse( !expectException , string.Format( "Did not Expect to throw: aud: '{0}', allowedUri: '{1}'", aud, JwtTestUtilities.SerializeAsSingleCommaDelimitedString( allowedAudiences ) ) );
                }
            }
        }

        private static JwtSecurityToken AudienceValidationTestSetUp( TokenValidationParameters jwtParms, string audience, AudienceUriMode mode, string allowedAudience, IEnumerable<string> allowedAudiences )
        {
            jwtParms.AudienceUriMode = mode;
            jwtParms.AllowedAudience = allowedAudience;
            jwtParms.AllowedAudiences = allowedAudiences;
            return new JwtSecurityToken( "urn:jwtTest", audience );
        }

        private static void SignatureValidationTestSetUp( TokenValidationParameters jwtParms, SecurityToken token, IssuerTokenResolver tokenResolver )
        {
            jwtParms.AudienceUriMode = AudienceUriMode.Never;
            jwtParms.SigningToken = token;
            return;
        }
    }
}
