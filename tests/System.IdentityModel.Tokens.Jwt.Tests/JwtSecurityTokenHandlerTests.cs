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
                                            WSSecurityConstantsInternal.Elements.BinarySecurityToken,
                                            WSSecurityConstantsInternal.Namespace,
                                            WSSecurityConstantsInternal.Namespace,
                                            JwtConstants.TokenType,
                                            WSSecurityConstantsInternal.Base64EncodingType,
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
                                            WSSecurityConstantsInternal.Elements.BinarySecurityToken,
                                            WSSecurityConstantsInternal.Namespace,
                                            WSSecurityConstantsInternal.Namespace,
                                            JwtConstants.TokenTypeAlt,
                                            WSSecurityConstantsInternal.Base64EncodingType,
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
                                            WSSecurityConstantsInternal.Elements.BinarySecurityToken,
                                            WSSecurityConstantsInternal.Namespace,
                                            WSSecurityConstantsInternal.Namespace,
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
                                            WSSecurityConstantsInternal.Elements.BinarySecurityToken,
                                            WSSecurityConstantsInternal.Namespace,
                                            WSSecurityConstantsInternal.Namespace,
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
                                            WSSecurityConstantsInternal.Elements.BinarySecurityToken,
                                            WSSecurityConstantsInternal.Namespace,
                                            WSSecurityConstantsInternal.Namespace,
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
                                            WSSecurityConstantsInternal.Elements.BinarySecurityToken,
                                            JwtConstants.TokenType,
                                            WSSecurityConstantsInternal.Base64EncodingType,
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
        public static void ClassSetup(TestContext testContext)
        { }

        [ClassCleanup]
        public static void ClassCleanup()
        { }

        [TestInitialize]
        public void Initialize()
        {
            _testContextProvider = new TestContextProvider(TestContext);
        }

        [TestMethod]
        [TestProperty("TestCaseID", "B237EA9D-0453-4717-8870-E6A49DE04F0E")]
        [Description("Actor Tests.  Ensure that 'actors' work correctly inbound and outbound.  Signed, with and without bootstrap context")]
        public void JwtSecurityTokenHandler_Actor()
        {
            // Set up tests artifacts here.
            JwtSecurityTokenHandler tokendHandler = new JwtSecurityTokenHandler();

            TokenValidationParameters validationParameters = IdentityUtilities.DefaultAsymmetricTokenValidationParameters;
            validationParameters.ValidateActor = false;
            validationParameters.SaveSigninToken = true;

            // Create the Jwts
            string jwtActorAsymmetric = IdentityUtilities.DefaultAsymmetricJwt;
            string jwtActorSymmetric = IdentityUtilities.DefaultSymmetricJwt;

            // actor can be set by adding the claim directly
            ClaimsIdentity claimsIdentity = IdentityUtilities.DefaultClaimsIdentity;
            claimsIdentity.AddClaim(new Claim(ClaimTypes.Actor, jwtActorAsymmetric));
            JwtSecurityToken jwtToken = tokendHandler.CreateToken
                    (issuer: IdentityUtilities.DefaultIssuer,
                     audience: IdentityUtilities.DefaultAudience,
                     subject: claimsIdentity,
                     signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials);

            // actor will be validated using same validationParameters
            validationParameters.ValidateActor = true;
            ClaimsPrincipal claimsPrincipal = RunActorTest(jwtToken.RawData, jwtActorAsymmetric, validationParameters, validationParameters, tokendHandler, ExpectedException.NoExceptionExpected);

            // Validation on actor will fail because the keys are different types
            claimsIdentity = IdentityUtilities.DefaultClaimsIdentity;
            claimsIdentity.AddClaim(new Claim(ClaimTypes.Actor, jwtActorSymmetric));
            jwtToken = tokendHandler.CreateToken
                    (issuer: IdentityUtilities.DefaultIssuer,
                     audience: IdentityUtilities.DefaultAudience,
                     subject: claimsIdentity,
                     signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials);

            claimsPrincipal = RunActorTest(jwtToken.RawData, jwtActorSymmetric, validationParameters, validationParameters, tokendHandler, ExpectedException.SecurityTokenInvalidSignatureException(innerTypeExpected: typeof(InvalidOperationException)));

            // Will succeed be validation is off
            validationParameters.ValidateActor = false;
            claimsPrincipal = RunActorTest(jwtToken.RawData, jwtActorSymmetric, validationParameters, IdentityUtilities.DefaultSymmetricTokenValidationParameters, tokendHandler, ExpectedException.NoExceptionExpected);
        }

        private ClaimsPrincipal RunActorTest(string secutityToken, string actor, TokenValidationParameters validationParameters, TokenValidationParameters actorValidationParameters,  JwtSecurityTokenHandler tokendHandler, ExpectedException expectedException)
        {
            ClaimsPrincipal claimsPrincipal = null;
            try
            {
                SecurityToken validatedToken;
                claimsPrincipal = tokendHandler.ValidateToken(secutityToken, validationParameters, out validatedToken);
                ClaimsIdentity claimsIdentityValidated = claimsPrincipal.Identity as ClaimsIdentity;
                ClaimsPrincipal actorClaimsPrincipal = tokendHandler.ValidateToken(actor, actorValidationParameters, out validatedToken);
                Assert.IsNotNull(claimsIdentityValidated.Actor);
                Assert.IsTrue(IdentityComparer.AreEqual<ClaimsIdentity>(claimsIdentityValidated.Actor, (actorClaimsPrincipal.Identity as ClaimsIdentity)));
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            return claimsPrincipal;
        }

        [TestMethod]
        [TestProperty("TestCaseID", "A1976E06-F5D5-4DDB-88F8-E57B86B4EC64")]
        [Description("Claim Type Mapping - Inbound and Outbound")]
        public void JwtSecurityTokenHandler_ClaimTypeMapping()
        {
            Dictionary<string, string> inboundClaimTypeMap = new Dictionary<string, string>(ClaimTypeMapping.InboundClaimTypeMap);
            Dictionary<string, string> outboundClaimTypeMap = new Dictionary<string, string>(ClaimTypeMapping.OutboundClaimTypeMap);

            try
            {
                List<KeyValuePair<string, string>> aadStrings = new List<KeyValuePair<string, string>>();
                aadStrings.Add(new KeyValuePair<string, string>("amr", "http://schemas.microsoft.com/claims/authnmethodsreferences"));
                aadStrings.Add(new KeyValuePair<string, string>("deviceid", "http://schemas.microsoft.com/2012/01/devicecontext/claims/identifier"));
                aadStrings.Add(new KeyValuePair<string, string>("family_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"));
                aadStrings.Add(new KeyValuePair<string, string>("given_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"));
                aadStrings.Add(new KeyValuePair<string, string>("idp", "http://schemas.microsoft.com/identity/claims/identityprovider"));
                aadStrings.Add(new KeyValuePair<string, string>("oid", "http://schemas.microsoft.com/identity/claims/objectidentifier"));
                aadStrings.Add(new KeyValuePair<string, string>("scp", "http://schemas.microsoft.com/identity/claims/scope"));
                aadStrings.Add(new KeyValuePair<string, string>("tid", "http://schemas.microsoft.com/identity/claims/tenantid"));
                aadStrings.Add(new KeyValuePair<string, string>("unique_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"));
                aadStrings.Add(new KeyValuePair<string, string>("upn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"));

                foreach (var kv in aadStrings)
                {
                    Assert.IsFalse(!JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey(kv.Key), "Inbound short type missing: " + kv.Key);
                    Assert.IsFalse(JwtSecurityTokenHandler.InboundClaimTypeMap[kv.Key] != kv.Value, "Inbound mapping wrong: key " + kv.Key + " expected: " + JwtSecurityTokenHandler.InboundClaimTypeMap[kv.Key] + ", received: " + kv.Value);
                }

                List<KeyValuePair<string, string>> adfsStrings = new List<KeyValuePair<string, string>>();
                adfsStrings.Add(new KeyValuePair<string, string>("pwdexptime", "http://schemas.microsoft.com/ws/2012/01/passwordexpirationtime"));
                adfsStrings.Add(new KeyValuePair<string, string>("pwdexpdays", "http://schemas.microsoft.com/ws/2012/01/passwordexpirationdays"));
                adfsStrings.Add(new KeyValuePair<string, string>("pwdchgurl", "http://schemas.microsoft.com/ws/2012/01/passwordchangeurl"));
                adfsStrings.Add(new KeyValuePair<string, string>("clientip", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-ip"));
                adfsStrings.Add(new KeyValuePair<string, string>("forwardedclientip", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-forwarded-client-ip"));
                adfsStrings.Add(new KeyValuePair<string, string>("clientapplication", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-application"));
                adfsStrings.Add(new KeyValuePair<string, string>("clientuseragent", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-user-agent"));
                adfsStrings.Add(new KeyValuePair<string, string>("endpointpath", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path"));
                adfsStrings.Add(new KeyValuePair<string, string>("proxy", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-proxy"));
                adfsStrings.Add(new KeyValuePair<string, string>("relyingpartytrustid", "http://schemas.microsoft.com/2012/01/requestcontext/claims/relyingpartytrustid"));
                adfsStrings.Add(new KeyValuePair<string, string>("insidecorporatenetwork", "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork"));
                adfsStrings.Add(new KeyValuePair<string, string>("isregistereduser", "http://schemas.microsoft.com/2012/01/devicecontext/claims/isregistereduser"));
                adfsStrings.Add(new KeyValuePair<string, string>("deviceowner", "http://schemas.microsoft.com/2012/01/devicecontext/claims/userowner"));
                adfsStrings.Add(new KeyValuePair<string, string>("deviceid", "http://schemas.microsoft.com/2012/01/devicecontext/claims/identifier"));
                adfsStrings.Add(new KeyValuePair<string, string>("deviceregid", "http://schemas.microsoft.com/2012/01/devicecontext/claims/registrationid"));
                adfsStrings.Add(new KeyValuePair<string, string>("devicedispname", "http://schemas.microsoft.com/2012/01/devicecontext/claims/displayname"));
                adfsStrings.Add(new KeyValuePair<string, string>("deviceosver", "http://schemas.microsoft.com/2012/01/devicecontext/claims/osversion"));
                adfsStrings.Add(new KeyValuePair<string, string>("deviceismanaged", "http://schemas.microsoft.com/2012/01/devicecontext/claims/ismanaged"));
                adfsStrings.Add(new KeyValuePair<string, string>("deviceostype", "http://schemas.microsoft.com/2012/01/devicecontext/claims/ostype"));
                adfsStrings.Add(new KeyValuePair<string, string>("auth_time", "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant"));
                adfsStrings.Add(new KeyValuePair<string, string>("authmethod", "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod"));
                adfsStrings.Add(new KeyValuePair<string, string>("email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"));
                adfsStrings.Add(new KeyValuePair<string, string>("given_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"));
                adfsStrings.Add(new KeyValuePair<string, string>("unique_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"));
                adfsStrings.Add(new KeyValuePair<string, string>("upn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"));
                adfsStrings.Add(new KeyValuePair<string, string>("commonname", "http://schemas.xmlsoap.org/claims/CommonName"));
                adfsStrings.Add(new KeyValuePair<string, string>("adfs1email", "http://schemas.xmlsoap.org/claims/EmailAddress"));
                adfsStrings.Add(new KeyValuePair<string, string>("group", "http://schemas.xmlsoap.org/claims/Group"));
                adfsStrings.Add(new KeyValuePair<string, string>("adfs1upn", "http://schemas.xmlsoap.org/claims/UPN"));
                adfsStrings.Add(new KeyValuePair<string, string>("role", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"));
                adfsStrings.Add(new KeyValuePair<string, string>("family_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"));
                adfsStrings.Add(new KeyValuePair<string, string>("ppid", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier"));
                adfsStrings.Add(new KeyValuePair<string, string>("nameid", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"));
                adfsStrings.Add(new KeyValuePair<string, string>("denyonlysid", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/denyonlysid"));
                adfsStrings.Add(new KeyValuePair<string, string>("denyonlyprimarysid", "http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarysid"));
                adfsStrings.Add(new KeyValuePair<string, string>("denyonlyprimarygroupsid", "http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarygroupsid"));
                adfsStrings.Add(new KeyValuePair<string, string>("groupsid", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid"));
                adfsStrings.Add(new KeyValuePair<string, string>("primarygroupsid", "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid"));
                adfsStrings.Add(new KeyValuePair<string, string>("primarysid", "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid"));
                adfsStrings.Add(new KeyValuePair<string, string>("winaccountname", "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"));
                adfsStrings.Add(new KeyValuePair<string, string>("certapppolicy", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/applicationpolicy"));
                adfsStrings.Add(new KeyValuePair<string, string>("certauthoritykeyidentifier", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/authoritykeyidentifier"));
                adfsStrings.Add(new KeyValuePair<string, string>("certbasicconstraints", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/basicconstraints"));
                adfsStrings.Add(new KeyValuePair<string, string>("certeku", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/eku"));
                adfsStrings.Add(new KeyValuePair<string, string>("certissuer", "http://schemas.microsoft.com/2012/12/certificatecontext/field/issuer"));
                adfsStrings.Add(new KeyValuePair<string, string>("certissuername", "http://schemas.microsoft.com/2012/12/certificatecontext/field/issuername"));
                adfsStrings.Add(new KeyValuePair<string, string>("certkeyusage", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/keyusage"));
                adfsStrings.Add(new KeyValuePair<string, string>("certnotafter", "http://schemas.microsoft.com/2012/12/certificatecontext/field/notafter"));
                adfsStrings.Add(new KeyValuePair<string, string>("certnotbefore", "http://schemas.microsoft.com/2012/12/certificatecontext/field/notbefore"));
                adfsStrings.Add(new KeyValuePair<string, string>("certpolicy", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatepolicy"));
                adfsStrings.Add(new KeyValuePair<string, string>("certpublickey", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/rsa"));
                adfsStrings.Add(new KeyValuePair<string, string>("certrawdata", "http://schemas.microsoft.com/2012/12/certificatecontext/field/rawdata"));
                adfsStrings.Add(new KeyValuePair<string, string>("certsubjectaltname", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/san"));
                adfsStrings.Add(new KeyValuePair<string, string>("certserialnumber", "http://schemas.microsoft.com/ws/2008/06/identity/claims/serialnumber"));
                adfsStrings.Add(new KeyValuePair<string, string>("certsignaturealgorithm", "http://schemas.microsoft.com/2012/12/certificatecontext/field/signaturealgorithm"));
                adfsStrings.Add(new KeyValuePair<string, string>("certsubject", "http://schemas.microsoft.com/2012/12/certificatecontext/field/subject"));
                adfsStrings.Add(new KeyValuePair<string, string>("certsubjectkeyidentifier", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/subjectkeyidentifier"));
                adfsStrings.Add(new KeyValuePair<string, string>("certsubjectname", "http://schemas.microsoft.com/2012/12/certificatecontext/field/subjectname"));
                adfsStrings.Add(new KeyValuePair<string, string>("certtemplateinformation", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatetemplateinformation"));
                adfsStrings.Add(new KeyValuePair<string, string>("certtemplatename", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatetemplatename"));
                adfsStrings.Add(new KeyValuePair<string, string>("certthumbprint", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/thumbprint"));
                adfsStrings.Add(new KeyValuePair<string, string>("certx509version", "http://schemas.microsoft.com/2012/12/certificatecontext/field/x509version"));
                adfsStrings.Add(new KeyValuePair<string, string>("acr", "http://schemas.microsoft.com/claims/authnclassreference"));
                adfsStrings.Add(new KeyValuePair<string, string>("amr", "http://schemas.microsoft.com/claims/authnmethodsreferences"));


                foreach (var kv in adfsStrings)
                {
                    Assert.IsFalse(!JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey(kv.Key), "Inbound short type missing: " + kv.Key);
                    Assert.IsFalse(JwtSecurityTokenHandler.InboundClaimTypeMap[kv.Key] != kv.Value, "Inbound mapping wrong: key " + kv.Key + " expected: " + JwtSecurityTokenHandler.InboundClaimTypeMap[kv.Key] + ", received: " + kv.Value);
                }

                var handler = new JwtSecurityTokenHandler();

                // CreateToken will all 'aud' and 'sub' claims.
                IEnumerable<Claim> inboundShortClaims =
                    ClaimSets.AllInboundShortClaimTypes(
                            IdentityUtilities.DefaultIssuer,
                            IdentityUtilities.DefaultIssuer,
                            new List<Claim>
                        { 
                            new Claim("iss", IdentityUtilities.DefaultIssuer, ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                            new Claim("aud", IdentityUtilities.DefaultAudience, ClaimValueTypes.String, IdentityUtilities.DefaultIssuer),
                        });

                var jwt = handler.CreateToken(
                    issuer: IdentityUtilities.DefaultIssuer,
                    audience: IdentityUtilities.DefaultAudience,
                    subject: new ClaimsIdentity(
                        ClaimSets.AllInboundShortClaimTypes(
                            IdentityUtilities.DefaultIssuer,
                            IdentityUtilities.DefaultIssuer)));

                // These should not be translated.            
                // TODO fix this statement
                //Assert.IsTrue(IdentityComparer.AreEqual<IEnumerable<Claim>>(jwt.Claims, inboundShortClaims, CompareContext.Default));

                var validationParameters = new TokenValidationParameters
                {
                    RequireExpirationTime = false,
                    RequireSignedTokens = false,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                };

                // ValidateToken will map claims according to the InboundClaimTypeMap
                ValidateClaimMapping(jwt, handler, validationParameters, null, null, "Jwt with all ShortClaimTypes, InboundClaimTypeMap default");

                JwtSecurityTokenHandler.InboundClaimTypeMap.Clear();
                ValidateClaimMapping(jwt, handler, validationParameters, null, null, "Jwt with all ShortClaimTypes, InboundClaimTypeMap.Clear()");

                // test that setting the NameClaimType override works.
                List<Claim> claims = new List<Claim>()
                {
                    new Claim( ClaimTypes.GivenName, "Bob", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( ClaimTypes.Spn,       "spn", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( ReservedClaims.Sub,   "Subject1", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( ReservedClaims.Prn,   "Principal1", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( ReservedClaims.Sub,   "Subject2", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( ReservedClaims.Prn,   "Principal2", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( ReservedClaims.Sub,   "Subject3", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                };

                jwt = new JwtSecurityToken(issuer: Issuers.GotJwt, audience: Audiences.AuthFactors, claims: claims);
                JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>()
                {
                    { ReservedClaims.Email,     "Mapped_" + ReservedClaims.Email },
                    { ReservedClaims.GivenName, "Mapped_" + ReservedClaims.GivenName },
                    { ReservedClaims.Prn,       "Mapped_" + ReservedClaims.Prn },
                    { ReservedClaims.Sub,       "Mapped_" + ReservedClaims.Sub },
                };

                List<Claim> expectedClaims = new List<Claim>()
                {
                    new Claim( ReservedClaims.Iss, Issuers.GotJwt, ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( ReservedClaims.Audience, Audiences.AuthFactors, ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( "Mapped_" + ReservedClaims.Email, "Bob", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( ClaimTypes.Spn,   "spn", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( "Mapped_" + ReservedClaims.Sub, "Subject1", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( "Mapped_" + ReservedClaims.Prn, ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( "Mapped_" + ReservedClaims.Sub, "Subject2", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( "Mapped_" + ReservedClaims.Prn, "Principal2", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( "Mapped_" + ReservedClaims.Sub, "Subject3", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                };
            }
            finally
            {
                JwtSecurityTokenHandler.InboundClaimTypeMap = inboundClaimTypeMap;
                JwtSecurityTokenHandler.OutboundClaimTypeMap = inboundClaimTypeMap;
            }
        }

        private void ValidateClaimMapping(JwtSecurityToken jwt, JwtSecurityTokenHandler handler, TokenValidationParameters validationParameters, IEnumerable<Claim> expectedClaims, string identityName, string variation)
        {
            Console.WriteLine("ValidateClaimMapping: variation: " + variation);
            SecurityToken validatedToken;

            ClaimsPrincipal cp = handler.ValidateToken(jwt.RawData, validationParameters, out validatedToken);
            ClaimsIdentity identity = cp.Identity as ClaimsIdentity;

            Assert.IsFalse(expectedClaims != null && !IdentityComparer.AreEqual(identity.Claims, expectedClaims), "identity.Claims != expectedClaims");
            Assert.IsFalse(identityName != null && identity.Name != identityName, "identity.Name != identityName");

            // This checks that all claims that should have been mapped.
            foreach (Claim claim in identity.Claims)
            {
                // if it was mapped, make sure the shortname is found in the mapping and equals the claim.Type
                if (claim.Properties.ContainsKey(JwtSecurityTokenHandler.ShortClaimTypeProperty))
                {
                    Assert.IsFalse(!JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey(claim.Properties[JwtSecurityTokenHandler.ShortClaimTypeProperty]), "!JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( claim.Properties[JwtSecurityTokenHandler.ShortClaimTypeProperty] ): " + claim.Type);
                }
                // there was no short property.
                Assert.IsFalse(JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey(claim.Type), "JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( claim.Type ), wasn't mapped claim.Type: " + claim.Type);
            }

            foreach (Claim claim in jwt.Claims)
            {
                string claimType = claim.Type;

                if (JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey(claimType))
                {
                    claimType = JwtSecurityTokenHandler.InboundClaimTypeMap[claim.Type];
                }

                if (!JwtSecurityTokenHandler.InboundClaimFilter.Contains(claim.Type))
                {
                    Claim firstClaim = identity.FindFirst(claimType);
                    Assert.IsFalse(firstClaim == null, "Claim firstClaim = identity.FindFirst( claimType ), firstClaim == null. claim.Type: " + claim.Type + " claimType: " + claimType);
                }
            }
        }


        [TestMethod]
        [TestProperty("TestCaseID", "2CADC17D-D1F4-4A20-B54A-44FE37445348")]
        [Description("Tests: Publics")]
        public void JwtSecurityTokenHandler_Publics()
        {
            string methodToCall = _testContextProvider.GetValue<string>("Method");
            SecurityToken validatedToken;
            foreach (JwtSecurityTokenTestVariation variation in PublicMethodVariations())
            {
                Console.WriteLine("Variation: " + variation.Name);
                try
                {
                    if (variation.Name.StartsWith("CanReadToken_XmlReader"))
                    {
                        bool retval = variation.JwtSecurityTokenHandler.CanReadToken(variation.XmlReader);
                        Assert.IsFalse(retval != variation.BoolRetVal, string.Format("variation.JwtSecurityTokenHandler.CanReadToken: expected: '{0}', received: '{1}'", variation.BoolRetVal, retval));

                    }
                    else if (variation.Name.StartsWith("CanReadToken_String"))
                    {

                        Assert.IsFalse(variation.JwtSecurityTokenHandler.CanReadToken(variation.EncodedString) != variation.BoolRetVal, string.Format("variation.JwtSecurityTokenHandler.CanReadToken: expected: '{0}', received: '{1}'", variation.BoolRetVal, variation.JwtSecurityTokenHandler.CanReadToken(variation.EncodedString)));
                    }
                    else if (variation.Name.StartsWith("CanValidateToken"))
                    {
                        Assert.IsFalse(variation.JwtSecurityTokenHandler.CanValidateToken != variation.BoolRetVal, string.Format("variation.JwtSecurityTokenHandler.CanValidateToken: expected: '{0}', received: '{1}'", variation.BoolRetVal, variation.JwtSecurityTokenHandler.CanValidateToken));
                    }
                    else if (variation.Name.StartsWith("CanWriteToken"))
                    {
                        Assert.IsFalse(variation.JwtSecurityTokenHandler.CanWriteToken != variation.BoolRetVal, string.Format("variation.JwtSecurityTokenHandler.CanWriteToken: expected: '{0}', received: '{1}'", variation.BoolRetVal, variation.JwtSecurityTokenHandler.CanWriteToken));
                    }
                    else if (variation.Name.StartsWith("CreateToken_SecurityTokenDescriptor"))
                    {
                        SecurityToken retval = variation.JwtSecurityTokenHandler.CreateToken(variation.SecurityTokenDescriptor);
                        if (variation.JwtSecurityToken != null)
                        {
                            Assert.IsFalse(IdentityComparer.AreEqual(retval as JwtSecurityToken, variation.JwtSecurityToken), string.Format("variation.JwtSecurityTokenHandler.CreateToken: expected: '{0}', received: '{1}'", variation.JwtSecurityToken, retval));
                        }
                    }
                    else if (variation.Name.StartsWith("ReadToken_Reader"))
                    {
                        variation.JwtSecurityTokenHandler.ReadToken(variation.XmlReader);
                    }
                    else if (variation.Name.StartsWith("ReadToken_String"))
                    {
                        variation.JwtSecurityTokenHandler.ReadToken(variation.EncodedString);
                    }
                    else if (variation.Name.StartsWith("ValidateToken_String_TVP"))
                    {
                        variation.JwtSecurityTokenHandler.ValidateToken(variation.EncodedString, variation.TokenValidationParameters, out validatedToken);
                    }
                    else if (variation.Name.StartsWith("ValidateToken_Jwt_TVP"))
                    {
                        variation.JwtSecurityTokenHandler.ValidateToken(variation.JwtSecurityToken.RawData, variation.TokenValidationParameters, out validatedToken);
                    }
                    else if (variation.Name.StartsWith("WriteToken_XmlWriter"))
                    {
                        variation.JwtSecurityTokenHandler.WriteToken(variation.XmlWriter, variation.SecurityToken);
                    }
                    else if (variation.Name.StartsWith("WriteToken_Token"))
                    {
                        variation.JwtSecurityTokenHandler.WriteToken(variation.SecurityToken);
                    }
                    else
                    {
                        Assert.Fail("unknown variation: " + variation.Name);
                    }

                    variation.ExpectedException.ProcessNoException();
                }
                catch (Exception ex)
                {
                    variation.ExpectedException.ProcessException(ex);
                }
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "70553299-B307-48AD-A406-3CB12E7C6463")]
        [Description("CanRead Variations")]
        public void JwtSecurityTokenHandler_CanReadVariations()
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            // XML reader
            Assert.IsFalse(RunCanReadXmlVariation(XmlReaderVariation.WithoutNS, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.IsFalse(RunCanReadXmlVariation(null, tokenHandler, ExpectedException.ArgumentNullException()));
            Assert.IsTrue(RunCanReadXmlVariation(XmlReaderVariation.JwtTokenType, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.IsTrue(RunCanReadXmlVariation(XmlReaderVariation.JwtTokenTypeAlt, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.IsTrue(RunCanReadXmlVariation(XmlReaderVariation.WithoutEncodingType, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.IsFalse(RunCanReadXmlVariation(XmlReaderVariation.WithWrongEncodingType, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.IsFalse(RunCanReadXmlVariation(XmlReaderVariation.WithWrongTokenType, tokenHandler, ExpectedException.NoExceptionExpected));

            // Encoded string
            Assert.IsFalse(RunCanReadStringVariation(null, tokenHandler, ExpectedException.ArgumentNullException()));
            Assert.IsFalse(RunCanReadStringVariation("bob", tokenHandler, ExpectedException.NoExceptionExpected));
        }

        private bool RunCanReadXmlVariation(XmlReader reader, JwtSecurityTokenHandler tokenHandler,ExpectedException expectedException)
        {
            bool retVal = false;
            try
            {
                retVal = tokenHandler.CanReadToken(reader);
                expectedException.ProcessNoException();
            }
            catch(Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            return retVal;
        }

        private bool RunCanReadStringVariation(string securityToken, JwtSecurityTokenHandler tokenHandler, ExpectedException expectedException)
        {
            bool retVal = false;
            try
            {
                retVal = tokenHandler.CanReadToken(securityToken);
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            return retVal;
        }

        [TestMethod]
        [TestProperty("TestCaseID", "94084020-42E7-47D0-A398-021124F7F28C")]
        [Description("Read Variations")]
        public void JwtSecurityTokenHandler_ReadVariations()
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            JwtSecurityToken jwt = RunReadXmlVariation(null, tokenHandler, ExpectedException.ArgumentNullException());
            jwt = RunReadXmlVariation(XmlReaderVariation.WithWrongEncodingType, tokenHandler, ExpectedException.ArgumentException(substringExpected: "Jwt10203"));

            jwt = RunReadStringVariation(null, tokenHandler, ExpectedException.ArgumentNullException());
            jwt = RunReadStringVariation(EncodedJwts.Asymmetric_LocalSts, new JwtSecurityTokenHandler() { MaximumTokenSizeInBytes = 100 }, ExpectedException.ArgumentException(substringExpected: "Jwt10206"));
            jwt = RunReadStringVariation("SignedEncodedJwts.Asymmetric_LocalSts", tokenHandler, ExpectedException.ArgumentException(substringExpected: "Jwt10204"));
            jwt = RunReadStringVariation(EncodedJwts.Asymmetric_LocalSts, tokenHandler, ExpectedException.NoExceptionExpected);
        }

        private JwtSecurityToken RunReadXmlVariation(XmlReader reader, JwtSecurityTokenHandler tokenHandler, ExpectedException expectedException)
        {
            JwtSecurityToken retVal = null;
            try
            {
                retVal = tokenHandler.ReadToken(reader) as JwtSecurityToken;;
                expectedException.ProcessNoException();
            }
            catch(Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            return retVal;
        }

        private JwtSecurityToken RunReadStringVariation(string securityToken, JwtSecurityTokenHandler tokenHandler, ExpectedException expectedException)
        {
            JwtSecurityToken retVal = null;
            try
            {
                retVal = tokenHandler.ReadToken(securityToken) as JwtSecurityToken;
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            return retVal;
        }

        [TestMethod]
        [TestProperty("TestCaseID", "94084020-42E7-47D0-A398-021124F7F28C")]
        [Description("Validate Tokens")]
        public void JwtSecurityTokenHandler_ValidateToken()
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            
            RunValidateTokenVariation(null, new TokenValidationParameters(), tokenHandler, ExpectedException.ArgumentNullException());
            RunValidateTokenVariation(EncodedJwts.Asymmetric_LocalSts, new TokenValidationParameters(), new JwtSecurityTokenHandler() { MaximumTokenSizeInBytes = 100 }, ExpectedException.ArgumentException(substringExpected: "Jwt10206"));
            RunValidateTokenVariation("ValidateToken_String_Only_IllFormed", new TokenValidationParameters(), tokenHandler, ExpectedException.ArgumentException(substringExpected:"Jwt10204"));
            RunValidateTokenVariation("     ", new TokenValidationParameters(), tokenHandler, ExpectedException.ArgumentNullException());
            RunValidateTokenVariation(EncodedJwts.Asymmetric_LocalSts, null, tokenHandler, ExpectedException.ArgumentNullException());
        }

        private ClaimsPrincipal RunValidateTokenVariation(string securityToken, TokenValidationParameters validationParameters, JwtSecurityTokenHandler tokenHandler, ExpectedException expectedException)
        {
            ClaimsPrincipal retVal = null;
            try
            {
                SecurityToken validatedToken;
                retVal = tokenHandler.ValidateToken(securityToken, validationParameters, out validatedToken);
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            return retVal;
        }


        private List<JwtSecurityTokenTestVariation> PublicMethodVariations()
        {
            List<JwtSecurityTokenTestVariation> variations = new List<JwtSecurityTokenTestVariation>()
            {
                new JwtSecurityTokenTestVariation
                {
                    Name = "CreateToken_SecurityTokenDescriptor_Null",
                    SecurityTokenDescriptor = null,
                    ExpectedException = ExpectedException.ArgumentNullException(),
                },

#region ValidateToken
#endregion

#region WriteToken
                new JwtSecurityTokenTestVariation
                {
                    Name = "WriteToken_XmlWriter_WriterNull",
                    XmlWriter = null,
                    SecurityToken = new JwtSecurityToken( EncodedJwts.Asymmetric_2048 ), 
                    ExpectedException = ExpectedException.ArgumentNullException(),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "WriteToken_XmlWriter_Token_Null",
                    XmlWriter = XmlDictionaryWriter.CreateTextWriter( new MemoryStream() ),
                    SecurityToken = null,
                    ExpectedException = ExpectedException.ArgumentNullException(),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "WriteToken_XmlWriter_Token_NotJwt",
                    XmlWriter = XmlDictionaryWriter.CreateTextWriter( new MemoryStream() ),
                    SecurityToken = new UserNameSecurityToken( "Foo", "Bar"),
                    ExpectedException = ExpectedException.ArgumentException(substringExpected:"Jwt10200" ),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "WriteToken_Token_TokenNull",
                    SecurityToken = null,
                    ExpectedException = ExpectedException.ArgumentNullException(),
                },
                new JwtSecurityTokenTestVariation
                {
                    Name = "WriteToken_Token_TokenNotJwt",
                    XmlWriter = XmlDictionaryWriter.CreateTextWriter( new MemoryStream() ),
                    SecurityToken = new UserNameSecurityToken("Foo", "Bar"),
                    ExpectedException = ExpectedException.ArgumentException(substringExpected:"Jwt10200"),
                },
#endregion
            };

            return variations;
        }

        [TestMethod]
        [TestProperty("TestCaseID", "B6C1D4D1-3CF9-4281-B024-39FCBD03160E")]
        [Description("JWTSecurityTokenHandler - tests that the bootstrap context is saved and is as expected")]
        public void JwtSecurityTokenHandler_BootstrapTokenTests()
        {
            SecurityToken validatedToken;
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            TokenValidationParameters validationParameters = IdentityUtilities.DefaultSymmetricTokenValidationParameters;
            validationParameters.SaveSigninToken = false;
            string jwt = IdentityUtilities.DefaultSymmetricJwt;
            ClaimsPrincipal claimsPrincipal = tokenHandler.ValidateToken(jwt, validationParameters, out validatedToken);
            BootstrapContext context = (claimsPrincipal.Identity as ClaimsIdentity).BootstrapContext as BootstrapContext;
            Assert.IsNull(context);

            validationParameters.SaveSigninToken = true;            
            claimsPrincipal = tokenHandler.ValidateToken(jwt, validationParameters, out validatedToken);
            context = (claimsPrincipal.Identity as ClaimsIdentity).BootstrapContext as BootstrapContext;
            Assert.IsNotNull(context);
            Assert.IsTrue(IdentityComparer.AreEqual(claimsPrincipal, tokenHandler.ValidateToken(context.Token, validationParameters, out validatedToken)));
        }


        [TestMethod]
        [TestProperty("TestCaseID", "D540296C-BEFD-4D37-BC94-6E3FD9DBBC31")]
        [Description("JWTSecurityTokenHandler - ReadToken")]
        public void JwtSecurityTokenHandler_ReadTokenTests()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            ExpectedException expectedException = ExpectedException.ArgumentOutOfRangeException();
            try
            {
                handler.MaximumTokenSizeInBytes = 0;
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            Assert.IsFalse(handler.CanReadToken("1"), string.Format("Expected JWTSecurityTokenHandler.CanReadToken to be false"));

            expectedException = ExpectedException.ArgumentException(substringExpected: "Jwt10204");
            try
            {
                handler.ReadToken("1");
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "00E34491-C6F0-40FA-AA66-090729F46927")]
        [Description("Signature Validation")]
        public void JwtSecurityTokenHandler_SignatureValidation()
        {
            // "Security Key Identifier not found",
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            ExpectedException expectedException = new ExpectedException(typeof(SecurityTokenInvalidSignatureException), "Jwt10315:");
            TokenValidationParameters validationParameters = SignatureValidationParameters(signingToken: KeyingMaterial.X509Token_LocalSts);
            CheckVariation(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "ALLParts"), tokenHandler, validationParameters, expectedException);

            // "Asymmetric_LocalSts"
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = SignatureValidationParameters(signingToken: KeyingMaterial.X509Token_LocalSts);
            CheckVariation(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_LocalSts, "ALLParts"), tokenHandler, validationParameters, expectedException);

            // "Asymmetric_1024"
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = SignatureValidationParameters(signingToken: KeyingMaterial.X509Token_1024);
            CheckVariation(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_1024, "ALLParts"), tokenHandler, validationParameters, expectedException);

            // "Asymmetric_2048"
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = SignatureValidationParameters(signingToken: KeyingMaterial.DefaultX509Token_2048);
            CheckVariation(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "ALLParts"), tokenHandler, validationParameters, expectedException);

            // "Symmetric_256"
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = SignatureValidationParameters(signingToken: KeyingMaterial.DefaultSymmetricSecurityToken_256 );
            CheckVariation(JwtTestUtilities.GetJwtParts(EncodedJwts.Symmetric_256, "ALLParts"), tokenHandler, validationParameters, expectedException);

            // "Signature missing, just two parts",
            expectedException = ExpectedException.SecurityTokenValidationException("Jwt10312:");
            validationParameters = SignatureValidationParameters(signingToken: KeyingMaterial.DefaultX509Token_2048 );
            CheckVariation(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "Parts-0-1"), tokenHandler, validationParameters, expectedException);

            // "SigningToken and SigningTokens both null",
            expectedException = new ExpectedException(typeExpected: typeof(SecurityTokenInvalidSignatureException), substringExpected:"Jwt10315:");
            validationParameters = SignatureValidationParameters();
            CheckVariation(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "ALLParts"), tokenHandler, validationParameters, expectedException);

            // "SigningToken null, SigningTokens valid",
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = SignatureValidationParameters( signingTokens: new List<SecurityToken> { KeyingMaterial.DefaultX509Token_2048 } );
            CheckVariation(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "ALLParts"), tokenHandler, validationParameters, expectedException);

            // "SigningToken no keys",
            expectedException = new ExpectedException(typeExpected: typeof(SecurityTokenInvalidSignatureException), substringExpected:"Jwt10315:");
            validationParameters = SignatureValidationParameters( signingToken: new UserNameSecurityToken( "username", "password" ) );
            CheckVariation(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_LocalSts, "ALLParts"), tokenHandler, validationParameters, expectedException);

            // "RSA signingtoken"
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = SignatureValidationParameters( signingToken: KeyingMaterial.RsaToken_2048 );
            CheckVariation(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "ALLParts"), tokenHandler, validationParameters, expectedException);

            // "NamedKey SecurityToken",
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = 
                SignatureValidationParameters(
                    signingToken: new NamedKeySecurityToken( "keys", 
                        new List<SecurityKey>(){ KeyingMaterial.RsaToken_2048.SecurityKeys[0], KeyingMaterial.DefaultSymmetricSecurityKey_256}));
            CheckVariation(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "ALLParts"), tokenHandler, validationParameters, expectedException);

            // "BinaryKey 56Bits",
            expectedException = new ExpectedException(typeExpected: typeof(SecurityTokenInvalidSignatureException), innerTypeExpected: typeof(ArgumentOutOfRangeException), substringExpected:"Jwt10503:");
            validationParameters = SignatureValidationParameters(signingToken: KeyingMaterial.BinarayToken56BitKey);
            CheckVariation(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "ALLParts"), tokenHandler, validationParameters, expectedException);
        }

        private static TokenValidationParameters SignatureValidationParameters(
            Func<string, IEnumerable<SecurityKey>> issuerSigningKeyRetriever = null,
            SecurityKey signingKey = null,
            IEnumerable<SecurityKey> signingKeys = null,
            SecurityToken signingToken = null, 
            IEnumerable<SecurityToken> signingTokens = null)
        {
            return new TokenValidationParameters()
            {
                IssuerSigningKeyRetriever = issuerSigningKeyRetriever,
                IssuerSigningToken = signingToken,
                IssuerSigningKeys = signingKeys,
                IssuerSigningTokens = signingTokens,
                RequireExpirationTime = false,
                ValidateAudience = false,
                ValidateIssuer = false,
            };
        }

        [TestMethod]
        [TestProperty("TestCaseID", "6356C21F-280C-4A9E-875C-F6543DF0A5E3")]
        [Description("Issuer Validation TVP")]
        public void JwtSecurityTokenHandler_IssuerValidationTests()
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            string jwt = (tokenHandler.CreateToken(issuer: IdentityUtilities.DefaultIssuer, audience: IdentityUtilities.DefaultAudience, signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials) as JwtSecurityToken).RawData;
            TokenValidationParameters validationParameters = new TokenValidationParameters() { IssuerSigningToken = IdentityUtilities.DefaultAsymmetricSigningToken, ValidateAudience = false, ValidateLifetime = false };
            
            // ValidateIssuer == true

            // validIssuer null, validIssuers null
            ExpectedException ee = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), substringExpected: "IDX10204");
            CheckVariation(jwt, tokenHandler, validationParameters, ee);

            // no issuers
            ee = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), substringExpected: "IDX10205");
            validationParameters.ValidIssuers = new List<string>();
            CheckVariation(jwt, tokenHandler, validationParameters, ee);

            // delegate ignored on virtual call
            ee = ExpectedException.NoExceptionExpected;
            validationParameters.IssuerValidator = IdentityUtilities.IssuerValidatorEcho;
            CheckVariation(jwt, tokenHandler, validationParameters, ee);

            // VaidateIssuer == false
            ee = ExpectedException.NoExceptionExpected;
            validationParameters.ValidateIssuer = false;
            CheckVariation(jwt, tokenHandler, validationParameters, ee);

            // no issuers should NOT fail. vaidate issuer is not needed.
            ee = ExpectedException.NoExceptionExpected;
            validationParameters.ValidIssuers = new List<string>() { "http://Simple.CertData_2049" };
            CheckVariation(jwt, tokenHandler, validationParameters, ee);

            // matches ValidIssuer
            validationParameters.ValidateIssuer = true;
            validationParameters.ValidIssuer = IdentityUtilities.DefaultIssuer;
            CheckVariation(jwt, tokenHandler, validationParameters, ExpectedException.NoExceptionExpected);
            
            // matches ValidIssuers
            validationParameters.ValidIssuer = null;
            validationParameters.ValidIssuers = new string[] { "http://Simple.CertData_2048", IdentityUtilities.DefaultIssuer };
            CheckVariation(jwt, tokenHandler, validationParameters, ExpectedException.NoExceptionExpected);
        }

        [TestMethod]
        [TestProperty("TestCaseID", "6356C21F-280C-4A9E-875C-F6543DF0A5E3")]
        [Description("Audience Validation")]
        public void JwtSecurityTokenHandler_AudienceValidationTests()
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            // "Jwt.Audience == null"
            TokenValidationParameters validationParameters = new TokenValidationParameters() { ValidateIssuer = false, RequireExpirationTime = false, RequireSignedTokens = false };
            ExpectedException ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208");
            string jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: null) as JwtSecurityToken).RawData;
            CheckVariation(jwt, tokenHandler, validationParameters, ee);

            // "jwt.Audience == EmptyString"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: string.Empty) as JwtSecurityToken).RawData;
            CheckVariation(jwt, tokenHandler, validationParameters, ee);

            // "jwt.Audience == whitespace"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: "    ") as JwtSecurityToken).RawData;
            CheckVariation(jwt, tokenHandler, validationParameters, ee);

            // "TokenValidationParameters.ValidAudience TokenValidationParameters.ValidAudiences both null"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: "http://www.GotJwt.com") as JwtSecurityToken).RawData;
            CheckVariation(jwt, tokenHandler, validationParameters, ee);

            // "TokenValidationParameters.ValidAudience empty, TokenValidationParameters.ValidAudiences empty"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: "http://www.GotJwt.com") as JwtSecurityToken).RawData;
            validationParameters = new TokenValidationParameters() { RequireExpirationTime = false, RequireSignedTokens = false, ValidAudience = string.Empty, ValidAudiences = new List<string>(), ValidateIssuer = false };
            CheckVariation(jwt, tokenHandler, validationParameters, ee);

            // "TokenValidationParameters.ValidAudience whitespace, TokenValidationParameters.ValidAudiences empty"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: "http://www.GotJwt.com") as JwtSecurityToken).RawData;
            validationParameters = new TokenValidationParameters() { RequireExpirationTime = false, RequireSignedTokens = false, ValidAudience = "   ", ValidAudiences = new List<string>(), ValidateIssuer = false };
            CheckVariation(jwt, tokenHandler, validationParameters, ee);

            // "TokenValidationParameters.ValidAudience empty, TokenValidationParameters.ValidAudience one null string"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: "http://www.GotJwt.com") as JwtSecurityToken).RawData;
            validationParameters = new TokenValidationParameters() { RequireExpirationTime = false, RequireSignedTokens = false, ValidAudience = "", ValidAudiences = new List<string>() { null }, ValidateIssuer = false };
            CheckVariation(jwt, tokenHandler, validationParameters, ee);

            // "TokenValidationParameters.ValidAudience empty, TokenValidationParameters.ValidAudiences one empty string"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience:  "http://www.GotJwt.com") as JwtSecurityToken).RawData;
            validationParameters = new TokenValidationParameters() { RequireExpirationTime = false, RequireSignedTokens = false, ValidAudience = "", ValidAudiences = new List<string>() { string.Empty }, ValidateIssuer = false };
            CheckVariation(jwt, tokenHandler, validationParameters, ee);

            // "TokenValidationParameters.ValidAudience string.Empty, TokenValidationParameters.ValidAudiences one string whitespace"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: "http://www.GotJwt.com") as JwtSecurityToken).RawData;
            validationParameters = new TokenValidationParameters() { RequireExpirationTime = false, RequireSignedTokens = false, ValidAudience = "", ValidAudiences = new List<string>() { "     " }, ValidateIssuer = false };
            CheckVariation(jwt, tokenHandler, validationParameters, ee);
        }

        private void CheckVariation(string jwt, JwtSecurityTokenHandler tokenHandler, TokenValidationParameters validationParameters, ExpectedException expectedException)
        {
            try
            {
                SecurityToken validatedToken;
                tokenHandler.ValidateToken(jwt, validationParameters, out validatedToken);
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        private void CheckVariation(JwtSecurityToken jwt, JwtSecurityTokenHandler tokenHandler, ExpectedException expectedException)
        {
            try
            {
                tokenHandler.ValidateToken(jwt);
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

    }    
}
