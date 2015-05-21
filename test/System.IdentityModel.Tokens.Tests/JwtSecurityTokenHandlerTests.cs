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

using Microsoft.IdentityModel.Protocols;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using Xunit;

namespace System.IdentityModel.Test
{

#if JWT_XML
    public class XmlReaderVariation
    {
        public const string  WsuId                    = "c9b6b6b4-bd35-46ae-8146-15d6b00d22ed";
        private const string _templateWithEncoding    = @"<wsse:{0}  xmlns:wsu='{1}' xmlns:wsse='{2}' ValueType='{3}' EncodingType='{4}' wsu:Id='c9b6b6b4-bd35-46ae-8146-15d6b00d22ed' >{5}</wsse:{0}>";
        private const string _templateWithoutEncoding = @"<wsse:{0}  xmlns:wsu='{1}' xmlns:wsse='{2}' ValueType='{3}'>{4}</wsse:{0}>";
        private const string _templateWithoutns       = @"<{0}  ValueType='{1}' EncodingType='{2}'>{3}<{0}>";

        public static string JwtTokenTypeString
        {
            get
            {
                return string.Format( _templateWithEncoding,
                                      WSSecurityConstantsInternal.Elements.BinarySecurityToken,
                                      WSSecurityConstantsInternal.Namespace,
                                      WSSecurityConstantsInternal.Namespace,
                                      JwtConstants.TokenType,
                                      WSSecurityConstantsInternal.Base64EncodingType,
                                      Convert.ToBase64String(Encoding.UTF8.GetBytes(EncodedJwts.Asymmetric_LocalSts)));
            }
        }

        public static XmlReader JwtTokenType
        {
            get
            {
                XmlReader reader = XmlReader.Create(new MemoryStream(UTF8Encoding.UTF8.GetBytes(JwtTokenTypeString)));
                reader.MoveToContent();
                return reader;
            }
        }

        public static string JwtTokenTypeAltString
        {
            get
            {
                return string.Format(_templateWithEncoding,
                                     WSSecurityConstantsInternal.Elements.BinarySecurityToken,
                                     WSSecurityConstantsInternal.Namespace,
                                     WSSecurityConstantsInternal.Namespace,
                                     JwtConstants.TokenTypeAlt,
                                     WSSecurityConstantsInternal.Base64EncodingType,
                                     Convert.ToBase64String(Encoding.UTF8.GetBytes(EncodedJwts.Asymmetric_LocalSts)));
            }
        }
        public static XmlReader JwtTokenTypeAlt
        {
            get
            {
                XmlReader reader = XmlReader.Create(new MemoryStream(UTF8Encoding.UTF8.GetBytes(JwtTokenTypeAltString)));
                reader.MoveToContent();
                return reader;
            }
        }

        public static string WithoutEncodingTypeString
        {
            get
            {
                return string.Format(_templateWithoutEncoding,
                                     WSSecurityConstantsInternal.Elements.BinarySecurityToken,
                                     WSSecurityConstantsInternal.Namespace,
                                     WSSecurityConstantsInternal.Namespace,
                                     JwtConstants.TokenType,
                                     Convert.ToBase64String(Encoding.UTF8.GetBytes(EncodedJwts.Asymmetric_LocalSts)));
            }
        }

        public static XmlReader WithoutEncodingType
        {
            get
            {
                XmlReader reader = XmlReader.Create(new MemoryStream(UTF8Encoding.UTF8.GetBytes(WithoutEncodingTypeString)));
                reader.MoveToContent();
                return reader;
            }
        }

        public static string WithWrongEncodingTypeString
        {
            get
            {
                return string.Format(_templateWithEncoding,
                                     WSSecurityConstantsInternal.Elements.BinarySecurityToken,
                                     WSSecurityConstantsInternal.Namespace,
                                     WSSecurityConstantsInternal.Namespace,
                                     JwtConstants.TokenType,
                                     "BadEncoding",
                                     Convert.ToBase64String(Encoding.UTF8.GetBytes(EncodedJwts.Asymmetric_LocalSts)));
            }
        }
        public static XmlReader WithWrongEncodingType
        {
            get
            {
                XmlReader reader = XmlReader.Create(new MemoryStream(UTF8Encoding.UTF8.GetBytes(WithWrongEncodingTypeString)));
                reader.MoveToContent();
                return reader;
            }
        }

        public static string WithWrongTokenTypeString
        {
            get
            {
                return string.Format(_templateWithoutEncoding,
                                     WSSecurityConstantsInternal.Elements.BinarySecurityToken,
                                     WSSecurityConstantsInternal.Namespace,
                                     WSSecurityConstantsInternal.Namespace,
                                     "JwtConstants.TokenTypeShort",
                                     Convert.ToBase64String(Encoding.UTF8.GetBytes(EncodedJwts.Asymmetric_LocalSts)));
            }
        }
        public static XmlReader WithWrongTokenType
        {
            get
            {
                XmlReader reader = XmlReader.Create(new MemoryStream(UTF8Encoding.UTF8.GetBytes(WithWrongTokenTypeString)));
                reader.MoveToContent();
                return reader;
            }
        }

        public static string WithoutNSString
        {
            get 
            {
                return string.Format(_templateWithoutns,
                                     WSSecurityConstantsInternal.Elements.BinarySecurityToken,
                                     JwtConstants.TokenType,
                                     WSSecurityConstantsInternal.Base64EncodingType,
                                     Convert.ToBase64String(Encoding.UTF8.GetBytes(EncodedJwts.Asymmetric_LocalSts)));
            }
        }


        public static XmlReader WithoutNS
        {
            get
            {
                XmlReader reader = XmlReader.Create(new MemoryStream(UTF8Encoding.UTF8.GetBytes(WithoutNSString)));
                reader.MoveToContent();
                return reader;
            }
        }

    }
    #endif

    /// <summary>
    /// 
    /// </summary>
    public class JwtSecurityTokenHandlerTests
    {
        [Fact( DisplayName = "JwtSecurityTokenHandlerTests: Actor Tests.  Ensure that 'actors' work correctly inbound and outbound.  Signed, with and without bootstrap context")]
        public void ActorTests()
        {
            // Set up tests artifacts here.
            JwtSecurityTokenHandler tokendHandler = new JwtSecurityTokenHandler();

            TokenValidationParameters validationParameters = IdentityUtilities.DefaultAsymmetricTokenValidationParameters;
            validationParameters.ValidateActor = false;
            validationParameters.SaveSigninToken = true;

            string jwtActorAsymmetric = IdentityUtilities.DefaultAsymmetricJwt;

            // actor can be set by adding the claim directly
            ClaimsIdentity claimsIdentity = ClaimSets.DefaultClaimsIdentity;
            claimsIdentity.AddClaim(new Claim(ClaimTypes.Actor, jwtActorAsymmetric));
            JwtSecurityToken jwtToken = tokendHandler.CreateToken
                    (issuer: IdentityUtilities.DefaultIssuer,
                     audience: IdentityUtilities.DefaultAudience,
                     subject: claimsIdentity,
                     signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials);

            // actor will be validated using same validationParameters
            validationParameters.ValidateActor = true;
            ClaimsPrincipal claimsPrincipal = RunActorVariation(jwtToken.RawData, jwtActorAsymmetric, validationParameters, validationParameters, tokendHandler, ExpectedException.NoExceptionExpected);

#if SymmetricKeySuport
            string jwtActorSymmetric = IdentityUtilities.DefaultSymmetricJwt;

            // Validation on actor will fail because the keys are different types
            claimsIdentity = IdentityUtilities.DefaultClaimsIdentity;
            claimsIdentity.AddClaim(new Claim(ClaimTypes.Actor, jwtActorSymmetric));
            jwtToken = tokendHandler.CreateToken
                    (issuer: IdentityUtilities.DefaultIssuer,
                     audience: IdentityUtilities.DefaultAudience,
                     subject: claimsIdentity,
                     signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials);

            claimsPrincipal = RunActorVariation(jwtToken.RawData, jwtActorSymmetric, validationParameters, validationParameters, tokendHandler, ExpectedException.SignatureVerificationFailedException(innerTypeExpected: typeof(InvalidOperationException)));

            // Will succeed be validation is off
            validationParameters.ValidateActor = false;
            claimsPrincipal = RunActorVariation(jwtToken.RawData, jwtActorSymmetric, validationParameters, IdentityUtilities.DefaultSymmetricTokenValidationParameters, tokendHandler, ExpectedException.NoExceptionExpected);
#endif
        }

        private ClaimsPrincipal RunActorVariation(string secutityToken, string actor, TokenValidationParameters validationParameters, TokenValidationParameters actorValidationParameters,  JwtSecurityTokenHandler tokendHandler, ExpectedException expectedException)
        {
            ClaimsPrincipal claimsPrincipal = null;
            try
            {
                SecurityToken validatedToken;
                claimsPrincipal = tokendHandler.ValidateToken(secutityToken, validationParameters, out validatedToken);
                ClaimsIdentity claimsIdentityValidated = claimsPrincipal.Identity as ClaimsIdentity;
                ClaimsPrincipal actorClaimsPrincipal = tokendHandler.ValidateToken(actor, actorValidationParameters, out validatedToken);
                Assert.NotNull(claimsIdentityValidated.Actor);
                Assert.True(IdentityComparer.AreEqual<ClaimsIdentity>(claimsIdentityValidated.Actor, (actorClaimsPrincipal.Identity as ClaimsIdentity)));
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            return claimsPrincipal;
        }

        [Fact( DisplayName = "JwtSecurityTokenHandlerTests: Claim Type Mapping - Inbound and Outbound")]
        public void ClaimTypeMapping()
        {
            Dictionary<string, string> inboundClaimTypeMap = new Dictionary<string, string>(JwtSecurityTokenHandler.InboundClaimTypeMap);
            Dictionary<string, string> outboundClaimTypeMap = new Dictionary<string, string>(JwtSecurityTokenHandler.OutboundClaimTypeMap);

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
                    Assert.True(JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey(kv.Key), "Inbound short type missing: " + kv.Key);
                    Assert.True(JwtSecurityTokenHandler.InboundClaimTypeMap[kv.Key] == kv.Value, "Inbound mapping wrong: key " + kv.Key + " expected: " + JwtSecurityTokenHandler.InboundClaimTypeMap[kv.Key] + ", received: " + kv.Value);
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
                    Assert.True(JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey(kv.Key), "Inbound short type missing: '" + kv.Key + "'");
                    Assert.True(JwtSecurityTokenHandler.InboundClaimTypeMap[kv.Key] == kv.Value, "Inbound mapping wrong: key '" + kv.Key + "' expected: " + JwtSecurityTokenHandler.InboundClaimTypeMap[kv.Key] + ", received: '" + kv.Value + "'");
                }

                var handler = new JwtSecurityTokenHandler();

                List<Claim> expectedInboundClaimsMapped = new List<Claim>(
                    ClaimSets.ExpectedInClaimsIdentityUsingAllInboundShortClaimTypes(
                            IdentityUtilities.DefaultIssuer,
                            IdentityUtilities.DefaultIssuer
                            ));

                var jwt = handler.CreateToken(
                    issuer: IdentityUtilities.DefaultIssuer,
                    audience: IdentityUtilities.DefaultAudience,
                    subject: new ClaimsIdentity(
                        ClaimSets.AllInboundShortClaimTypes(
                            IdentityUtilities.DefaultIssuer,
                            IdentityUtilities.DefaultIssuer)));

                List<Claim> expectedInboundClaimsUnMapped = new List<Claim>(
                        ClaimSets.AllInboundShortClaimTypes(
                            IdentityUtilities.DefaultIssuer,
                            IdentityUtilities.DefaultIssuer
                          ));


                var validationParameters = new TokenValidationParameters
                {
                    RequireExpirationTime = false,
                    RequireSignedTokens = false,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                };

                JwtSecurityTokenHandler.InboundClaimFilter.Add("aud");
                JwtSecurityTokenHandler.InboundClaimFilter.Add("exp");
                JwtSecurityTokenHandler.InboundClaimFilter.Add("iat");
                JwtSecurityTokenHandler.InboundClaimFilter.Add("iss");
                JwtSecurityTokenHandler.InboundClaimFilter.Add("nbf");

                // ValidateToken will map claims according to the InboundClaimTypeMap
                RunClaimMappingVariation(jwt: jwt, tokenHandler: handler, validationParameters: validationParameters, expectedClaims: expectedInboundClaimsMapped, identityName: ClaimTypes.Name);

                JwtSecurityTokenHandler.InboundClaimTypeMap.Clear();
                RunClaimMappingVariation(jwt, handler, validationParameters, expectedClaims: expectedInboundClaimsUnMapped, identityName: null);

                // test that setting the NameClaimType override works.
                List<Claim> claims = new List<Claim>()
                {
                    new Claim( ClaimTypes.GivenName, "Bob", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( ClaimTypes.Spn,       "spn", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( JwtRegisteredClaimNames.Sub,   "Subject1", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( JwtRegisteredClaimNames.Prn,   "Principal1", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( JwtRegisteredClaimNames.Sub,   "Subject2", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( JwtRegisteredClaimNames.Prn,   "Principal2", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( JwtRegisteredClaimNames.Sub,   "Subject3", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                };

                jwt = new JwtSecurityToken(issuer: Issuers.GotJwt, audience: Audiences.AuthFactors, claims: claims);
                JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>()
                {
                    { JwtRegisteredClaimNames.Email,     "Mapped_" + JwtRegisteredClaimNames.Email },
                    { JwtRegisteredClaimNames.GivenName, "Mapped_" + JwtRegisteredClaimNames.GivenName },
                    { JwtRegisteredClaimNames.Prn,       "Mapped_" + JwtRegisteredClaimNames.Prn },
                    { JwtRegisteredClaimNames.Sub,       "Mapped_" + JwtRegisteredClaimNames.Sub },
                };

                List<Claim> expectedClaims = new List<Claim>()
                {
                    new Claim( JwtRegisteredClaimNames.Iss, Issuers.GotJwt, ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( JwtRegisteredClaimNames.Aud, Audiences.AuthFactors, ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( "Mapped_" + JwtRegisteredClaimNames.Email, "Bob", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( ClaimTypes.Spn,   "spn", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( "Mapped_" + JwtRegisteredClaimNames.Sub, "Subject1", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( "Mapped_" + JwtRegisteredClaimNames.Prn, ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( "Mapped_" + JwtRegisteredClaimNames.Sub, "Subject2", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( "Mapped_" + JwtRegisteredClaimNames.Prn, "Principal2", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                    new Claim( "Mapped_" + JwtRegisteredClaimNames.Sub, "Subject3", ClaimValueTypes.String, Issuers.GotJwt, Issuers.GotJwt ),
                };
            }
            finally
            {
                JwtSecurityTokenHandler.InboundClaimTypeMap = inboundClaimTypeMap;
                JwtSecurityTokenHandler.OutboundClaimTypeMap = inboundClaimTypeMap;
                JwtSecurityTokenHandler.InboundClaimFilter.Clear();
            }
        }

        private void RunClaimMappingVariation(JwtSecurityToken jwt, JwtSecurityTokenHandler tokenHandler, TokenValidationParameters validationParameters, IEnumerable<Claim> expectedClaims, string identityName)
        {
            SecurityToken validatedToken;

            ClaimsPrincipal cp = tokenHandler.ValidateToken(jwt.RawData, validationParameters, out validatedToken);
            ClaimsIdentity identity = cp.Identity as ClaimsIdentity;

            Assert.True(IdentityComparer.AreEqual(identity.Claims, expectedClaims), "identity.Claims != expectedClaims");
            Assert.Equal(identity.Name, identityName);

            // This checks that all claims that should have been mapped.
            foreach (Claim claim in identity.Claims)
            {
                // if it was mapped, make sure the shortname is found in the mapping and equals the claim.Type
                if (claim.Properties.ContainsKey(JwtSecurityTokenHandler.ShortClaimTypeProperty))
                {
                    Assert.True(JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey(claim.Properties[JwtSecurityTokenHandler.ShortClaimTypeProperty]), "!JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( claim.Properties[JwtSecurityTokenHandler.ShortClaimTypeProperty] ): " + claim.Type);
                }
                // there was no short property.
                Assert.False(JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey(claim.Type), "JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( claim.Type ), wasn't mapped claim.Type: " + claim.Type);
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
                    Assert.True(firstClaim != null, "Claim firstClaim = identity.FindFirst( claimType ), firstClaim == null. claim.Type: " + claim.Type + " claimType: " + claimType);
                }
            }
        }

        [Fact( DisplayName = "JwtSecurityTokenHandlerTests: Ensures that JwtSecurityTokenHandler defaults are as expected")]
        public void Defaults()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            Assert.True(handler.CanValidateToken, "!handler.CanValidateToken");
            Assert.True(handler.CanWriteToken, "!handler.CanWriteToken");
            Assert.True(handler.SignatureProviderFactory != null, "handler.SignatureProviderFactory == null");
            Assert.True(handler.TokenType == typeof(JwtSecurityToken), "handler.TokenType != typeof(JwtSecurityToken)");
        }

#if JWT_XML
        [Fact( DisplayName = "JwtSecurityTokenHandlerTests: : WriteXmlToken Tests")]
        public void JwtSecurityTokenHandler_WriteXmlToken()
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            StringBuilder sb = new StringBuilder();
            XmlWriter writer = XmlWriter.Create(sb);
            SamlSecurityToken samlToken = IdentityUtilities.CreateSamlSecurityToken();

            RunWriteXmlWriterVariation(writer: null, token: null, tokenHandler: tokenHandler, ee: ExpectedException.ArgumentNullException());
            RunWriteXmlWriterVariation(writer: writer, token: null, tokenHandler: tokenHandler, ee: ExpectedException.ArgumentNullException());
            RunWriteXmlWriterVariation(writer: writer, token: samlToken, tokenHandler: tokenHandler, ee: ExpectedException.ArgumentException(substringExpected: "IDX10226:"));
        }

        private void RunWriteXmlWriterVariation(XmlWriter writer, SecurityToken token, SecurityTokenHandler tokenHandler, ExpectedException ee)
        {
            try
            {
                tokenHandler.WriteToken(writer, token);
                ee.ProcessNoException();
            }
            catch(Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        [Fact( DisplayName = "CanRead Tests")]
        public void JwtSecurityTokenHandler_CanRead()
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            // XML reader
            Assert.False(RunCanReadXmlVariation(XmlReaderVariation.WithoutNS, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.False(RunCanReadXmlVariation(null, tokenHandler, ExpectedException.ArgumentNullException()));
            Assert.True(RunCanReadXmlVariation(XmlReaderVariation.JwtTokenType, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.True(RunCanReadXmlVariation(XmlReaderVariation.JwtTokenTypeAlt, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.True(RunCanReadXmlVariation(XmlReaderVariation.WithoutEncodingType, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.False(RunCanReadXmlVariation(XmlReaderVariation.WithWrongEncodingType, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.False(RunCanReadXmlVariation(XmlReaderVariation.WithWrongTokenType, tokenHandler, ExpectedException.NoExceptionExpected));

            // Encoded string
            Assert.False(RunCanReadStringVariation(null, tokenHandler, ExpectedException.ArgumentNullException()));
            Assert.False(RunCanReadStringVariation("bob", tokenHandler, ExpectedException.NoExceptionExpected));

            Assert.False(RunCanReadStringVariation(XmlReaderVariation.WithoutNSString, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.True(RunCanReadStringVariation(XmlReaderVariation.JwtTokenTypeString, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.True(RunCanReadStringVariation(XmlReaderVariation.JwtTokenTypeAltString, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.True(RunCanReadStringVariation(XmlReaderVariation.WithoutEncodingTypeString, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.False(RunCanReadStringVariation(XmlReaderVariation.WithWrongEncodingTypeString, tokenHandler, ExpectedException.NoExceptionExpected));
            Assert.False(RunCanReadStringVariation(XmlReaderVariation.WithWrongTokenTypeString, tokenHandler, ExpectedException.NoExceptionExpected));
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
#endif

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

        [Fact( DisplayName = "JwtSecurityTokenHandlerTests: Read Tokens")]
        public void Read()
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwt;
#if JWT_XML
            jwt = RunReadXmlVariation(null, tokenHandler, ExpectedException.ArgumentNullException());
            jwt = RunReadXmlVariation(XmlReaderVariation.WithWrongEncodingType, tokenHandler, ExpectedException.ArgumentException(substringExpected: "IDX10707:"));
#endif
            jwt = RunReadStringVariation(null, tokenHandler, ExpectedException.ArgumentNullException());
            jwt = RunReadStringVariation(EncodedJwts.Asymmetric_LocalSts, new JwtSecurityTokenHandler() { MaximumTokenSizeInBytes = 100 }, ExpectedException.ArgumentException(substringExpected: "IDX10209:"));
            jwt = RunReadStringVariation("SignedEncodedJwts.Asymmetric_LocalSts", tokenHandler, ExpectedException.ArgumentException(substringExpected: "IDX10708"));
            jwt = RunReadStringVariation(EncodedJwts.Asymmetric_LocalSts, tokenHandler, ExpectedException.NoExceptionExpected);
        }

#if JWT_XML
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
#endif

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

        [Fact( DisplayName = "JwtSecurityTokenHandlerTests: Validate Tokens")]
        public void ValidateToken()
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            TestUtilities.ValidateToken(null, new TokenValidationParameters(), tokenHandler, ExpectedException.ArgumentNullException());
            TestUtilities.ValidateToken(EncodedJwts.Asymmetric_LocalSts, new TokenValidationParameters(), new JwtSecurityTokenHandler() { MaximumTokenSizeInBytes = 100 }, ExpectedException.ArgumentException(substringExpected: "IDX10209:"));
            TestUtilities.ValidateToken("ValidateToken_String_Only_IllFormed", new TokenValidationParameters(), tokenHandler, ExpectedException.ArgumentException(substringExpected: "IDX10708:"));
            TestUtilities.ValidateToken("     ", new TokenValidationParameters(), tokenHandler, ExpectedException.ArgumentNullException());
            TestUtilities.ValidateToken(EncodedJwts.Asymmetric_LocalSts, null, tokenHandler, ExpectedException.ArgumentNullException());

            var tvpNoValidation =
                new TokenValidationParameters
                {
                    IssuerSigningKey = KeyingMaterial.RsaSecurityKey_2048_Public,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                };

#if JWT_XML
            TestUtilities.ValidateToken(XmlReaderVariation.JwtTokenTypeAltString,
                                        tvpNoValidation,
                                        tokenHandler,
                                        ExpectedException.NoExceptionExpected);

            TestUtilities.ValidateToken(XmlReaderVariation.JwtTokenTypeString,
                                        tvpNoValidation,
                                        tokenHandler,
                                        ExpectedException.NoExceptionExpected);

            TestUtilities.ValidateToken(XmlReaderVariation.JwtTokenTypeString,
                                        tvpNoValidation,
                                        tokenHandler,
                                        ExpectedException.NoExceptionExpected);
#endif

            JwtSecurityToken jwt = tokenHandler.CreateToken(
                IdentityUtilities.DefaultIssuer,
                IdentityUtilities.DefaultAudience,
                ClaimSets.DefaultClaimsIdentity,
                DateTime.UtcNow,
                DateTime.UtcNow + TimeSpan.FromHours(1),
                IdentityUtilities.DefaultAsymmetricSigningCredentials);


            TokenValidationParameters validationParameters =
                new TokenValidationParameters()
                {
                    IssuerSigningKey = IdentityUtilities.DefaultAsymmetricSigningKey,
                    ValidAudience = IdentityUtilities.DefaultAudience,
                    ValidIssuer = IdentityUtilities.DefaultIssuer,
                };

            TestUtilities.ValidateTokenReplay(securityToken: jwt.RawData, tokenValidator: tokenHandler, validationParameters: validationParameters);
            TestUtilities.ValidateToken(jwt.RawData, validationParameters, tokenHandler, ExpectedException.NoExceptionExpected);
            validationParameters.LifetimeValidator =
                (nb, exp, st, tvp) =>
                {
                    return false;
                };
            TestUtilities.ValidateToken(jwt.RawData, validationParameters, tokenHandler, new ExpectedException(typeExpected: typeof(SecurityTokenInvalidLifetimeException), substringExpected: "IDX10230:"));

            validationParameters.ValidateLifetime = false;
            validationParameters.LifetimeValidator = IdentityUtilities.LifetimeValidatorThrows;
            TestUtilities.ValidateToken(securityToken: jwt.RawData, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: ExpectedException.NoExceptionExpected);
        }

        [Fact( DisplayName = "JwtSecurityTokenHandlerTests: Bootstrap context is saved and is as expected")]
        public void BootstrapToken()
        {
            SecurityToken validatedToken;
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            TokenValidationParameters validationParameters = IdentityUtilities.DefaultAsymmetricTokenValidationParameters;
            validationParameters.SaveSigninToken = false;
            string jwt = IdentityUtilities.DefaultAsymmetricJwt;
            ClaimsPrincipal claimsPrincipal = tokenHandler.ValidateToken(jwt, validationParameters, out validatedToken);
            object context = (claimsPrincipal.Identity as ClaimsIdentity).BootstrapContext;
            Assert.Null(context);

            validationParameters.SaveSigninToken = true;            
            claimsPrincipal = tokenHandler.ValidateToken(jwt, validationParameters, out validatedToken);
            context = (claimsPrincipal.Identity as ClaimsIdentity).BootstrapContext;
            Assert.NotNull(context);

            //Assert.True(IdentityComparer.AreEqual(claimsPrincipal, tokenHandler.ValidateToken(context.Token, validationParameters, out validatedToken)));
        }


        [Fact( DisplayName = "JwtSecurityTokenHandlerTests: ReadToken")]
        public void ReadToken()
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

            Assert.False(handler.CanReadToken("1"), string.Format("Expected JWTSecurityTokenHandler.CanReadToken to be false"));

            expectedException = ExpectedException.ArgumentException(substringExpected: "IDX10708:");
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

        private ClaimsPrincipal RunReadTokenVariation(string securityToken, TokenValidationParameters validationParameters, JwtSecurityTokenHandler tokenHandler, ExpectedException expectedException)
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

        [Fact( DisplayName = "JwtSecurityTokenHandlerTests: Signature Validation")]
        public void SignatureValidation()
        {
            // "Security Key Identifier not found",
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            ExpectedException expectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10503:");
            TokenValidationParameters validationParameters = SignatureValidationParameters(signingKey: KeyingMaterial.X509SecurityKey_LocalSts);
            TestUtilities.ValidateToken(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "ALLParts"), validationParameters, tokenHandler, expectedException);

            // "Asymmetric_LocalSts"
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = SignatureValidationParameters(signingKey: KeyingMaterial.X509SecurityKey_LocalSts);
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_LocalSts, "ALLParts")), validationParameters, tokenHandler, expectedException);

            // "SigningKey null, SigningKeys single key",
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = SignatureValidationParameters(signingKeys: new List<SecurityKey> { KeyingMaterial.X509SecurityKey_LocalSts });
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_LocalSts, "ALLParts")), validationParameters, tokenHandler, expectedException);

            // "Asymmetric_1024"
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = SignatureValidationParameters(signingKey: KeyingMaterial.X509SecurityKey_1024);
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_1024, "ALLParts")), validationParameters, tokenHandler, expectedException);

            // Cyrano was generated from AAD 12-22-2014
            JsonWebKeySet webKeySet = new JsonWebKeySet(OpenIdConfigData.CyranoJsonWebKeySet);
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = SignatureValidationParameters(signingKeys: webKeySet.GetSigningKeys());
            TestUtilities.ValidateToken(EncodedJwts.Cyrano, validationParameters, tokenHandler, expectedException);

            // "Signature missing, just two parts",
            expectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10504:");
            validationParameters = SignatureValidationParameters(signingKey: KeyingMaterial.DefaultX509Key_Public_2048);
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "Parts-0-1")), validationParameters, tokenHandler, expectedException);

            // "SigningKey and SigningKeys both null",
            expectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10503:");
            validationParameters = SignatureValidationParameters();
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "ALLParts")), validationParameters, tokenHandler, expectedException);

            // "SigningKeys empty",
            expectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10503:");
            validationParameters = SignatureValidationParameters(signingKeys: new List<SecurityKey>());
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_LocalSts, "ALLParts")), validationParameters, tokenHandler, expectedException);

#if SymmetricKeySuport
            // "Symmetric_256"
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = SignatureValidationParameters(signingKey: KeyingMaterial.DefaultSymmetricSecurityKey_256);
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Symmetric_256, "ALLParts")), validationParameters, tokenHandler, expectedException);

            // "BinaryKey 56Bits",
            expectedException = ExpectedException.SignatureVerificationFailedException( innerTypeExpected: typeof(ArgumentOutOfRangeException), substringExpected: "IDX10503:");
            validationParameters = SignatureValidationParameters(signingKey: KeyingMaterial.DefaultSymmetricSecurityKey_256);
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "ALLParts")), validationParameters, tokenHandler, expectedException);
#endif
        }

        private static TokenValidationParameters SignatureValidationParameters(SecurityKey signingKey = null, IEnumerable<SecurityKey> signingKeys = null)
        {
            return new TokenValidationParameters()
            {
                IssuerSigningKey = signingKey,
                IssuerSigningKeys = signingKeys,
                RequireExpirationTime = false,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
            };
        }

        [Fact( DisplayName = "JwtSecurityTokenHandlerTests: Issuer Validation TVP")]
        public void IssuerValidation()
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            string jwt = (tokenHandler.CreateToken(issuer: IdentityUtilities.DefaultIssuer, audience: IdentityUtilities.DefaultAudience, signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials) as JwtSecurityToken).RawData;
            TokenValidationParameters validationParameters = new TokenValidationParameters() { IssuerSigningKey = IdentityUtilities.DefaultAsymmetricSigningKey, ValidateAudience = false, ValidateLifetime = false };
            
            // ValidateIssuer == true

            // validIssuer null, validIssuers null
            ExpectedException ee = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), substringExpected: "IDX10204");
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // no issuers
            ee = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), substringExpected: "IDX10205");
            validationParameters.ValidIssuers = new List<string>();
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // delegate ignored on virtual call
            ee = ExpectedException.NoExceptionExpected;
            validationParameters.IssuerValidator = IdentityUtilities.IssuerValidatorEcho;
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // VaidateIssuer == false
            ee = ExpectedException.NoExceptionExpected;
            validationParameters.ValidateIssuer = false;
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // no issuers should NOT fail. vaidate issuer is not needed.
            ee = ExpectedException.NoExceptionExpected;
            validationParameters.ValidIssuers = new List<string>() { "http://Simple.CertData_2049" };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // matches ValidIssuer
            validationParameters.ValidateIssuer = true;
            validationParameters.ValidIssuer = IdentityUtilities.DefaultIssuer;
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ExpectedException.NoExceptionExpected);
            
            // matches ValidIssuers
            validationParameters.ValidIssuer = null;
            validationParameters.ValidIssuers = new string[] { "http://Simple.CertData_2048", IdentityUtilities.DefaultIssuer };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ExpectedException.NoExceptionExpected);

            validationParameters.ValidateIssuer = false;
            validationParameters.IssuerValidator = IdentityUtilities.IssuerValidatorThrows;
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ExpectedException.NoExceptionExpected);
        }

        [Fact(DisplayName = "JwtSecurityTokenHandlerTests: Audience Validation")]
        public void AudienceValidation()
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            // "Jwt.Audience == null"
            TokenValidationParameters validationParameters = new TokenValidationParameters() { ValidateIssuer = false, RequireExpirationTime = false, RequireSignedTokens = false };
            ExpectedException ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208");
            string jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: null) as JwtSecurityToken).RawData;
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "jwt.Audience == EmptyString"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: string.Empty) as JwtSecurityToken).RawData;
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "jwt.Audience == whitespace"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: "    ") as JwtSecurityToken).RawData;
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "TokenValidationParameters.ValidAudience TokenValidationParameters.ValidAudiences both null"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: "http://www.GotJwt.com") as JwtSecurityToken).RawData;
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "TokenValidationParameters.ValidAudience empty, TokenValidationParameters.ValidAudiences empty"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: "http://www.GotJwt.com") as JwtSecurityToken).RawData;
            validationParameters = new TokenValidationParameters() { RequireExpirationTime = false, RequireSignedTokens = false, ValidAudience = string.Empty, ValidAudiences = new List<string>(), ValidateIssuer = false };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "TokenValidationParameters.ValidAudience whitespace, TokenValidationParameters.ValidAudiences empty"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: "http://www.GotJwt.com") as JwtSecurityToken).RawData;
            validationParameters = new TokenValidationParameters() { RequireExpirationTime = false, RequireSignedTokens = false, ValidAudience = "   ", ValidAudiences = new List<string>(), ValidateIssuer = false };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "TokenValidationParameters.ValidAudience empty, TokenValidationParameters.ValidAudience one null string"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: "http://www.GotJwt.com") as JwtSecurityToken).RawData;
            validationParameters = new TokenValidationParameters() { RequireExpirationTime = false, RequireSignedTokens = false, ValidAudience = "", ValidAudiences = new List<string>() { null }, ValidateIssuer = false };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "TokenValidationParameters.ValidAudience empty, TokenValidationParameters.ValidAudiences one empty string"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience:  "http://www.GotJwt.com") as JwtSecurityToken).RawData;
            validationParameters = new TokenValidationParameters() { RequireExpirationTime = false, RequireSignedTokens = false, ValidAudience = "", ValidAudiences = new List<string>() { string.Empty }, ValidateIssuer = false };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "TokenValidationParameters.ValidAudience string.Empty, TokenValidationParameters.ValidAudiences one string whitespace"
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214");
            jwt = (tokenHandler.CreateToken(issuer: "http://www.GotJwt.com", audience: "http://www.GotJwt.com") as JwtSecurityToken).RawData;
            validationParameters = new TokenValidationParameters() { RequireExpirationTime = false, RequireSignedTokens = false, ValidAudience = "", ValidAudiences = new List<string>() { "     " }, ValidateIssuer = false };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            validationParameters.AudienceValidator =
                (aud, token, tvp) =>
                {
                    return false;
                };

            ee = new ExpectedException(typeExpected: typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10231:");
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            validationParameters.ValidateAudience = false;
            validationParameters.AudienceValidator = IdentityUtilities.AudienceValidatorThrows;
            TestUtilities.ValidateToken(securityToken: jwt, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: ExpectedException.NoExceptionExpected);
        }
    }    
}
