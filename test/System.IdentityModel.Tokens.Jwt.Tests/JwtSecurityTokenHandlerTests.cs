//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class JwtSecurityTokenHandlerTests
    {
        [Fact]
        public void OutboundHeaderMappingInstanceTesting()
        {
            var handler1 = new JwtSecurityTokenHandler();
            var handler2 = new JwtSecurityTokenHandler();

            handler1.OutboundAlgorithmMap[SecurityAlgorithms.Aes128Encryption] = SecurityAlgorithms.EcdsaSha256;
            Assert.True(handler1.OutboundAlgorithmMap.ContainsKey(SecurityAlgorithms.Aes128Encryption));
            Assert.False(handler2.OutboundAlgorithmMap.ContainsKey(SecurityAlgorithms.Aes128Encryption));

            var header = new JwtHeader(
                new SigningCredentials(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.Aes128Encryption),
                handler1.OutboundAlgorithmMap);

            Assert.True(header.Alg == SecurityAlgorithms.EcdsaSha256);

            header = new JwtHeader(
                new SigningCredentials(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.Aes128Encryption),
                handler2.OutboundAlgorithmMap);

            Assert.True(header.Alg == SecurityAlgorithms.Aes128Encryption);
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory]
        [InlineData(SecurityAlgorithms.EcdsaSha256Signature, SecurityAlgorithms.EcdsaSha256)]
        [InlineData(SecurityAlgorithms.EcdsaSha384Signature, SecurityAlgorithms.EcdsaSha384)]
        [InlineData(SecurityAlgorithms.EcdsaSha512Signature, SecurityAlgorithms.EcdsaSha512)]
        [InlineData(SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.HmacSha256)]
        [InlineData(SecurityAlgorithms.HmacSha384Signature, SecurityAlgorithms.HmacSha384)]
        [InlineData(SecurityAlgorithms.HmacSha512Signature, SecurityAlgorithms.HmacSha512)]
        [InlineData(SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.RsaSha256)]
        [InlineData(SecurityAlgorithms.RsaSha384Signature, SecurityAlgorithms.RsaSha384)]
        [InlineData(SecurityAlgorithms.RsaSha512Signature, SecurityAlgorithms.RsaSha512)]
        [InlineData(SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.EcdsaSha256)]
        [InlineData(SecurityAlgorithms.EcdsaSha384, SecurityAlgorithms.EcdsaSha384)]
        [InlineData(SecurityAlgorithms.EcdsaSha512, SecurityAlgorithms.EcdsaSha512)]
        [InlineData(SecurityAlgorithms.HmacSha256, SecurityAlgorithms.HmacSha256)]
        [InlineData(SecurityAlgorithms.HmacSha384, SecurityAlgorithms.HmacSha384)]
        [InlineData(SecurityAlgorithms.HmacSha512, SecurityAlgorithms.HmacSha512)]
        [InlineData(SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSha256)]
        [InlineData(SecurityAlgorithms.RsaSha384, SecurityAlgorithms.RsaSha384)]
        [InlineData(SecurityAlgorithms.RsaSha512, SecurityAlgorithms.RsaSha512)]
        [InlineData(SecurityAlgorithms.Aes128Encryption, SecurityAlgorithms.Aes128Encryption)]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void OutboundHeaderMappingCreateHeader(string outboundAlgorithm, string expectedValue)
        {
            var handler = new JwtSecurityTokenHandler();
            var header = new JwtHeader(
                            new SigningCredentials(KeyingMaterial.ECDsa256Key, outboundAlgorithm),
                            handler.OutboundAlgorithmMap);

            Assert.True(header.Alg == expectedValue);
        }


#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory]
        // uncomment once - cryptoExtensibility PR is committed.
        [InlineData(SecurityAlgorithms.EcdsaSha256Signature, SecurityAlgorithms.EcdsaSha256)]
        [InlineData(SecurityAlgorithms.EcdsaSha384Signature, SecurityAlgorithms.EcdsaSha384)]
        [InlineData(SecurityAlgorithms.EcdsaSha512Signature, SecurityAlgorithms.EcdsaSha512)]
        [InlineData(SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.HmacSha256)]
        [InlineData(SecurityAlgorithms.HmacSha384Signature, SecurityAlgorithms.HmacSha384)]
        [InlineData(SecurityAlgorithms.HmacSha512Signature, SecurityAlgorithms.HmacSha512)]
        [InlineData(SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.RsaSha256)]
        [InlineData(SecurityAlgorithms.RsaSha384Signature, SecurityAlgorithms.RsaSha384)]
        [InlineData(SecurityAlgorithms.RsaSha512Signature, SecurityAlgorithms.RsaSha512)]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void OutboundHeaderMappingCreateToken(string outboundAlgorithm, string expectedValue)
        {
            var handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwt = null;

            switch (outboundAlgorithm)
            {
                case SecurityAlgorithms.EcdsaSha256Signature:
                    jwt = handler.CreateJwtSecurityToken(new SecurityTokenDescriptor { SigningCredentials = new SigningCredentials(KeyingMaterial.ECDsa256Key, outboundAlgorithm) });
                    break;
                case SecurityAlgorithms.EcdsaSha384Signature:
                    jwt = handler.CreateJwtSecurityToken(new SecurityTokenDescriptor { SigningCredentials = new SigningCredentials(KeyingMaterial.ECDsa384Key, outboundAlgorithm) });
                    break;
                case SecurityAlgorithms.EcdsaSha512Signature:
                    jwt = handler.CreateJwtSecurityToken(new SecurityTokenDescriptor { SigningCredentials = new SigningCredentials(KeyingMaterial.ECDsa521Key, outboundAlgorithm) });
                    break;

                case SecurityAlgorithms.RsaSha256Signature:
                case SecurityAlgorithms.RsaSha384Signature:
                case SecurityAlgorithms.RsaSha512Signature:
                    jwt = handler.CreateJwtSecurityToken(new SecurityTokenDescriptor { SigningCredentials = new SigningCredentials(KeyingMaterial.RsaSecurityKey_2048, outboundAlgorithm) });
                    break;

                case SecurityAlgorithms.HmacSha256Signature:
                case SecurityAlgorithms.HmacSha384Signature:
                case SecurityAlgorithms.HmacSha512Signature:
                    jwt = handler.CreateJwtSecurityToken(new SecurityTokenDescriptor { SigningCredentials = new SigningCredentials(KeyingMaterial.SymmetricSecurityKey2_256, outboundAlgorithm) });
                    break;
            }

            Assert.True(jwt.Header.Alg == expectedValue);
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ActorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ActorTests(CreateAndValidateParams cvp)
        {
            var context = new CompareContext();
            try
            {
                SecurityToken validatedToken;
                var claimsIdentity = cvp.JwtSecurityTokenHandler.ValidateToken(cvp.Jwt, cvp.TokenValidationParameters, out validatedToken).Identity as ClaimsIdentity;
                var actorIdentity = cvp.JwtSecurityTokenHandler.ValidateToken(cvp.Actor, cvp.ActorTokenValidationParameters, out validatedToken).Identity as ClaimsIdentity;
                IdentityComparer.AreEqual(claimsIdentity.Actor, actorIdentity, context);
                cvp.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                cvp.ExpectedException.ProcessException(ex, context.Diffs);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateAndValidateParams> ActorTheoryData
        {
            get
            {
                var theoryData = new TheoryData<CreateAndValidateParams>();
                var handler = new JwtSecurityTokenHandler();

                // Actor validation is true
                // Actor will be validated using validationParameters since validationsParameters.ActorValidationParameters is null
                ClaimsIdentity claimsIdentity = new ClaimsIdentity(ClaimSets.DefaultClaimsIdentity);
                claimsIdentity.AddClaim(new Claim(ClaimTypes.Actor, Default.AsymmetricJwt));
                var validationParameters = Default.AsymmetricSignTokenValidationParameters;
                validationParameters.ValidateActor = true;
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        Actor = Default.AsymmetricJwt,
                        ActorTokenValidationParameters = Default.AsymmetricSignTokenValidationParameters,
                        Case = "Test1",
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Jwt = handler.CreateEncodedJwt(Default.Issuer, Default.Audience, claimsIdentity, null, null, null, Default.AsymmetricSigningCredentials),
                        JwtSecurityTokenHandler = handler,
                        TokenValidationParameters = validationParameters
                    }
                );

                // Actor validation is true
                // Actor is signed with symmetric key
                // TokenValidationParameters.ActorValidationParameters will not find signing key
                claimsIdentity = new ClaimsIdentity(ClaimSets.DefaultClaimsIdentity);
                claimsIdentity.AddClaim(new Claim(ClaimTypes.Actor, Default.SymmetricJws));
                validationParameters = Default.AsymmetricSignTokenValidationParameters;
                validationParameters.ValidateActor = true;
                validationParameters.ActorValidationParameters = Default.AsymmetricSignTokenValidationParameters;
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        Actor = Default.SymmetricJws,
                        ActorTokenValidationParameters = Default.SymmetricEncryptSignTokenValidationParameters,
                        Case = "Test2",
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10501"),
                        Jwt = handler.CreateEncodedJwt(Default.Issuer, Default.Audience, claimsIdentity, null, null, null, Default.AsymmetricSigningCredentials),
                        JwtSecurityTokenHandler = handler,
                        TokenValidationParameters = validationParameters
                    }
                );

                // Actor validation is false
                // Actor is signed with symmetric key
                // TokenValidationParameters.ActorValidationParameters will not find signing key, but Actor should not be validated
                claimsIdentity = new ClaimsIdentity(ClaimSets.DefaultClaimsIdentity);
                claimsIdentity.AddClaim(new Claim(ClaimTypes.Actor, Default.SymmetricJws));
                validationParameters = Default.AsymmetricSignTokenValidationParameters;
                validationParameters.ValidateActor = false;
                validationParameters.ActorValidationParameters = Default.AsymmetricSignTokenValidationParameters;
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        Actor = Default.SymmetricJws,
                        ActorTokenValidationParameters = Default.SymmetricEncryptSignTokenValidationParameters,
                        Case = "Test3",
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Jwt = handler.CreateEncodedJwt(Default.Issuer, Default.Audience, claimsIdentity, null, null, null, Default.AsymmetricSigningCredentials),
                        JwtSecurityTokenHandler = handler,
                        TokenValidationParameters = validationParameters
                    }
                );

                return theoryData;
            }
        }

        [Fact]
        public void InboundOutboundClaimTypeMapping()
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
                Assert.True(JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.ContainsKey(kv.Key), "Inbound short type missing: " + kv.Key);
                Assert.True(JwtSecurityTokenHandler.DefaultInboundClaimTypeMap[kv.Key] == kv.Value, "Inbound mapping wrong: key " + kv.Key + " expected: " + JwtSecurityTokenHandler.DefaultInboundClaimTypeMap[kv.Key] + ", received: " + kv.Value);
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
                Assert.True(JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.ContainsKey(kv.Key), "Inbound short type missing: '" + kv.Key + "'");
                Assert.True(JwtSecurityTokenHandler.DefaultInboundClaimTypeMap[kv.Key] == kv.Value, "Inbound mapping wrong: key '" + kv.Key + "' expected: " + JwtSecurityTokenHandler.DefaultInboundClaimTypeMap[kv.Key] + ", received: '" + kv.Value + "'");
            }

            var handler = new JwtSecurityTokenHandler();

            List<Claim> expectedInboundClaimsMapped = new List<Claim>(
                ClaimSets.ExpectedInClaimsIdentityUsingAllInboundShortClaimTypes(
                        IdentityUtilities.DefaultIssuer,
                        IdentityUtilities.DefaultIssuer
                        ));

            var jwt = handler.CreateJwtSecurityToken(
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

            handler.InboundClaimFilter.Add("aud");
            handler.InboundClaimFilter.Add("exp");
            handler.InboundClaimFilter.Add("iat");
            handler.InboundClaimFilter.Add("iss");
            handler.InboundClaimFilter.Add("nbf");

            // ValidateToken will map claims according to the InboundClaimTypeMap
            RunClaimMappingVariation(jwt: jwt, tokenHandler: handler, validationParameters: validationParameters, expectedClaims: expectedInboundClaimsMapped, identityName: ClaimTypes.Name);

            handler.InboundClaimTypeMap.Clear();
            RunClaimMappingVariation(jwt, handler, validationParameters, expectedClaims: expectedInboundClaimsUnMapped, identityName: null);

            // test that setting the NameClaimType override works.
            List<Claim> claims = new List<Claim>()
            {
                new Claim( JwtRegisteredClaimNames.Email, "Bob", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer ),
                new Claim( ClaimTypes.Spn, "spn", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer ),
                new Claim( JwtRegisteredClaimNames.Sub, "Subject1", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer ),
                new Claim( JwtRegisteredClaimNames.Prn, "Principal1", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer ),
                new Claim( JwtRegisteredClaimNames.Sub, "Subject2", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer ),
            };


            handler = new JwtSecurityTokenHandler();
            handler.InboundClaimFilter.Add("exp");
            handler.InboundClaimFilter.Add("nbf");
            handler.InboundClaimFilter.Add("iat");
            handler.InboundClaimTypeMap = new Dictionary<string, string>()
            {
                { JwtRegisteredClaimNames.Email, "Mapped_" + JwtRegisteredClaimNames.Email },
                { JwtRegisteredClaimNames.GivenName, "Mapped_" + JwtRegisteredClaimNames.GivenName },
                { JwtRegisteredClaimNames.Prn, "Mapped_" + JwtRegisteredClaimNames.Prn },
                { JwtRegisteredClaimNames.Sub, "Mapped_" + JwtRegisteredClaimNames.Sub },
            };

            jwt = handler.CreateJwtSecurityToken(issuer: IdentityUtilities.DefaultIssuer, audience: IdentityUtilities.DefaultAudience, subject: new ClaimsIdentity(claims));

            List<Claim> expectedClaims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Iss, IdentityUtilities.DefaultIssuer, ClaimValueTypes.String, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer),
                new Claim(JwtRegisteredClaimNames.Aud, IdentityUtilities.DefaultAudience, ClaimValueTypes.String, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer),
                new Claim(ClaimTypes.Spn, "spn", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer),
            };

            Claim claim = null;
            claim = new Claim("Mapped_" + JwtRegisteredClaimNames.Email, "Bob", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer);
            claim.Properties.Add(new KeyValuePair<string, string>(JwtSecurityTokenHandler.ShortClaimTypeProperty, JwtRegisteredClaimNames.Email));
            expectedClaims.Add(claim);

            claim = new Claim("Mapped_" + JwtRegisteredClaimNames.Sub, "Subject1", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer);
            claim.Properties.Add(new KeyValuePair<string, string>(JwtSecurityTokenHandler.ShortClaimTypeProperty, JwtRegisteredClaimNames.Sub));
            expectedClaims.Add(claim);

            claim = new Claim("Mapped_" + JwtRegisteredClaimNames.Prn, "Principal1", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer);
            claim.Properties.Add(new KeyValuePair<string, string>(JwtSecurityTokenHandler.ShortClaimTypeProperty, JwtRegisteredClaimNames.Prn));
            expectedClaims.Add(claim);

            claim = new Claim("Mapped_" + JwtRegisteredClaimNames.Sub, "Subject2", ClaimValueTypes.String, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer);
            claim.Properties.Add(new KeyValuePair<string, string>(JwtSecurityTokenHandler.ShortClaimTypeProperty, JwtRegisteredClaimNames.Sub));
            expectedClaims.Add(claim);

            RunClaimMappingVariation(jwt, handler, validationParameters, expectedClaims: expectedClaims, identityName: null);
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
                    Assert.True(tokenHandler.InboundClaimTypeMap.ContainsKey(claim.Properties[JwtSecurityTokenHandler.ShortClaimTypeProperty]), "!JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( claim.Properties[JwtSecurityTokenHandler.ShortClaimTypeProperty] ): " + claim.Type);
                }
                // there was no short property.
                Assert.False(tokenHandler.InboundClaimTypeMap.ContainsKey(claim.Type), "JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( claim.Type ), wasn't mapped claim.Type: " + claim.Type);
            }

            foreach (Claim claim in jwt.Claims)
            {
                string claimType = claim.Type;

                if (tokenHandler.InboundClaimTypeMap.ContainsKey(claimType))
                {
                    claimType = tokenHandler.InboundClaimTypeMap[claim.Type];
                }

                if (!tokenHandler.InboundClaimFilter.Contains(claim.Type))
                {
                    Claim firstClaim = identity.FindFirst(claimType);
                    Assert.True(firstClaim != null, "Claim firstClaim = identity.FindFirst( claimType ), firstClaim == null. claim.Type: " + claim.Type + " claimType: " + claimType);
                }
            }
        }

        [Fact]
        public void InstanceClaimMappingAndFiltering()
        {
            // testing if one handler overrides instance claim type map of another
            JwtSecurityTokenHandler handler1 = new JwtSecurityTokenHandler();
            JwtSecurityTokenHandler handler2 = new JwtSecurityTokenHandler();
            Assert.True(handler1.InboundClaimTypeMap.Count != 0, "handler1 should not have an empty inbound claim type map");
            handler1.InboundClaimTypeMap.Clear();
            Assert.True(handler1.InboundClaimTypeMap.Count == 0, "handler1 should have an empty inbound claim type map");
            Assert.True(handler2.InboundClaimTypeMap.Count != 0, "handler2 should not have an empty inbound claim type map");

            // Setup
            var jwtClaim = new Claim("jwtClaim", "claimValue");
            var internalClaim = new Claim("internalClaim", "claimValue");
            var unwantedClaim = new Claim("unwantedClaim", "unwantedValue");
            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimFilter = new HashSet<string>();
            handler.InboundClaimTypeMap = new Dictionary<string, string>();
            handler.OutboundClaimTypeMap = new Dictionary<string, string>();

            handler.InboundClaimFilter.Add("unwantedClaim");
            handler.InboundClaimTypeMap.Add("jwtClaim", "internalClaim");
            handler.OutboundClaimTypeMap.Add("internalClaim", "jwtClaim");

            // Test outgoing
            var outgoingToken = handler.CreateJwtSecurityToken(subject: new ClaimsIdentity(new Claim[] { internalClaim }));
            var wasClaimMapped = System.Linq.Enumerable.Contains<Claim>(outgoingToken.Claims, jwtClaim, new ClaimComparer());
            Assert.True(wasClaimMapped);

            // Test incoming
            var incomingToken = handler.CreateJwtSecurityToken(issuer: "Test Issuer", subject: new ClaimsIdentity(new Claim[] { jwtClaim, unwantedClaim }));
            var validationParameters = new TokenValidationParameters
            {
                RequireSignedTokens = false,
                ValidateAudience = false,
                ValidateIssuer = false
            };
            SecurityToken token;
            var identity = handler.ValidateToken(incomingToken.RawData, validationParameters, out token);
            Assert.False(identity.HasClaim(c => c.Type == "unwantedClaim"));
            Assert.False(identity.HasClaim(c => c.Type == "jwtClaim"));
            Assert.True(identity.HasClaim("internalClaim", "claimValue"));
        }

        [Fact]
        public void Defaults()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            Assert.True(handler.CanValidateToken, "!handler.CanValidateToken");
            Assert.True(handler.CanWriteToken, "!handler.CanWriteToken");
            Assert.True(handler.TokenType == typeof(JwtSecurityToken), "handler.TokenType != typeof(JwtSecurityToken)");
            Assert.True(handler.SetDefaultTimesOnTokenCreation);
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

        [Fact]
        public void MaximumTokenSizeInBytes()
        {
            var handler = new JwtSecurityTokenHandler() { MaximumTokenSizeInBytes = 100 };
            var ee = ExpectedException.ArgumentException(substringExpected: "IDX10209:");
            try
            {
                handler.ReadToken(EncodedJwts.Asymmetric_LocalSts);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        [Fact]
        public void ValidateTokens()
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            TestUtilities.ValidateToken(null, new TokenValidationParameters(), tokenHandler, ExpectedException.ArgumentNullException());
            TestUtilities.ValidateToken(EncodedJwts.Asymmetric_LocalSts, new TokenValidationParameters(), new JwtSecurityTokenHandler() { MaximumTokenSizeInBytes = 100 }, ExpectedException.ArgumentException(substringExpected: "IDX10209:"));
            TestUtilities.ValidateToken("ValidateToken_String_Only_IllFormed", new TokenValidationParameters(), tokenHandler, ExpectedException.ArgumentException(substringExpected: "IDX10709:"));
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

            DateTime? notBefore = DateTime.UtcNow;
            DateTime? expires = DateTime.UtcNow + TimeSpan.FromHours(1);
            var jwt = tokenHandler.CreateEncodedJwt(
                IdentityUtilities.DefaultIssuer,
                IdentityUtilities.DefaultAudience,
                ClaimSets.DefaultClaimsIdentity,
                notBefore,
                expires,
                DateTime.UtcNow + TimeSpan.FromHours(1),
                IdentityUtilities.DefaultAsymmetricSigningCredentials);

            TokenValidationParameters validationParameters =
                new TokenValidationParameters()
                {
                    IssuerSigningKey = IdentityUtilities.DefaultAsymmetricSigningKey,
                    ValidAudience = IdentityUtilities.DefaultAudience,
                    ValidIssuer = IdentityUtilities.DefaultIssuer,
                };

            TestUtilities.ValidateTokenReplay(jwt, tokenHandler, validationParameters);
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ExpectedException.NoExceptionExpected);
            validationParameters.LifetimeValidator =
                (nb, exp, st, tvp) =>
                {
                    return false;
                };
            Dictionary<string, object> properties = new Dictionary<string, object>();
            notBefore = EpochTime.DateTime(EpochTime.GetIntDate(notBefore.Value.ToUniversalTime()));
            expires = EpochTime.DateTime(EpochTime.GetIntDate(expires.Value.ToUniversalTime()));
            properties.Add("NotBefore", notBefore);
            properties.Add("Expires", expires);
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, new ExpectedException(typeExpected: typeof(SecurityTokenInvalidLifetimeException), substringExpected: "IDX10230:", propertiesExpected: properties));

            // validating lifetime validator
            validationParameters.ValidateLifetime = false;
            validationParameters.LifetimeValidator = IdentityUtilities.LifetimeValidatorThrows;
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ExpectedException.NoExceptionExpected);

            // validating issuer signing key validator
            validationParameters = SignatureValidationParameters(IdentityUtilities.DefaultAsymmetricSigningKey);
            validationParameters.ValidateIssuerSigningKey = true;
            validationParameters.IssuerSigningKeyValidator = (key, token, parameters) => { return true; };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ExpectedException.NoExceptionExpected);

            properties.Clear();
            properties.Add("SigningKey", IdentityUtilities.DefaultAsymmetricSigningKey);
            validationParameters.IssuerSigningKeyValidator = (key, token, parameters) => { return false; };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ExpectedException.SecurityTokenInvalidSigningKeyException("IDX10232:", propertiesExpected: properties));

            // no keys provided
            validationParameters = SignatureValidationParameters();
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ExpectedException.SecurityTokenInvalidSignatureException("IDX10500:"));

            // user returns one key
            validationParameters.IssuerSigningKeyResolver = (token, idToken, kid, parameters) => { return new List<SecurityKey> { IdentityUtilities.DefaultAsymmetricSigningKey }; };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ExpectedException.NoExceptionExpected);

            // validating custom crypto provider factory
            validationParameters = SignatureValidationParameters(KeyingMaterial.DefaultX509Key_2048);
            validationParameters.CryptoProviderFactory = new CustomCryptoProviderFactory() { SignatureProvider = new CustomSignatureProvider(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaSha256) { VerifyResult = false } };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"));
        }

        [Fact]
        public void BootstrapContext()
        {
            SecurityToken validatedToken;
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            TokenValidationParameters validationParameters = IdentityUtilities.DefaultAsymmetricTokenValidationParameters;
            validationParameters.SaveSigninToken = false;
            string jwt = IdentityUtilities.DefaultAsymmetricJwt;
            ClaimsPrincipal claimsPrincipal = tokenHandler.ValidateToken(jwt, validationParameters, out validatedToken);
            var context = (claimsPrincipal.Identity as ClaimsIdentity).BootstrapContext as string;
            Assert.Null(context);

            validationParameters.SaveSigninToken = true;
            claimsPrincipal = tokenHandler.ValidateToken(jwt, validationParameters, out validatedToken);
            context = (claimsPrincipal.Identity as ClaimsIdentity).BootstrapContext as string;
            Assert.NotNull(context);

            Assert.True(IdentityComparer.AreEqual(claimsPrincipal, tokenHandler.ValidateToken(context, validationParameters, out validatedToken)));
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(ValidEncodedSegmentsData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void CanReadValidEncodedSegments(string testId, string jwt, ExpectedException ee)
        {
            Assert.True((new JwtSecurityTokenHandler()).CanReadToken(jwt));
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(ValidEncodedSegmentsData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadValidEncodedSegments(string testId, string jwt, ExpectedException ee)
        {
            try
            {
                (new JwtSecurityTokenHandler()).ReadToken(jwt);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        private static TheoryData<string, string, ExpectedException> ValidEncodedSegmentsData()
        {
            return JwtTestData.ValidEncodedSegmentsData();
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(InvalidNumberOfSegmentsData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadInvalidNumberOfSegments(string testId, string jwt, ExpectedException ee)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                handler.ReadJwtToken(jwt);

                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(InvalidNumberOfSegmentsData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void CanReadInvalidNumberOfSegment(string testId, string jwt, ExpectedException ee)
        {
            Assert.False((new JwtSecurityTokenHandler()).CanReadToken(jwt));
        }

        public static TheoryData<string, string, ExpectedException> InvalidNumberOfSegmentsData()
        {
            return JwtTestData.InvalidNumberOfSegmentsData("IDX10709:");
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(InvalidRegExSegmentsData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void CanReadInvalidRegExSegments(string testId, string jwt, ExpectedException ee)
        {
            Assert.False((new JwtSecurityTokenHandler()).CanReadToken(jwt));
        }

        public static TheoryData<string, string, ExpectedException> InvalidRegExSegmentsData()
        {
            return JwtTestData.InvalidRegExSegmentsData("IDX10709:");
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(InvalidEncodedSegmentsData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadInvalidEncodedSegments(string testId, string jwt, ExpectedException ee)
        {
            try
            {
                (new JwtSecurityTokenHandler()).ReadToken(jwt);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<string, string, ExpectedException> InvalidEncodedSegmentsData()
        {
            return JwtTestData.InvalidEncodedSegmentsData("IDX10709:");
        }

        [Fact]
        public void MaximumTokenSize()
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
        }

        [Fact]
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

            // "kid" is not present, but an "x5t" is present.
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = SignatureValidationParameters(signingKey: KeyingMaterial.DefaultX509Key_2048);
            JwtSecurityToken jwt =
                new JwtSecurityToken
                (
                    issuer: IdentityUtilities.DefaultIssuer,
                    audience: IdentityUtilities.DefaultAudience,
                    claims: ClaimSets.Simple(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer),
                    signingCredentials: KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
                    expires: DateTime.UtcNow + TimeSpan.FromHours(10),
                    notBefore: DateTime.UtcNow
                );
            jwt.Header[JwtHeaderParameterNames.Kid] = null;
            jwt.Header[JwtHeaderParameterNames.X5t] = KeyingMaterial.DefaultCert_2048.Thumbprint;
            TestUtilities.ValidateToken(tokenHandler.WriteToken(jwt), validationParameters, tokenHandler, expectedException);

            // "Signature missing, just two parts",
            expectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10504:");
            validationParameters = SignatureValidationParameters(signingKey: KeyingMaterial.DefaultX509Key_Public_2048);
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "Parts-0-1")), validationParameters, tokenHandler, expectedException);

            // "SigningKey and SigningKeys both null",
            expectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10500:");
            validationParameters = SignatureValidationParameters();
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "ALLParts")), validationParameters, tokenHandler, expectedException);

            // "SigningKeys empty",
            expectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10500:");
            validationParameters = SignatureValidationParameters(signingKeys: new List<SecurityKey>());
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_LocalSts, "ALLParts")), validationParameters, tokenHandler, expectedException);

            // signature missing, "ValidateSignature = true"
            expectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10504:");
            validationParameters = SignatureValidationParameters();
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_1024, "Parts-0-1")), validationParameters, tokenHandler, expectedException);

            // signature missing, ValidateSignature = false"
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters.RequireSignedTokens = false;
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_1024, "Parts-0-1")), validationParameters, tokenHandler, expectedException);

            // custom signature validator
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = SignatureValidationParameters();
            validationParameters.SignatureValidator = IdentityUtilities.SignatureValidatorReturnsTokenAsIs;
            TestUtilities.ValidateToken(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_1024, "Parts-0-1"), validationParameters, tokenHandler, expectedException);

            expectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10505:");
            validationParameters.SignatureValidator = ((token, parameters) => { return null; });
            TestUtilities.ValidateToken(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_1024, "Parts-0-1"), validationParameters, tokenHandler, expectedException);

            expectedException = ExpectedException.SecurityTokenInvalidSignatureException("SignatureValidatorThrows");
            validationParameters.RequireSignedTokens = false;
            validationParameters.SignatureValidator = IdentityUtilities.SignatureValidatorThrows;
            TestUtilities.ValidateToken(JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_1024, "Parts-0-1"), validationParameters, tokenHandler, expectedException);

            // "Symmetric_256"
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = SignatureValidationParameters(signingKey: KeyingMaterial.DefaultSymmetricSecurityKey_256);
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Symmetric_256, "ALLParts")), validationParameters, tokenHandler, expectedException);

            // "BinaryKey 56Bits",
            expectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10503:");
            validationParameters = SignatureValidationParameters(signingKey: KeyingMaterial.DefaultSymmetricSecurityKey_56);
            TestUtilities.ValidateToken((JwtTestUtilities.GetJwtParts(EncodedJwts.Symmetric_256, "ALLParts")), validationParameters, tokenHandler, expectedException);
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
                ValidateLifetime = false
            };
        }

        [Fact]
        public void IssuerValidation()
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            string jwt = (tokenHandler.CreateJwtSecurityToken(issuer: IdentityUtilities.DefaultIssuer, audience: IdentityUtilities.DefaultAudience, signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials) as JwtSecurityToken).RawData;
            TokenValidationParameters validationParameters = new TokenValidationParameters() { IssuerSigningKey = IdentityUtilities.DefaultAsymmetricSigningKey, ValidateAudience = false, ValidateLifetime = false };
            Dictionary<string, object> properties = new Dictionary<string, object>();

            // ValidateIssuer == true, validIssuer null, validIssuers null
            properties.Add("InvalidIssuer", IdentityUtilities.DefaultIssuer);
            ExpectedException ee = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), substringExpected: "IDX10204", propertiesExpected: properties);
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // no issuers
            ee = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), substringExpected: "IDX10205", propertiesExpected: properties);
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

        [Fact]
        public void AudienceValidation()
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            Dictionary<string, object> properties = new Dictionary<string, object>();
            string invalidAudience;

            // "Jwt.Audience == null"
            TokenValidationParameters validationParameters = new TokenValidationParameters() { ValidateIssuer = false, RequireExpirationTime = false, RequireSignedTokens = false };
            properties.Add("InvalidAudience", "empty");
            ExpectedException ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208", propertiesExpected: properties);
            string jwt = tokenHandler.CreateJwtSecurityToken(issuer: "http://www.GotJwt.com", audience: null).RawData;
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "jwt.Audience == EmptyString" (Empty string in the token is the same as not defined, or null)
            properties.Clear();
            properties.Add("InvalidAudience", "empty");
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208", propertiesExpected: properties);
            jwt = tokenHandler.CreateJwtSecurityToken(issuer: "http://www.GotJwt.com", audience: String.Empty).RawData;
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "jwt.Audience == whitespace"
            invalidAudience = "    ";
            properties.Clear();
            properties.Add("InvalidAudience", invalidAudience);
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208", propertiesExpected: properties);
            jwt = tokenHandler.CreateJwtSecurityToken(issuer: "http://www.GotJwt.com", audience: invalidAudience).RawData;
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "TokenValidationParameters.ValidAudience TokenValidationParameters.ValidAudiences both null"
            invalidAudience = "http://www.GotJwt.com";
            properties.Clear();
            properties.Add("InvalidAudience", invalidAudience);
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208", propertiesExpected: properties);
            jwt = tokenHandler.CreateJwtSecurityToken(issuer: "http://www.GotJwt.com", audience: invalidAudience).RawData;
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "TokenValidationParameters.ValidAudience empty, TokenValidationParameters.ValidAudiences empty"
            invalidAudience = "http://www.GotJwt.com";
            properties.Clear();
            properties.Add("InvalidAudience", invalidAudience);
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214", propertiesExpected: properties);
            jwt = tokenHandler.CreateJwtSecurityToken(issuer: "http://www.GotJwt.com", audience: invalidAudience).RawData;
            validationParameters = new TokenValidationParameters() { RequireExpirationTime = false, RequireSignedTokens = false, ValidAudience = string.Empty, ValidAudiences = new List<string>(), ValidateIssuer = false };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "TokenValidationParameters.ValidAudience whitespace, TokenValidationParameters.ValidAudiences empty"
            invalidAudience = "http://www.GotJwt.com";
            properties.Clear();
            properties.Add("InvalidAudience", invalidAudience);
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214", propertiesExpected: properties);
            jwt = tokenHandler.CreateJwtSecurityToken(issuer: "http://www.GotJwt.com", audience: invalidAudience).RawData;
            validationParameters = new TokenValidationParameters() { RequireExpirationTime = false, RequireSignedTokens = false, ValidAudience = "   ", ValidAudiences = new List<string>(), ValidateIssuer = false };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "TokenValidationParameters.ValidAudience empty, TokenValidationParameters.ValidAudience one null string"
            invalidAudience = "http://www.GotJwt.com";
            properties.Clear();
            properties.Add("InvalidAudience", invalidAudience);
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214", propertiesExpected: properties);
            jwt = tokenHandler.CreateJwtSecurityToken(issuer: "http://www.GotJwt.com", audience: invalidAudience).RawData;
            validationParameters = new TokenValidationParameters() { RequireExpirationTime = false, RequireSignedTokens = false, ValidAudience = "", ValidAudiences = new List<string>() { null }, ValidateIssuer = false };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "TokenValidationParameters.ValidAudience empty, TokenValidationParameters.ValidAudiences one empty string"
            invalidAudience = "http://www.GotJwt.com";
            properties.Clear();
            properties.Add("InvalidAudience", invalidAudience);
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214", propertiesExpected: properties);
            jwt = tokenHandler.CreateJwtSecurityToken(issuer: "http://www.GotJwt.com", audience: invalidAudience).RawData;
            validationParameters = new TokenValidationParameters() { RequireExpirationTime = false, RequireSignedTokens = false, ValidAudience = "", ValidAudiences = new List<string>() { string.Empty }, ValidateIssuer = false };
            TestUtilities.ValidateToken(jwt, validationParameters, tokenHandler, ee);

            // "TokenValidationParameters.ValidAudience string.Empty, TokenValidationParameters.ValidAudiences one string whitespace"
            invalidAudience = "http://www.GotJwt.com";
            properties.Clear();
            properties.Add("InvalidAudience", invalidAudience);
            ee = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214", propertiesExpected: properties);
            jwt = tokenHandler.CreateJwtSecurityToken(issuer: "http://www.GotJwt.com", audience: invalidAudience).RawData;
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

        class ClaimComparer : IEqualityComparer<Claim>
        {
            public bool Equals(Claim x, Claim y)
            {
                if (x.Type == y.Type && x.Value == y.Value)
                    return true;

                return false;
            }

            public int GetHashCode(Claim obj)
            {
                throw new NotImplementedException();
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(WriteTokenTheoryData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void WriteToken(WriteJwtTokenParams testParams)
        {
            try
            {
                var token = testParams.TokenHandler.WriteToken(testParams.Token);
                if (testParams.TokenType == TokenType.JWE)
                    Assert.True(token.Split('.').Length == 5);
                else
                    Assert.True(token.Split('.').Length == 3);

                testParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                testParams.EE.ProcessException(ex);
            }
        }

        public static TheoryData<WriteJwtTokenParams> WriteTokenTheoryData()
        {
            var theoryData = new TheoryData<WriteJwtTokenParams>();
            var handler = new JwtSecurityTokenHandler();

            theoryData.Add(new WriteJwtTokenParams()
            {
                EE = ExpectedException.ArgumentNullException(),
                TestId = "Test1",
                Token = null,
                TokenHandler = handler
            });

            theoryData.Add(new WriteJwtTokenParams
            {
                EE = ExpectedException.ArgumentException("IDX10706:"),
                TestId = "Test2",
                Token = new CustomSecurityToken()
            });

            theoryData.Add(new WriteJwtTokenParams
            {
                EE = ExpectedException.ArgumentException("IDX10706:"),
                TestId = "Test3",
                Token = new CustomSecurityToken()
            });

            theoryData.Add(new WriteJwtTokenParams
            {
                EE = ExpectedException.SecurityTokenEncryptionFailedException("IDX10736:"),
                TestId = "Test4",
                Token = new JwtSecurityToken(
                                new JwtHeader(Default.SymmetricSigningCredentials),
                                new JwtSecurityToken(),
                                "ey",
                                "ey",
                                "ey",
                                "ey",
                                "ey")
            });

            theoryData.Add(new WriteJwtTokenParams
            {
                EE = ExpectedException.SecurityTokenEncryptionFailedException("IDX10735:"),
                TestId = "Test5",
                Token = new JwtSecurityToken(
                                new JwtHeader(),
                                new JwtSecurityToken(),
                                "ey",
                                "ey",
                                "ey",
                                "ey",
                                "ey")
            });

            var header = new JwtHeader(Default.SymmetricSigningCredentials);
            var payload = new JwtPayload();
            theoryData.Add(new WriteJwtTokenParams
            {
                TestId = "Test6",
                Token = new JwtSecurityToken(
                    new JwtHeader(Default.SymmetricEncryptingCredentials),
                    new JwtSecurityToken(header, payload),
                    "ey",
                    "ey",
                    "ey",
                    "ey",
                    "ey"),
                TokenType = TokenType.JWE
            });

            theoryData.Add(new WriteJwtTokenParams()
            {
                TestId = "Test7",
                Token = new JwtSecurityToken(
                    new JwtHeader(Default.SymmetricSigningCredentials),
                    new JwtPayload() ),
                TokenType = TokenType.JWS
            });

            header = new JwtHeader(Default.SymmetricSigningCredentials);
            payload = new JwtPayload();
            var innerToken = new JwtSecurityToken(
                    header,
                    new JwtSecurityToken(header, payload),
                    "ey",
                    "ey",
                    "ey",
                    "ey",
                    "ey");

            theoryData.Add(new WriteJwtTokenParams
            {
                TestId = "Test8",
                Token = new JwtSecurityToken(
                        new JwtHeader(Default.SymmetricEncryptingCredentials),
                            innerToken,
                            "ey",
                            "ey",
                            "ey",
                            "ey",
                            "ey"),
                TokenType = TokenType.JWE
            });

            return theoryData;
        }
    }

    public enum TokenType
    {
        JWE,
        JWS
    }

    public class WriteJwtTokenParams
    {
        public bool ExpectSignature { get; set; } = false;

        public ExpectedException EE { get; set; } = ExpectedException.NoExceptionExpected;

        public string TestId { get; set; }

        public SecurityToken Token { get; set; }

        public JwtSecurityTokenHandler TokenHandler { get; set; } = new JwtSecurityTokenHandler();

        public TokenType TokenType { get; set; }
    }
}
