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
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class JwtSecurityTokenHandlerTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ActorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Actor(JwtTheoryData theoryData)
        {
            var context = new CompareContext();
            try
            {
                var claimsIdentity = theoryData.TokenHandler.ValidateToken(theoryData.Token, theoryData.ValidationParameters, out SecurityToken validatedToken).Identity as ClaimsIdentity;
                var actorIdentity = theoryData.TokenHandler.ValidateToken(theoryData.Actor, theoryData.ActorTokenValidationParameters, out validatedToken).Identity as ClaimsIdentity;
                IdentityComparer.AreEqual(claimsIdentity.Actor, actorIdentity, context);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context.Diffs);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JwtTheoryData> ActorTheoryData
        {
            get
            {
                var theoryData = new TheoryData<JwtTheoryData>();
                var handler = new JwtSecurityTokenHandler();

                // Actor validation is true
                // Actor will be validated using validationParameters since validationsParameters.ActorValidationParameters is null
                ClaimsIdentity claimsIdentity = new ClaimsIdentity(ClaimSets.DefaultClaimsIdentity);
                claimsIdentity.AddClaim(new Claim(ClaimTypes.Actor, Default.AsymmetricJwt));
                var validationParameters = Default.AsymmetricSignTokenValidationParameters;
                validationParameters.ValidateActor = true;
                theoryData.Add(
                    new JwtTheoryData
                    {
                        Actor = Default.AsymmetricJwt,
                        ActorTokenValidationParameters = Default.AsymmetricSignTokenValidationParameters,
                        TestId = "Test1",
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Token = handler.CreateEncodedJwt(Default.Issuer, Default.Audience, claimsIdentity, null, null, null, Default.AsymmetricSigningCredentials),
                        TokenHandler = handler,
                        ValidationParameters = validationParameters
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
                    new JwtTheoryData
                    {
                        Actor = Default.SymmetricJws,
                        ActorTokenValidationParameters = Default.SymmetricEncryptSignTokenValidationParameters,
                        TestId = "Test2",
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10501"),
                        Token = handler.CreateEncodedJwt(Default.Issuer, Default.Audience, claimsIdentity, null, null, null, Default.AsymmetricSigningCredentials),
                        TokenHandler = handler,
                        ValidationParameters = validationParameters
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
                    new JwtTheoryData
                    {
                        Actor = Default.SymmetricJws,
                        ActorTokenValidationParameters = Default.SymmetricEncryptSignTokenValidationParameters,
                        TestId = "Test3",
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Token = handler.CreateEncodedJwt(Default.Issuer, Default.Audience, claimsIdentity, null, null, null, Default.AsymmetricSigningCredentials),
                        TokenHandler = handler,
                        ValidationParameters = validationParameters
                    }
                );

                return theoryData;
            }
        }

        #pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("AudienceValidationTheoryData")]
        #pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void AudienceValidation(JwtTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.AudienceValidation", theoryData);

            try
            {
                SecurityToken securityToken;
                theoryData.TokenHandler.ValidateToken((theoryData.SecurityToken as JwtSecurityToken).RawData, theoryData.ValidationParameters, out securityToken);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<JwtTheoryData> AudienceValidationTheoryData
        {
            get
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                return new TheoryData<JwtTheoryData>
                {
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208", propertiesExpected: new Dictionary<string, object>{ { "InvalidAudience", "empty" } }),
                        TestId = "'Audience == null'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: null),
                        TokenHandler = new JwtSecurityTokenHandler(),
                        ValidationParameters = AudienceValidationParameters(null, null, null, true),
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208", propertiesExpected: new Dictionary<string, object>{ { "InvalidAudience", "empty" } }),
                        TestId = "'Audience == string.Empty'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: string.Empty),
                        TokenHandler = new JwtSecurityTokenHandler(),
                        ValidationParameters = AudienceValidationParameters(null, null, null, true),
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208", propertiesExpected: new Dictionary<string, object>{ { "InvalidAudience", "        " } }),
                        TestId = "'Audience == whitespace'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: "        "),
                        TokenHandler = new JwtSecurityTokenHandler(),
                        ValidationParameters = AudienceValidationParameters(null, null, null, true),
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214", propertiesExpected: new Dictionary<string, object>{ { "InvalidAudience", Default.Audience } }),
                        TestId = "'Audience == NotDefault.Audience'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: Default.Audience),
                        ValidationParameters = AudienceValidationParameters(NotDefault.Audience, null, null, true),
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208", propertiesExpected: new Dictionary<string, object>{ { "InvalidAudience", Default.Audience } }),
                        TestId = "'ValidAudience && ValidAudiences == null'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: Default.Audience),
                        ValidationParameters = AudienceValidationParameters(null, null, null, true),
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208", propertiesExpected: new Dictionary<string, object>{ { "InvalidAudience", Default.Audience } }),
                        TestId = "'ValidAudience empty, validAudiences empty'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: Default.Audience),
                        ValidationParameters = AudienceValidationParameters(string.Empty, new List<string>(), null, true),
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208", propertiesExpected: new Dictionary<string, object>{ { "InvalidAudience", Default.Audience } }),
                        TestId = "'ValidAudience whitespace, validAudiences empty'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: Default.Audience),
                        ValidationParameters = AudienceValidationParameters("    ", new List<string>(), null, true),
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208", propertiesExpected: new Dictionary<string, object>{ { "InvalidAudience", Default.Audience } }),
                        TestId = "'ValidAudiences one null string'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: Default.Audience),
                        ValidationParameters = AudienceValidationParameters(null, new List<string>{ (string)null }, null, true),
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208: Unable to validate audience. validationParameters.ValidAudience is null or whitespace ", propertiesExpected: new Dictionary<string, object>{ { "InvalidAudience", Default.Audience } }),
                        TestId = "'ValidAudiences == string.empty'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: Default.Audience),
                        ValidationParameters = AudienceValidationParameters(null, new List<string>{ string.Empty }, null, true),
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10208: Unable to validate audience. ", propertiesExpected: new Dictionary<string, object>{ { "InvalidAudience", Default.Audience } }),
                        TestId = "'ValidAudience string.empty, validAudiences whitespace'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: Default.Audience),
                        ValidationParameters = AudienceValidationParameters(string.Empty, new List<string>{ "    " }, null, true),
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10231", propertiesExpected: new Dictionary<string, object>{ { "InvalidAudience", Default.Audience } }),
                        TestId = "'AudienceValidator return false'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: Default.Audience),
                        ValidationParameters = AudienceValidationParameters(Default.Audience, null, ValidationDelegates.AudienceValidatorReturnsFalse, true),
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), substringExpected: $"{typeof(ValidationDelegates)}.AudienceValidatorThrows"),
                        TestId = "'AudienceValidator throws'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: Default.Audience),
                        ValidationParameters = AudienceValidationParameters(Default.Audience, null, ValidationDelegates.AudienceValidatorThrows, true),
                    },
                    new JwtTheoryData
                    {
                        TestId = "'validateAudience == false, validAudience null, validAudiences == null'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: Default.Audience),
                        ValidationParameters = AudienceValidationParameters(null, null, null, false),
                    },
                    new JwtTheoryData
                    {
                        TestId = "'validateAudience == false, AudienceValidator throws'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: Default.Audience),
                        ValidationParameters = AudienceValidationParameters(null, null, ValidationDelegates.AudienceValidatorThrows, false),
                    },
                    new JwtTheoryData
                    {
                        TestId = "'validateAudience == false, AudienceValidator return false'",
                        SecurityToken = tokenHandler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: Default.Audience),
                        ValidationParameters = AudienceValidationParameters(null, null, ValidationDelegates.AudienceValidatorReturnsFalse, false),
                    }
                };
            }
        }

        private static TokenValidationParameters AudienceValidationParameters(string validAudience, IEnumerable<string> validAudiences, AudienceValidator audienceValidator, bool validateAudience)
        {
            return new TokenValidationParameters
            {
                AudienceValidator = audienceValidator,
                RequireSignedTokens = false,
                ValidateAudience = validateAudience,
                ValidateIssuer = false,
                ValidateLifetime = false,
                ValidAudience = validAudience,
                ValidIssuers = validAudiences
            };
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("BootstrapContextTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void BootstrapContext(JwtTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.BootstrapContext", theoryData);

            var claimsPrincipal = theoryData.TokenHandler.ValidateToken(theoryData.Token, theoryData.ValidationParameters, out SecurityToken securityToken);
            var bootstrapContext = (claimsPrincipal.Identity as ClaimsIdentity).BootstrapContext as string;
            if (theoryData.ValidationParameters.SaveSigninToken)
            {
                Assert.NotNull(bootstrapContext);
                Assert.True(IdentityComparer.AreEqual(claimsPrincipal, theoryData.TokenHandler.ValidateToken(bootstrapContext, theoryData.ValidationParameters, out SecurityToken validatedToken)));
            }
            else
            {
                Assert.Null(bootstrapContext);
            }
        }

        public static TheoryData<JwtTheoryData> BootstrapContextTheoryData
        {
            get
            {
                var theoryData = new TheoryData<JwtTheoryData>();
                var validationParameters = Default.AsymmetricEncryptSignTokenValidationParameters;
                validationParameters.SaveSigninToken = true;
                theoryData.Add(new JwtTheoryData
                {
                    Token = Default.AsymmetricJwt,
                    ValidationParameters = Default.AsymmetricEncryptSignTokenValidationParameters,
                });

                validationParameters = Default.AsymmetricEncryptSignTokenValidationParameters;
                validationParameters.SaveSigninToken = false;
                theoryData.Add(new JwtTheoryData
                {
                    Token = Default.AsymmetricJwt,
                    ValidationParameters = validationParameters
                });

                return theoryData;
            }
        }

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
                        Default.Issuer,
                        Default.Issuer
                        ));

            var jwt = handler.CreateJwtSecurityToken(
                issuer: Default.Issuer,
                audience: Default.Audience,
                subject: new ClaimsIdentity(
                    ClaimSets.AllInboundShortClaimTypes(
                        Default.Issuer,
                        Default.Issuer)));

            List<Claim> expectedInboundClaimsUnMapped = new List<Claim>(
                    ClaimSets.AllInboundShortClaimTypes(
                        Default.Issuer,
                        Default.Issuer
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
                new Claim( JwtRegisteredClaimNames.Email, "Bob", ClaimValueTypes.String, Default.Issuer, Default.Issuer ),
                new Claim( ClaimTypes.Spn, "spn", ClaimValueTypes.String, Default.Issuer, Default.Issuer ),
                new Claim( JwtRegisteredClaimNames.Sub, "Subject1", ClaimValueTypes.String, Default.Issuer, Default.Issuer ),
                new Claim( JwtRegisteredClaimNames.Prn, "Principal1", ClaimValueTypes.String, Default.Issuer, Default.Issuer ),
                new Claim( JwtRegisteredClaimNames.Sub, "Subject2", ClaimValueTypes.String, Default.Issuer, Default.Issuer ),
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

            jwt = handler.CreateJwtSecurityToken(issuer: Default.Issuer, audience: Default.Audience, subject: new ClaimsIdentity(claims));

            List<Claim> expectedClaims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Iss, Default.Issuer, ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                new Claim(JwtRegisteredClaimNames.Aud, Default.Audience, ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                new Claim(ClaimTypes.Spn, "spn", ClaimValueTypes.String, Default.Issuer, Default.Issuer),
            };

            Claim claim = null;
            claim = new Claim("Mapped_" + JwtRegisteredClaimNames.Email, "Bob", ClaimValueTypes.String, Default.Issuer, Default.Issuer);
            claim.Properties.Add(new KeyValuePair<string, string>(JwtSecurityTokenHandler.ShortClaimTypeProperty, JwtRegisteredClaimNames.Email));
            expectedClaims.Add(claim);

            claim = new Claim("Mapped_" + JwtRegisteredClaimNames.Sub, "Subject1", ClaimValueTypes.String, Default.Issuer, Default.Issuer);
            claim.Properties.Add(new KeyValuePair<string, string>(JwtSecurityTokenHandler.ShortClaimTypeProperty, JwtRegisteredClaimNames.Sub));
            expectedClaims.Add(claim);

            claim = new Claim("Mapped_" + JwtRegisteredClaimNames.Prn, "Principal1", ClaimValueTypes.String, Default.Issuer, Default.Issuer);
            claim.Properties.Add(new KeyValuePair<string, string>(JwtSecurityTokenHandler.ShortClaimTypeProperty, JwtRegisteredClaimNames.Prn));
            expectedClaims.Add(claim);

            claim = new Claim("Mapped_" + JwtRegisteredClaimNames.Sub, "Subject2", ClaimValueTypes.String, Default.Issuer, Default.Issuer);
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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ValidateTokenTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ValidateToken(JwtTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateToken", theoryData);

            TestUtilities.ValidateToken(theoryData.Token, theoryData.ValidationParameters, theoryData.TokenHandler, theoryData.ExpectedException);
        }

        public static TheoryData<JwtTheoryData> ValidateTokenTheoryData
        {
            get
            {
                return new TheoryData<JwtTheoryData>
                {
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "Token: null",
                        ValidationParameters = new TokenValidationParameters()
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10209:"),
                        TestId = "Token.length > MaximumTokenSizeInBytes",
                        Token = EncodedJwts.Asymmetric_LocalSts,
                        TokenHandler = new JwtSecurityTokenHandler{ MaximumTokenSizeInBytes = 100 },
                        ValidationParameters = new TokenValidationParameters()
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10709:"),
                        TestId = "Token = Guid().NewGuid().ToString()",
                        Token = Guid.NewGuid().ToString(),
                        ValidationParameters = new TokenValidationParameters()
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "Token = '      ' (whitespace)",
                        Token = "     ",
                        ValidationParameters = new TokenValidationParameters()
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "TokenValidationParameters: null",
                        Token = EncodedJwts.Asymmetric_1024,
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJwt),
                        Token = Default.AsymmetricJwt,
                        ValidationParameters = Default.AsymmetricSignTokenValidationParameters
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.SymmetricJws),
                        Token = Default.SymmetricJws,
                        ValidationParameters = Default.SymmetricSignTokenValidationParameters
                    },
                };
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("TokenReplayValidationTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void TokenReplayValidation(TokenReplayTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.TokenReplayValidation", theoryData);
            var context = new CompareContext($"{this}.ReadKeyInfo, {theoryData.TestId}");
            var tvp = Default.AsymmetricEncryptSignTokenValidationParameters.Clone();
            tvp.TokenReplayValidator = theoryData.TokenReplayValidator;
            tvp.ValidateTokenReplay = theoryData.ValidateTokenReplay;
            var token = Default.AsymmetricJwt;
            var tokenValidator = new JwtSecurityTokenHandler();

            try
            {
                if (theoryData.TokenReplayValidator == null)
                {
                    // TokenReplayCache is used since TokenReplayValidator is not provided.
                    // This test tests TokenReplayCache.
                    TestUtilities.ValidateTokenReplay(token, tokenValidator, tvp);
                }
                else
                {
                    // TokenReplayValidator is provided.
                    // This test tests TokenReplayValidator.
                    tokenValidator.ValidateToken(token, tvp, out SecurityToken validatedToken);
                    theoryData.ExpectedException.ProcessNoException(context.Diffs);
                }
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context.Diffs);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<TokenReplayTheoryData> TokenReplayValidationTheoryData
        {
            get
            {
                return ReferenceTheoryData.TokenReplayValidationTheoryData;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("LifetimeValidationTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void LifetimeValidation(JwtTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.LifetimeValidation", theoryData);

            TestUtilities.ValidateToken(theoryData.Token, theoryData.ValidationParameters, theoryData.TokenHandler, theoryData.ExpectedException);
        }

        public static TheoryData<JwtTheoryData> LifetimeValidationTheoryData
        {
            get
            {
                return new TheoryData<JwtTheoryData>
                {
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException("IDX10230:"),
                        TestId = nameof(ValidationDelegates.LifetimeValidatorReturnsFalse),
                        Token = Default.UnsignedJwt,
                        ValidationParameters = LifetimeValidationParameters(ValidationDelegates.LifetimeValidatorReturnsFalse, true)
                    },
                    new JwtTheoryData
                    {
                        TestId = $"{nameof(ValidationDelegates.LifetimeValidatorReturnsFalse)}, ValidateLifetime: false",
                        Token = Default.UnsignedJwt,
                        ValidationParameters = LifetimeValidationParameters(ValidationDelegates.LifetimeValidatorReturnsFalse, false)
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException("IDX10230:"),
                        TestId = nameof(ValidationDelegates.LifetimeValidatorThrows),
                        Token = Default.UnsignedJwt,
                        ValidationParameters = LifetimeValidationParameters(ValidationDelegates.LifetimeValidatorReturnsFalse, true)
                    },
                    new JwtTheoryData
                    {
                        TestId = $"'{nameof(ValidationDelegates.LifetimeValidatorThrows)}, ValidateLifetime: false'",
                        Token = Default.UnsignedJwt,
                        ValidationParameters = LifetimeValidationParameters(ValidationDelegates.LifetimeValidatorThrows, false)
                    },
                };
            }
        }

        private static TokenValidationParameters LifetimeValidationParameters(LifetimeValidator lifetimeValidator, bool validateLifetime)
        {
            return new TokenValidationParameters
            {
                LifetimeValidator = lifetimeValidator,
                RequireSignedTokens = false,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = validateLifetime
            };
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(SegmentTheoryData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SegmentRead(JwtTheoryData theoryData)
        {
            try
            {
                theoryData.TokenHandler.ReadJwtToken(theoryData.Token);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(SegmentTheoryData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SegmentCanRead(JwtTheoryData theoryData)
        {
            Assert.Equal(theoryData.CanRead, theoryData.TokenHandler.CanReadToken(theoryData.Token));
        }

        public static TheoryData<JwtTheoryData> SegmentTheoryData()
        {
            var theoryData = new TheoryData<JwtTheoryData>();

            JwtTestData.InvalidRegExSegmentsData("IDX10709:", theoryData);
            JwtTestData.InvalidNumberOfSegmentsData("IDX10709:", theoryData);
            JwtTestData.InvalidEncodedSegmentsData("", theoryData);
            JwtTestData.ValidEncodedSegmentsData(theoryData);

            return theoryData;
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SignatureValidationTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SignatureValidation(JwtTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignatureValidation", theoryData);

            TestUtilities.ValidateToken(theoryData.Token, theoryData.ValidationParameters, theoryData.TokenHandler, theoryData.ExpectedException);
        }

        public static TheoryData<JwtTheoryData> SignatureValidationTheoryData
        {
            get
            {
                var theoryData = new TheoryData<JwtTheoryData>
                {
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10503:"),
                        TestId = "Security Key Identifier not found",
                        Token = JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "ALLParts"),
                        ValidationParameters = SignatureValidationParameters(KeyingMaterial.X509SecurityKey_LocalSts, null)
                    },
                    new JwtTheoryData
                    {
                        TestId = "Asymmetric_LocalSts",
                        Token = JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_LocalSts, "ALLParts"),
                        ValidationParameters = SignatureValidationParameters(KeyingMaterial.X509SecurityKey_LocalSts, null)
                    },
                    new JwtTheoryData
                    {
                        TestId = "SigningKey null, SigningKeys single key",
                        Token = JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_LocalSts, "ALLParts"),
                        ValidationParameters = SignatureValidationParameters(null, new List<SecurityKey> { KeyingMaterial.X509SecurityKey_LocalSts })
                    },
                    new JwtTheoryData
                    {
                        TestId = "Asymmetric_1024",
                        Token = JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_1024, "ALLParts"),
                        ValidationParameters = SignatureValidationParameters(KeyingMaterial.X509SecurityKey_1024, null)
                    },
                    new JwtTheoryData
                    {
                        TestId = "'kid' is missing, 'x5t' is present.",
                        Token = EncodedJwts.JwsKidNullX5t,
                        ValidationParameters = SignatureValidationParameters(KeyingMaterial.DefaultX509Key_2048, null)
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10504:"),
                        TestId = "Signature missing, required",
                        Token = JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "Parts-0-1"),
                        ValidationParameters = SignatureValidationParameters(KeyingMaterial.DefaultX509Key_Public_2048, null)
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10500:"),
                        TestId = "SigningKey and SigningKeys both null",
                        Token = JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_2048, "ALLParts"),
                        ValidationParameters = SignatureValidationParameters(null, null)
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10500:"),
                        TestId = "SigningKeys empty",
                        Token = JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_LocalSts, "ALLParts"),
                        ValidationParameters = SignatureValidationParameters(null, new List<SecurityKey>())
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10504:"),
                        TestId = "signature missing, RequireSignedTokens = true",
                        Token = JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_1024, "Parts-0-1"),
                        ValidationParameters = SignatureValidationParameters(null, null)
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        TestId = "signature missing, RequireSignedTokens = false",
                        Token = JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_1024, "Parts-0-1"),
                        ValidationParameters = SignatureValidationParameters(null, null, false)
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        TestId = "custom signature validator",
                        Token = JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_1024, "Parts-0-1"),
                        ValidationParameters = SignatureValidationParameters(null, null, true, ValidationDelegates.SignatureValidatorReturnsJwtTokenAsIs)
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10505:"),
                        TestId = "signature validator returns null",
                        Token = JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_1024, "Parts-0-1"),
                        ValidationParameters = SignatureValidationParameters(null, null, true, ValidationDelegates.SignatureValidatorReturnsNull)
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("SignatureValidatorThrows"),
                        TestId = "Signature validator throws",
                        Token = JwtTestUtilities.GetJwtParts(EncodedJwts.Asymmetric_1024, "Parts-0-1"),
                        ValidationParameters = SignatureValidationParameters(null, null, true, ValidationDelegates.SignatureValidatorThrows)
                    },
                    new JwtTheoryData
                    {
                        TestId = "EncodedJwts.Symmetric_256",
                        Token = JwtTestUtilities.GetJwtParts(EncodedJwts.Symmetric_256, "ALLParts"),
                        ValidationParameters = SignatureValidationParameters(KeyingMaterial.DefaultSymmetricSecurityKey_256, null),
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10503:"),
                        TestId = "BinaryKey 56Bits",
                        Token = JwtTestUtilities.GetJwtParts(EncodedJwts.Symmetric_256, "ALLParts"),
                        ValidationParameters = SignatureValidationParameters(KeyingMaterial.DefaultSymmetricSecurityKey_56, null),
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(ValidationDelegates.IssuerSecurityKeyValidatorReturnsTrue),
                        Token = Default.AsymmetricJwt,
                        ValidationParameters = Default.AsymmetricSignTokenValidationParameters
                    }
                };

                // TODO break IssuerSecurityKeyValidator into seperate tests.
                // User has set an IssuerSecurityKeyValidator which returns false
                var expectedException = ExpectedException.SecurityTokenInvalidSigningKeyException("IDX10232:");
                expectedException.PropertiesExpected.Add("SigningKey", Default.AsymmetricSigningKey);
                var validationParameters = Default.AsymmetricSignTokenValidationParameters;
                validationParameters.ValidateIssuerSigningKey = true;
                validationParameters.IssuerSigningKeyValidator = ValidationDelegates.IssuerSecurityKeyValidatorReturnsFalse;
                theoryData.Add(new JwtTheoryData
                {
                    ExpectedException = expectedException,
                    TestId = nameof(ValidationDelegates.IssuerSecurityKeyValidatorReturnsFalse),
                    Token = Default.AsymmetricJwt,
                    ValidationParameters = validationParameters
                });

                validationParameters = Default.AsymmetricSignTokenValidationParameters;
                validationParameters.CryptoProviderFactory = new CustomCryptoProviderFactory() { SignatureProvider = new CustomSignatureProvider(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaSha256) { VerifyResult = false } };
                theoryData.Add(new JwtTheoryData
                {
                    ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                    TestId = $"{nameof(validationParameters.CryptoProviderFactory)} : returns false",
                    Token = Default.AsymmetricJwt,
                    ValidationParameters = validationParameters
                });

                return theoryData;
            }
        }

        private static TokenValidationParameters SignatureValidationParameters(SecurityKey signingKey, IEnumerable<SecurityKey> signingKeys)
        {
            return SignatureValidationParameters(signingKey, signingKeys, true);
        }

        private static TokenValidationParameters SignatureValidationParameters(SecurityKey signingKey, IEnumerable<SecurityKey> signingKeys, bool requireSignedTokens)
        {
            return SignatureValidationParameters(signingKey, signingKeys, requireSignedTokens, null);
        }

        private static TokenValidationParameters SignatureValidationParameters(SecurityKey signingKey, IEnumerable<SecurityKey> signingKeys, bool requireSignedTokens, SignatureValidator signatureValidator)
        {
            return new TokenValidationParameters()
            {
                IssuerSigningKey = signingKey,
                IssuerSigningKeys = signingKeys,
                RequireExpirationTime = false,
                RequireSignedTokens = requireSignedTokens,
                SignatureValidator = signatureValidator,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false
            };
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("IssuerValidationTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void IssuerValidation(JwtTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.IssuerValidation", theoryData);

            TestUtilities.ValidateToken(theoryData.Token, theoryData.ValidationParameters, theoryData.TokenHandler, theoryData.ExpectedException);
        }

        public static TheoryData<JwtTheoryData> IssuerValidationTheoryData
        {
            get
            {
                var handler = new JwtSecurityTokenHandler();
                var jwt = handler.CreateEncodedJwt(Default.Issuer, Default.Audience, Default.ClaimsIdentity, null, null, null, null);
                var properties = new Dictionary<string, object>
                {
                    {"InvalidIssuer", Default.Issuer }
                };


                return new TheoryData<JwtTheoryData>
                {
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), substringExpected: "IDX10204", propertiesExpected: properties),
                        Token = jwt,
                        TestId = "ValidIssuer == null, ValidIssuers == null",
                        ValidationParameters = IssuerValidationParameters(null, null, null, true)
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), substringExpected: "IDX10205", propertiesExpected: properties),
                        TestId = "ValidIssuers = List<string>()",
                        Token = jwt,
                        ValidationParameters = IssuerValidationParameters(null, new List<string>(), null, true)
                    },
                    new JwtTheoryData
                    {
                        TestId = "NotDefault.Issuer: ValidateIssuer: false",
                        Token = jwt,
                        ValidationParameters = IssuerValidationParameters(NotDefault.Issuer, null, null, false)
                    },
                    new JwtTheoryData
                    {
                        TestId = "NotDefault.Issuers: ValidateIssuer: false",
                        Token = jwt,
                        ValidationParameters = IssuerValidationParameters(null, NotDefault.Issuers, null, false)
                    },
                    new JwtTheoryData
                    {
                        TestId = "ValidationDelegates.IssuerValidatorEcho",
                        Token = jwt,
                        ValidationParameters = IssuerValidationParameters(null, null, ValidationDelegates.IssuerValidatorEcho, true)
                    },
                    new JwtTheoryData
                    {
                        TestId = "Default.Issuer",
                        Token = jwt,
                        ValidationParameters = IssuerValidationParameters(null, Default.Issuers, null, true)
                    },
                    new JwtTheoryData
                    {
                        TestId = "Default.Issuers",
                        Token = jwt,
                        ValidationParameters = IssuerValidationParameters(null, Default.Issuers, null, true)
                    },
                    new JwtTheoryData
                    {
                        TestId = "ValidationDelegates.IssuerValidatorThrows, ValidateIssuer: false",
                        Token = jwt,
                        ValidationParameters = IssuerValidationParameters(
                            Default.Issuer,
                            Default.Issuers,
                            ValidationDelegates.IssuerValidatorThrows,
                            false)
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), "IssuerValidatorThrows"),
                        Token = jwt,
                        TestId = "ValidationDelegates.IssuerValidatorThrows, ValidateIssuer: true",
                        ValidationParameters = IssuerValidationParameters(
                            Default.Issuer,
                            Default.Issuers,
                            ValidationDelegates.IssuerValidatorThrows,
                            true)
                    },
                };

            }
        }

        private static TokenValidationParameters IssuerValidationParameters(string validIssuer, IEnumerable<string> validIssuers, IssuerValidator issuerValidator, bool validateIssuer)
        {
            return new TokenValidationParameters
            {
                IssuerValidator = issuerValidator,
                RequireSignedTokens = false,
                ValidateAudience = false,
                ValidateIssuer = validateIssuer,
                ValidateLifetime = false,
                ValidIssuer = validIssuer,
                ValidIssuers = validIssuers
            };
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
        public void WriteToken(JwtTheoryData theoryData)
        {
            try
            {
                var token = theoryData.TokenHandler.WriteToken(theoryData.SecurityToken);
                if (theoryData.TokenType == TokenType.JWE)
                    Assert.True(token.Split('.').Length == 5);
                else
                    Assert.True(token.Split('.').Length == 3);

                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<JwtTheoryData> WriteTokenTheoryData()
        {
            var theoryData = new TheoryData<JwtTheoryData>();

            theoryData.Add(new JwtTheoryData()
            {
                ExpectedException = ExpectedException.ArgumentNullException(),
                TestId = "Test1",
                SecurityToken = null
            });

            theoryData.Add(new JwtTheoryData
            {
                ExpectedException = ExpectedException.ArgumentException("IDX10706:"),
                TestId = "Test2",
                SecurityToken = new CustomSecurityToken()
            });

            theoryData.Add(new JwtTheoryData
            {
                ExpectedException = ExpectedException.ArgumentException("IDX10706:"),
                TestId = "Test3",
                SecurityToken = new CustomSecurityToken()
            });

            theoryData.Add(new JwtTheoryData
            {
                ExpectedException = ExpectedException.SecurityTokenEncryptionFailedException("IDX10736:"),
                TestId = "Test4",
                SecurityToken = new JwtSecurityToken(
                                new JwtHeader(Default.SymmetricSigningCredentials),
                                new JwtSecurityToken(),
                                "ey",
                                "ey",
                                "ey",
                                "ey",
                                "ey")
            });

            theoryData.Add(new JwtTheoryData
            {
                ExpectedException = ExpectedException.SecurityTokenEncryptionFailedException("IDX10735:"),
                TestId = "Test5",
                SecurityToken = new JwtSecurityToken(
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
            theoryData.Add(new JwtTheoryData
            {
                TestId = "Test6",
                SecurityToken = new JwtSecurityToken(
                    new JwtHeader(Default.SymmetricEncryptingCredentials),
                    new JwtSecurityToken(header, payload),
                    "ey",
                    "ey",
                    "ey",
                    "ey",
                    "ey"),
                TokenType = TokenType.JWE
            });

            theoryData.Add(new JwtTheoryData()
            {
                TestId = "Test7",
                SecurityToken = new JwtSecurityToken(
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

            theoryData.Add(new JwtTheoryData
            {
                TestId = "Test8",
                SecurityToken = new JwtSecurityToken(
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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(KeyWrapTokenTheoryData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void KeyWrapTokenTest(KeyWrapTokenTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.KeyWrapTokenTest", theoryData);

            try
            {
                var signingCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2;
                var securityTokenDescriptor = Default.SecurityTokenDescriptor(theoryData.EncryptingCredentials, signingCredentials, null);

                var handler = new JwtSecurityTokenHandler();
                var token = handler.CreateToken(securityTokenDescriptor);
                var tokenString = handler.WriteToken(token);

                var validationParameters = Default.TokenValidationParameters(theoryData.DecryptingCredentials.Key, signingCredentials.Key);
                var principal = handler.ValidateToken(tokenString, validationParameters, out var validatedToken);

                Assert.NotNull(principal);
                theoryData.ExpectedException.ProcessNoException();
            } catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<KeyWrapTokenTheoryData> KeyWrapTokenTheoryData()
        {
            var theoryData = new TheoryData<KeyWrapTokenTheoryData>();
            var handler = new JwtSecurityTokenHandler();
            var rsaOAEPEncryptingCredential = new EncryptingCredentials(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512);
            var rsaPKCS1EncryptingCredential = new EncryptingCredentials(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes256CbcHmacSha512);

            theoryData.Add(new KeyWrapTokenTheoryData
            {
                EncryptingCredentials = rsaOAEPEncryptingCredential,
                DecryptingCredentials = rsaOAEPEncryptingCredential,
                TestId = "Key wrap token test using OAEP padding"
            });

            theoryData.Add(new KeyWrapTokenTheoryData
            {
                EncryptingCredentials = rsaPKCS1EncryptingCredential,
                DecryptingCredentials = rsaPKCS1EncryptingCredential,
                TestId = "Key wrap token test using PKCS1 padding"
            });

            theoryData.Add(new KeyWrapTokenTheoryData
            {
                EncryptingCredentials = rsaPKCS1EncryptingCredential,
                DecryptingCredentials = Default.SymmetricEncryptingCredentials,
                ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException("IDX10609:"),
                TestId = "Key wrap token test using RSA to wrap but symmetric key to unwrap"
            });

            theoryData.Add(new KeyWrapTokenTheoryData
            {
                EncryptingCredentials = Default.SymmetricEncryptingCredentials,
                DecryptingCredentials = rsaPKCS1EncryptingCredential,
                ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException("IDX10609:"),
                TestId = "Key wrap token test using symmetric key to wrap but RSA to unwrap"
            });

            return theoryData;
        }
    }

    public class KeyWrapTokenTheoryData : TheoryDataBase
    {
        public EncryptingCredentials EncryptingCredentials;
        public EncryptingCredentials DecryptingCredentials;
    }

    public enum TokenType
    {
        JWE,
        JWS
    }
}
