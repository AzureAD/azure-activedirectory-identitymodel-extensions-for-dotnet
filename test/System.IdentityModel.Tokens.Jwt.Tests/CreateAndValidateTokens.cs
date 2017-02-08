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
using System.Globalization;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    public class CreateAndValidateParams
    {
        public string Actor { get; set; }

        public TokenValidationParameters ActorTokenValidationParameters { get; set; }

        public string Case { get; set; }

        public JwtSecurityToken CompareTo { get; set; }

        public ExpectedException ExpectedException { get; set; }

        public Type ExceptionType { get; set; }

        public string Jwt { get; set; }

        public JwtSecurityTokenHandler JwtSecurityTokenHandler { get; set; }

        public SecurityTokenDescriptor SecurityTokenDescriptor { get; set; }

        public TokenValidationParameters TokenValidationParameters { get; set; }
    }

    public class CreateAndValidateTokens
    {
        private static string _roleClaimTypeForDelegate = "RoleClaimTypeForDelegate";
        private static string _nameClaimTypeForDelegate = "NameClaimTypeForDelegate";

        [Fact]
        public void MultipleX5C()
        {
            List<string> errors = new List<string>();
            var handler = new JwtSecurityTokenHandler();
            var payload = new JwtPayload();
            var header = new JwtHeader();

            payload.AddClaims(ClaimSets.DefaultClaims);
            List<string> x5cs = new List<string> { "x5c1", "x5c2" };
            header.Add(JwtHeaderParameterNames.X5c, x5cs);
            var jwtToken = new JwtSecurityToken(header, payload);
            var jwt = handler.WriteToken(jwtToken);

            var validationParameters =
                new TokenValidationParameters
                {
                    RequireExpirationTime = false,
                    RequireSignedTokens = false,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                };

            SecurityToken validatedSecurityToken = null;
            var cp = handler.ValidateToken(jwt, validationParameters, out validatedSecurityToken);

            JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;
            object x5csInHeader = validatedJwt.Header[JwtHeaderParameterNames.X5c];
            if (x5csInHeader == null)
            {
                errors.Add("1: validatedJwt.Header[JwtHeaderParameterNames.X5c]");
            }
            else
            {
                var list = x5csInHeader as IEnumerable<object>;
                if (list == null)
                {
                    errors.Add("2: var list = x5csInHeader as IEnumerable<object>; is NULL.");
                }

                int num = 0;
                foreach (var str in list)
                {
                    var value = str as Newtonsoft.Json.Linq.JValue;
                    if (value != null)
                    {
                        string aud = value.Value as string;
                        if (aud != null)
                        {

                        }
                    }
                    else if (!(str is string))
                    {
                        errors.Add("3: str is not string, is: " + str.GetType());
                        errors.Add("token : " + validatedJwt.ToString());
                    }
                    num++;
                }

                if (num != x5cs.Count)
                {
                    errors.Add("4: num != x5cs.Count. num: " + num.ToString() + "x5cs.Count: " + x5cs.Count.ToString());
                }
            }

            X509SecurityKey signingKey = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256;
            X509SecurityKey validateKey = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256_Public;

            // make sure we can still validate with existing logic.
            var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256Signature);
            header = new JwtHeader(signingCredentials);
            header.Add(JwtHeaderParameterNames.X5c, x5cs);
            jwtToken = new JwtSecurityToken(header, payload);
            jwt = handler.WriteToken(jwtToken);

            validationParameters.IssuerSigningKey = validateKey;
            validationParameters.RequireSignedTokens = true;
            validatedSecurityToken = null;
            cp = handler.ValidateToken(jwt, validationParameters, out validatedSecurityToken);

            TestUtilities.AssertFailIfErrors("CreateAndValidateTokens_MultipleX5C", errors);
        }

        [Fact]
        public void MatchX5t()
        {
            X509SecurityKey signingKey = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256;
            X509SecurityKey validateKey = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256_Public;

            // Assume SigningKey.KeyId doesn't match validationParameters.IssuerSigningKey.KeyId
            signingKey.KeyId = null;
            var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256Signature);

            var header = new JwtHeader(signingCredentials);
            header.Add(JwtHeaderParameterNames.X5t, Base64UrlEncoder.Encode(KeyingMaterial.CertSelfSigned2048_SHA256.GetCertHash()));
            var payload = new JwtPayload();
            payload.AddClaims(ClaimSets.DefaultClaims);

            var jwtToken = new JwtSecurityToken(header, payload);
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(jwtToken);

            var validationParameters =
                new TokenValidationParameters
                {
                    RequireExpirationTime = false,
                    RequireSignedTokens = true,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                };
            validationParameters.IssuerSigningKey = validateKey;

            SecurityToken validatedSecurityToken = null;
            var cp = handler.ValidateToken(jwt, validationParameters, out validatedSecurityToken);

            validateKey = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA384_Public;
            validationParameters.IssuerSigningKey = validateKey;

            ExpectedException expectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:");
            try
            {
                cp = handler.ValidateToken(jwt, validationParameters, out validatedSecurityToken);
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        [Fact]
        public void EmptyToken()
        {
            var handler = new JwtSecurityTokenHandler();
            var payload = new JwtPayload();
            var header = new JwtHeader();
            var jwtToken = new JwtSecurityToken(header, payload, header.Base64UrlEncode(), payload.Base64UrlEncode(), "" );
            var jwt = handler.WriteToken(jwtToken);
            var context = new CompareContext();
            IdentityComparer.AreJwtSecurityTokensEqual(jwtToken, new JwtSecurityToken(handler.WriteToken(jwtToken)), context);
            TestUtilities.AssertFailIfErrors(context.Diffs);
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(CreationParams))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void RoundTripTokens(CreateAndValidateParams createParams)
        {
            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();
            var encodedJwt1 = handler.CreateEncodedJwt(createParams.SecurityTokenDescriptor);
            var encodedJwt2 = handler.CreateEncodedJwt(
                createParams.SecurityTokenDescriptor.Issuer,
                createParams.SecurityTokenDescriptor.Audience,
                createParams.SecurityTokenDescriptor.Subject,
                createParams.SecurityTokenDescriptor.NotBefore,
                createParams.SecurityTokenDescriptor.Expires,
                createParams.SecurityTokenDescriptor.IssuedAt,
                createParams.SecurityTokenDescriptor.SigningCredentials);
            var jwtToken1 = new JwtSecurityToken(encodedJwt1);
            var jwtToken2 = new JwtSecurityToken(encodedJwt2);
            var jwtToken3 = handler.CreateJwtSecurityToken(createParams.SecurityTokenDescriptor);
            var jwtToken4 = handler.CreateJwtSecurityToken(
                createParams.SecurityTokenDescriptor.Issuer,
                createParams.SecurityTokenDescriptor.Audience,
                createParams.SecurityTokenDescriptor.Subject,
                createParams.SecurityTokenDescriptor.NotBefore,
                createParams.SecurityTokenDescriptor.Expires,
                createParams.SecurityTokenDescriptor.IssuedAt,
                createParams.SecurityTokenDescriptor.SigningCredentials);
            var jwtToken5 = handler.CreateToken(createParams.SecurityTokenDescriptor) as JwtSecurityToken;
            var jwtToken6 = handler.CreateJwtSecurityToken(
                createParams.SecurityTokenDescriptor.Issuer,
                createParams.SecurityTokenDescriptor.Audience,
                createParams.SecurityTokenDescriptor.Subject,
                createParams.SecurityTokenDescriptor.NotBefore,
                createParams.SecurityTokenDescriptor.Expires,
                createParams.SecurityTokenDescriptor.IssuedAt,
                createParams.SecurityTokenDescriptor.SigningCredentials,
                createParams.SecurityTokenDescriptor.EncryptingCredentials);
            var encodedJwt3 = handler.WriteToken(jwtToken3);
            var encodedJwt4 = handler.WriteToken(jwtToken4);
            var encodedJwt5 = handler.WriteToken(jwtToken5);
            var encodedJwt6 = handler.WriteToken(jwtToken6);

            SecurityToken validatedJwtToken1 = null;
            var claimsPrincipal1 = handler.ValidateToken(encodedJwt1, createParams.TokenValidationParameters, out validatedJwtToken1);

            SecurityToken validatedJwtToken2 = null;
            var claimsPrincipal2 = handler.ValidateToken(encodedJwt2, createParams.TokenValidationParameters, out validatedJwtToken2);

            SecurityToken validatedJwtToken3 = null;
            var claimsPrincipal3 = handler.ValidateToken(encodedJwt3, createParams.TokenValidationParameters, out validatedJwtToken3);

            SecurityToken validatedJwtToken4 = null;
            var claimsPrincipal4 = handler.ValidateToken(encodedJwt4, createParams.TokenValidationParameters, out validatedJwtToken4);

            SecurityToken validatedJwtToken5 = null;
            var claimsPrincipal5 = handler.ValidateToken(encodedJwt5, createParams.TokenValidationParameters, out validatedJwtToken5);

            SecurityToken validatedJwtToken6 = null;
            var claimsPrincipal6 = handler.ValidateToken(encodedJwt6, createParams.TokenValidationParameters, out validatedJwtToken6);

            var context = new CompareContext();
            var localContext = new CompareContext();
            if (!IdentityComparer.AreJwtSecurityTokensEqual(jwtToken1, jwtToken2, localContext))
            {
                context.Diffs.Add("jwtToken1 != jwtToken2");
                context.Diffs.AddRange(localContext.Diffs);
            }

            localContext.Diffs.Clear();
            if (!IdentityComparer.AreJwtSecurityTokensEqual(jwtToken3, jwtToken4, localContext))
            {
                context.Diffs.Add("jwtToken3 != jwtToken4");
                context.Diffs.AddRange(localContext.Diffs);
            }

            localContext.Diffs.Clear();
            if (!IdentityComparer.AreJwtSecurityTokensEqual(jwtToken3, jwtToken5, localContext))
            {
                context.Diffs.Add("jwtToken3 != jwtToken5");
                context.Diffs.AddRange(localContext.Diffs);
            }

            localContext.Diffs.Clear();
            if (!IdentityComparer.AreEqual(validatedJwtToken1, validatedJwtToken2, localContext))
            {
                context.Diffs.Add("validatedJwtToken1 != validatedJwtToken2");
                context.Diffs.AddRange(localContext.Diffs);
            }

            localContext.Diffs.Clear();
            if (!IdentityComparer.AreEqual(validatedJwtToken1, validatedJwtToken3, localContext))
            {
                context.Diffs.Add("validatedJwtToken1 != validatedJwtToken3");
                context.Diffs.AddRange(localContext.Diffs);
            }

            localContext.Diffs.Clear();
            if (!IdentityComparer.AreEqual(validatedJwtToken1, validatedJwtToken4, localContext))
            {
                context.Diffs.Add("validatedJwtToken1 != validatedJwtToken4");
                context.Diffs.AddRange(localContext.Diffs);
            }

            localContext.Diffs.Clear();
            if (!IdentityComparer.AreEqual(validatedJwtToken1, validatedJwtToken5, localContext))
            {
                context.Diffs.Add("validatedJwtToken1 != validatedJwtToken5");
                context.Diffs.AddRange(localContext.Diffs);
            }

            localContext.Diffs.Clear();
            if (!IdentityComparer.AreEqual(validatedJwtToken1, validatedJwtToken6, localContext))
            {
                context.Diffs.Add("validatedJwtToken1 != validatedJwtToken6");
                context.Diffs.AddRange(localContext.Diffs);
            }

            localContext.Diffs.Clear();
            if (!IdentityComparer.AreClaimsPrincipalsEqual(claimsPrincipal1, claimsPrincipal2, localContext))
            {
                context.Diffs.Add("claimsPrincipal1 != claimsPrincipal2");
                context.Diffs.AddRange(localContext.Diffs);
            }

            localContext.Diffs.Clear();
            if (!IdentityComparer.AreClaimsPrincipalsEqual(claimsPrincipal1, claimsPrincipal3, localContext))
            {
                context.Diffs.Add("claimsPrincipal1 != claimsPrincipal3");
                context.Diffs.AddRange(localContext.Diffs);
            }

            localContext.Diffs.Clear();
            if (!IdentityComparer.AreClaimsPrincipalsEqual(claimsPrincipal1, claimsPrincipal4, localContext))
            {
                context.Diffs.Add("claimsPrincipal1 != claimsPrincipal4");
                context.Diffs.AddRange(localContext.Diffs);
            }

            localContext.Diffs.Clear();
            if (!IdentityComparer.AreClaimsPrincipalsEqual(claimsPrincipal1, claimsPrincipal5, localContext))
            {
                context.Diffs.Add("claimsPrincipal1 != claimsPrincipal5");
                context.Diffs.AddRange(localContext.Diffs);
            }

            localContext.Diffs.Clear();
            if (!IdentityComparer.AreClaimsPrincipalsEqual(claimsPrincipal1, claimsPrincipal6, localContext))
            {
                context.Diffs.Add("claimsPrincipal1 != claimsPrincipal6");
                context.Diffs.AddRange(localContext.Diffs);
            }

            TestUtilities.AssertFailIfErrors(string.Format(CultureInfo.InvariantCulture, "RoundTripTokens: Case '{0}'", createParams.Case), context.Diffs);
        }

        public static TheoryData<CreateAndValidateParams> CreationParams()
        {
            var theoryData = new TheoryData<CreateAndValidateParams>();
            var handler = new JwtSecurityTokenHandler();

            theoryData.Add(new CreateAndValidateParams
            {
                Case = "Test1",
                SecurityTokenDescriptor = Default.AsymmetricSignSecurityTokenDescriptor(null),
                TokenValidationParameters = Default.AsymmetricSignTokenValidationParameters,
            });

            theoryData.Add(new CreateAndValidateParams
            {
                Case = "Test2",
                SecurityTokenDescriptor = new SecurityTokenDescriptor(),
                TokenValidationParameters = new TokenValidationParameters
                {
                    RequireSignedTokens = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                    ValidateIssuer = false,
                }
            });

            theoryData.Add(new CreateAndValidateParams
            {
                Case = "Test3",
                ExceptionType = null,
                SecurityTokenDescriptor = Default.AsymmetricSignSecurityTokenDescriptor(ClaimSets.DuplicateTypes()),
                TokenValidationParameters = Default.AsymmetricSignTokenValidationParameters,
            });

            theoryData.Add(new CreateAndValidateParams
            {
                Case = "Test4",
                ExceptionType = null,
                SecurityTokenDescriptor = Default.AsymmetricSignSecurityTokenDescriptor(ClaimSets.DefaultClaims),
                TokenValidationParameters = Default.AsymmetricSignTokenValidationParameters
            });

            theoryData.Add(new CreateAndValidateParams
            {
                Case = "Test5",
                ExceptionType = null,
                SecurityTokenDescriptor = Default.SymmetricSignSecurityTokenDescriptor(ClaimSets.DefaultClaims),
                TokenValidationParameters = Default.SymmetricEncyptSignTokenValidationParameters
            });

            theoryData.Add(new CreateAndValidateParams
            {
                Case = "Test6",
                ExceptionType = null,
                SecurityTokenDescriptor = Default.SymmetricSignSecurityTokenDescriptor(ClaimSets.GetDefaultRoleClaims(handler)),
                TokenValidationParameters = Default.SymmetricEncyptSignTokenValidationParameters
            });

            return theoryData;
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(RoundTripJWEParams))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void RoundTripJWETokens(string testId, SecurityTokenDescriptor tokenDescriptor, TokenValidationParameters validationParameters, ExpectedException ee)
        {
            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();
            var jweCreatedInMemory = handler.CreateJwtSecurityToken(tokenDescriptor);
            var jweCreatedInMemory2 = handler.CreateJwtSecurityToken
                (
                tokenDescriptor.Issuer,
                tokenDescriptor.Audience,
                tokenDescriptor.Subject,
                tokenDescriptor.NotBefore,
                tokenDescriptor.Expires,
                tokenDescriptor.IssuedAt,
                tokenDescriptor.SigningCredentials,
                tokenDescriptor.EncryptingCredentials
                );
            try
            {
                SecurityToken token = null;
                var claimsPrincipal = handler.ValidateToken(jweCreatedInMemory.RawData, validationParameters, out token);
                ee.ProcessNoException();
                var outerToken = token as JwtSecurityToken;

                Assert.True(outerToken != null, "ValidateToken should not return a null token for the JWE token.");
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(outerToken, testId);

                Assert.True(outerToken.InnerToken != null, "ValidateToken should not return a null token for the inner JWE token.");
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(outerToken.InnerToken, testId);

                var context = new CompareContext();
                if (!IdentityComparer.AreEqual(jweCreatedInMemory.Payload, outerToken.Payload, context))
                    context.Diffs.Add("jweCreatedInMemory.Payload != jweValidated.Payload");

                if (!IdentityComparer.AreEqual(jweCreatedInMemory.Payload, jweCreatedInMemory2.Payload, context))
                    context.Diffs.Add("jweCreatedInMemory.Payload != jweCreatedInMemory2.Payload");

                if (!IdentityComparer.AreEqual(jweCreatedInMemory.Payload, outerToken.InnerToken.Payload, context))
                    context.Diffs.Add("jweCreatedInMemory.Payload != jweValidated.InnerToken.Payload");

                TestUtilities.AssertFailIfErrors(string.Format(CultureInfo.InvariantCulture, "RoundTripJWETokens: "), context.Diffs);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<string, SecurityTokenDescriptor, TokenValidationParameters, ExpectedException> RoundTripJWEParams()
        {
            var theoryData = new TheoryData<string, SecurityTokenDescriptor, TokenValidationParameters, ExpectedException>();

            theoryData.Add(
                "Test1",
                Default.SymmetricEncryptSignSecurityTokenDescriptor(),
                Default.SymmetricEncyptSignTokenValidationParameters,
                ExpectedException.NoExceptionExpected
            );

            theoryData.Add(
                "Test2",
                Default.SecurityTokenDescriptor(Default.SymmetricEncryptingCredentials, Default.SymmetricSigningCredentials, ClaimSets.DefaultClaims),
                Default.TokenValidationParameters(Default.SymmetricEncryptionKey256, Default.SymmetricSigningKey256),
                ExpectedException.NoExceptionExpected
            );

            var encryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256);
            theoryData.Add(
                "Test3",
                Default.SecurityTokenDescriptor(encryptingCredentials, Default.SymmetricSigningCredentials, ClaimSets.DefaultClaims),
                Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                ExpectedException.NoExceptionExpected
            );

            encryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes192CbcHmacSha384);
            theoryData.Add(
                "Test4",
                Default.SecurityTokenDescriptor(encryptingCredentials, Default.SymmetricSigningCredentials, ClaimSets.DefaultClaims),
                Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                ExpectedException.NoExceptionExpected
            );

            encryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes256CbcHmacSha512);
            theoryData.Add(
                "Test5",
                Default.SecurityTokenDescriptor(encryptingCredentials, Default.SymmetricSigningCredentials, ClaimSets.DefaultClaims),
                Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                ExpectedException.NoExceptionExpected
            );

            encryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes128CbcHmacSha256);
            theoryData.Add(
                "Test6",
                Default.SecurityTokenDescriptor(encryptingCredentials, Default.SymmetricSigningCredentials, ClaimSets.DefaultClaims),
                Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                ExpectedException.NoExceptionExpected
            );

            encryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes192CbcHmacSha384);
            theoryData.Add(
                "Test7",
                Default.SecurityTokenDescriptor(encryptingCredentials, Default.SymmetricSigningCredentials, ClaimSets.DefaultClaims),
                Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                ExpectedException.NoExceptionExpected
            );

            encryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512);
            theoryData.Add(
                "Test8",
                Default.SecurityTokenDescriptor(encryptingCredentials, Default.SymmetricSigningCredentials, ClaimSets.DefaultClaims),
                Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                ExpectedException.NoExceptionExpected
            );

            // signing key not found
            theoryData.Add(
                "Test9",
                Default.SymmetricEncryptSignSecurityTokenDescriptor(),
                new TokenValidationParameters
                {
                    IssuerSigningKey = NotDefault.SymmetricSigningKey256,
                    TokenDecryptionKey = Default.SymmetricEncryptionKey256,
                },
                ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10501:")
            );

            // encryption key not found
            theoryData.Add(
                "Test10",
                Default.SymmetricEncryptSignSecurityTokenDescriptor(),
                new TokenValidationParameters
                {
                    IssuerSigningKey = Default.SymmetricSigningKey256,
                    TokenDecryptionKey = NotDefault.SymmetricEncryptionKey,
                },
                ExpectedException.SecurityTokenDecryptionFailedException("IDX10603:")
            );

            // symmetric key wrap
            encryptingCredentials = new EncryptingCredentials(KeyingMaterial.SymmetricSecurityKey2_128, SecurityAlgorithms.Aes128KW, SecurityAlgorithms.Aes128CbcHmacSha256);
            theoryData.Add(
                "Test11",
                Default.SecurityTokenDescriptor(encryptingCredentials, Default.SymmetricSigningCredentials, ClaimSets.DefaultClaims),
                Default.TokenValidationParameters(KeyingMaterial.SymmetricSecurityKey2_128, Default.SymmetricSigningKey256),
                ExpectedException.NoExceptionExpected
            );

            encryptingCredentials = new EncryptingCredentials(Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes128CbcHmacSha256);
            theoryData.Add(
                "Test12",
                Default.SecurityTokenDescriptor(encryptingCredentials, Default.SymmetricSigningCredentials, ClaimSets.DefaultClaims),
                Default.TokenValidationParameters(Default.SymmetricEncryptionKey256, Default.SymmetricSigningKey256),
                ExpectedException.NoExceptionExpected
            );

            return theoryData;
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(CreationJWEParams))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void CreateJWETokens(string testId, string jweToken, TokenValidationParameters validationParameters, JwtPayload expectedPayload, ExpectedException ee)
        {
            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();
            try
            {
                SecurityToken token = null;
                var claimsPrincipal = handler.ValidateToken(jweToken, validationParameters, out token);
                ee.ProcessNoException();
                var outerToken = token as JwtSecurityToken;

                Assert.True(outerToken != null, "ValidateToken should not return a null token for the JWE token.");
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(outerToken, testId);

                Assert.True(outerToken.InnerToken != null, "ValidateToken should not return a null token for the inner JWE token.");
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(outerToken.InnerToken, testId);

                var context = new CompareContext();
                if (!IdentityComparer.AreEqual(outerToken.Payload, outerToken.InnerToken.Payload, context))
                    context.Diffs.Add("outerToken.Payload != outerToken.InnerToken.Payload");

                foreach(KeyValuePair<string, object> claim in expectedPayload)
                {
                    if (!outerToken.Payload.ContainsKey(claim.Key))
                    {
                        context.Diffs.Add(String.Format("expectedPayload claim {0} : {1} doesn't exist in outerToken.Payload", claim.Key, claim.Value));
                    }
                    else
                    {
                        if ((outerToken.Payload[claim.Key] != null && !outerToken.Payload[claim.Key].Equals(claim.Value)) || (outerToken.Payload[claim.Key] == null && claim.Value != null))
                        {
                            context.Diffs.Add(String.Format("expectedPayload claim {0} doesn't match in outerToken.Payload. Expected value: {1}. Outer token value: {2}", claim.Key, claim.Value, outerToken.Payload[claim.Key]));
                        }
                    }

                }

                TestUtilities.AssertFailIfErrors(string.Format(CultureInfo.InvariantCulture, "CreateJWETokens: "), context.Diffs);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<string, string, TokenValidationParameters, JwtPayload, ExpectedException> CreationJWEParams()
        {
            var theoryData = new TheoryData<string, string, TokenValidationParameters, JwtPayload, ExpectedException>();
            JwtPayload expectedPayload = new JwtPayload(ClaimSets.DefaultClaimsAsCreatedInPayload());

            theoryData.Add(
                "Test1",
                EncodedJwts.JweTest1,
                Default.SymmetricEncyptSignInfiniteLifetimeTokenValidationParameters,
                expectedPayload,
                ExpectedException.NoExceptionExpected
            );

            theoryData.Add(
                "Test2",
                EncodedJwts.JweTest2,
                Default.SymmetricEncyptSignInfiniteLifetimeTokenValidationParameters,
                expectedPayload,
                ExpectedException.NoExceptionExpected
            );

            // signing key not found
            theoryData.Add(
                "Test3",
                EncodedJwts.JweTest3,
                new TokenValidationParameters
                {
                    IssuerSigningKey = NotDefault.SymmetricSigningKey256,
                    TokenDecryptionKey = Default.SymmetricEncryptionKey256,
                    ValidateLifetime = false
                },
                expectedPayload,
                ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10501:")
            );

            // encryption key not found
            theoryData.Add(
                "Test4",
                EncodedJwts.JweTest4,
                new TokenValidationParameters
                {
                    IssuerSigningKey = Default.SymmetricSigningKey256,
                    TokenDecryptionKey = NotDefault.SymmetricEncryptionKey,
                    ValidateLifetime = false
                },
                expectedPayload,
                ExpectedException.SecurityTokenDecryptionFailedException("IDX10603:")
            );

            return theoryData;
        }

        [Fact]
        public void CreateTokenNegativeCases()
        {
            var errors = new List<string>();
            var handler = new JwtSecurityTokenHandler();
            var ee = ExpectedException.ArgumentNullException("tokenDescriptor");

            try
            {
                handler.CreateEncodedJwt((SecurityTokenDescriptor)null);
                ee.ProcessNoException(errors);
            }
            catch(Exception ex)
            {
                ee.ProcessException(ex, errors);
            }

            try
            {
                handler.CreateJwtSecurityToken((SecurityTokenDescriptor)null);
                ee.ProcessNoException(errors);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, errors);
            }

            try
            {
                handler.CreateToken((SecurityTokenDescriptor)null);
                ee.ProcessNoException(errors);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, errors);
            }

            TestUtilities.AssertFailIfErrors(errors);
        }

        [Fact]
        public void InboundFilterTest()
        {
            var handler = new JwtSecurityTokenHandler();
            handler.OutboundClaimTypeMap.Clear();
            var claims = ClaimSets.DefaultClaims;

            string encodedJwt = handler.CreateEncodedJwt(IdentityUtilities.DefaultAsymmetricSecurityTokenDescriptor(claims));
            handler.InboundClaimTypeMap.Clear();
            handler.InboundClaimFilter.Add("aud");
            handler.InboundClaimFilter.Add("exp");
            handler.InboundClaimFilter.Add("iat");
            handler.InboundClaimFilter.Add("iss");
            handler.InboundClaimFilter.Add("nbf");

            SecurityToken validatedToken;
            ClaimsPrincipal claimsPrincipal = handler.ValidateToken(encodedJwt, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, out validatedToken);
            var context = new CompareContext();
            IdentityComparer.AreEqual(claimsPrincipal.Claims, claims, context);
            TestUtilities.AssertFailIfErrors(context.Diffs);
        }

        [Fact]
        public void ClaimSourceAndClaimName()
        {
            string claimSources = "_claim_sources";
            string claimNames = "_claim_names";
            var context = new CompareContext();

            JwtPayload payload = new JwtPayload();
            payload.Add(claimSources, JsonClaims.ClaimSourcesAsDictionary);
            payload.Add(claimNames, JsonClaims.ClaimNamesAsDictionary);
            payload.Add("iss", IdentityUtilities.DefaultIssuer);

            JwtSecurityToken jwtToken = new JwtSecurityToken(new JwtHeader(), payload);
            JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();
            string encodedJwt = jwtHandler.WriteToken(new JwtSecurityToken(new JwtHeader(), payload));
            var validationParameters = new TokenValidationParameters
            {
                IssuerValidator = (issuer, st, tvp) => { return issuer;},
                RequireSignedTokens = false,
                ValidateAudience = false,
                ValidateLifetime = false,
            };

            SecurityToken validatedJwt = null;
            var claimsPrincipal = jwtHandler.ValidateToken(encodedJwt, validationParameters, out validatedJwt);
            var expectedIdentity = JsonClaims.ClaimsIdentityDistributedClaims(
                IdentityUtilities.DefaultIssuer,
                TokenValidationParameters.DefaultAuthenticationType,
                JsonClaims.ClaimSourcesAsDictionary,
                JsonClaims.ClaimNamesAsDictionary);
            IdentityComparer.AreEqual(claimsPrincipal.Identity as ClaimsIdentity, expectedIdentity, context);

            jwtToken = new JwtSecurityToken( new JwtHeader(), new JwtPayload(IdentityUtilities.DefaultIssuer, null, ClaimSets.EntityAsJsonClaim(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer), null, null));
            encodedJwt = jwtHandler.WriteToken(jwtToken);
            SecurityToken validatedToken;
            var cp = jwtHandler.ValidateToken(encodedJwt, validationParameters, out validatedToken);
            IdentityComparer.AreEqual(
                cp.FindFirst(typeof(Entity).ToString()),
                new Claim(typeof(Entity).ToString(), JsonExtensions.SerializeToJson(Entity.Default), JsonClaimValueTypes.Json, IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer, cp.Identity as ClaimsIdentity ),
                context);
            TestUtilities.AssertFailIfErrors(context.Diffs);
        }

        [Fact]
        public void RoleClaims()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                RequireSignedTokens = false,
                ValidateAudience = false,
                ValidateIssuer = false
            };

            DateTime utcNow = DateTime.UtcNow;
            DateTime expire = utcNow + TimeSpan.FromHours(1);
            ClaimsIdentity subject = new ClaimsIdentity(claims: ClaimSets.GetDefaultRoleClaims(null));
            JwtSecurityToken jwtToken = handler.CreateJwtSecurityToken(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultAudience, subject, utcNow, expire, utcNow);

            SecurityToken securityToken;
            ClaimsPrincipal principal = handler.ValidateToken(jwtToken.RawData, validationParameters, out securityToken);
            CheckForRoles(ClaimSets.GetDefaultRoles(), new string[] { Guid.NewGuid().ToString(), Guid.NewGuid().ToString() }, principal);
            ClaimsIdentity expectedIdentity =
                new ClaimsIdentity(
                    authenticationType: "Federation",
                    claims: ClaimSets.GetDefaultRoleClaims(handler)
                    );

            expectedIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Iss, IdentityUtilities.DefaultIssuer, ClaimValueTypes.String, IdentityUtilities.DefaultIssuer));
            expectedIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Aud, IdentityUtilities.DefaultAudience, ClaimValueTypes.String, IdentityUtilities.DefaultIssuer));
            expectedIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(expire).ToString(), ClaimValueTypes.Integer, IdentityUtilities.DefaultIssuer));
            expectedIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(utcNow).ToString(), ClaimValueTypes.Integer, IdentityUtilities.DefaultIssuer));
            expectedIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(utcNow).ToString(), ClaimValueTypes.Integer, IdentityUtilities.DefaultIssuer));

            CompareContext context = new CompareContext();
            IdentityComparer.AreEqual(principal.Claims, expectedIdentity.Claims, context);
            TestUtilities.AssertFailIfErrors(GetType().ToString()+".RoleClaims", context.Diffs);
        }

        private static string NameClaimTypeDelegate(SecurityToken jwt, string issuer)
        {
            return _nameClaimTypeForDelegate;
        }

        private static string RoleClaimTypeDelegate(SecurityToken jwt, string issuer)
        {
            return _roleClaimTypeForDelegate;
        }

        [Fact]
        public void NameAndRoleClaimDelegates()
        {
            string defaultName = "defaultName";
            string defaultRole = "defaultRole";
            string delegateName = "delegateName";
            string delegateRole = "delegateRole";
            string validationParameterName = "validationParameterName";
            string validationParameterRole = "validationParameterRole";
            string validationParametersNameClaimType = "validationParametersNameClaimType";
            string validationParametersRoleClaimType = "validationParametersRoleClaimType";

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = KeyingMaterial.DefaultX509Key_2048,
                NameClaimType = validationParametersNameClaimType,
                RoleClaimType = validationParametersRoleClaimType,
                ValidateAudience = false,
                ValidateIssuer = false,
            };

            ClaimsIdentity subject =
                new ClaimsIdentity(
                    new List<Claim> 
                    {   new Claim(_nameClaimTypeForDelegate, delegateName), 
                        new Claim(validationParametersNameClaimType, validationParameterName), 
                        new Claim(ClaimsIdentity.DefaultNameClaimType, defaultName), 
                        new Claim(_roleClaimTypeForDelegate, delegateRole),
                        new Claim(validationParametersRoleClaimType, validationParameterRole), 
                        new Claim(ClaimsIdentity.DefaultRoleClaimType, defaultRole), 
                    });

            JwtSecurityToken jwt = handler.CreateJwtSecurityToken(issuer: "https://gotjwt.com", signingCredentials: KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2, subject: subject) as JwtSecurityToken;

            // Delegates should override any other settings
            validationParameters.NameClaimTypeRetriever = NameClaimTypeDelegate;
            validationParameters.RoleClaimTypeRetriever = RoleClaimTypeDelegate;

            SecurityToken validatedToken;
            ClaimsPrincipal principal = handler.ValidateToken(jwt.RawData, validationParameters, out validatedToken);
            CheckNamesAndRole(new string[] { delegateName, defaultName, validationParameterName }, new string[] { delegateRole, defaultRole, validationParameterRole }, principal, _nameClaimTypeForDelegate, _roleClaimTypeForDelegate);

            // Set delegates to null will use TVP values
            validationParameters.NameClaimTypeRetriever = null;
            validationParameters.RoleClaimTypeRetriever = null;
            principal = handler.ValidateToken(jwt.RawData, validationParameters, out validatedToken);
            CheckNamesAndRole(new string[] { validationParameterName, defaultName, delegateName }, new string[] { validationParameterRole, defaultRole, delegateRole }, principal, validationParametersNameClaimType, validationParametersRoleClaimType);

            // check for defaults
            validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = KeyingMaterial.DefaultX509Key_2048,
                ValidateAudience = false,
                ValidateIssuer = false,
            };

            principal = handler.ValidateToken(jwt.RawData, validationParameters, out validatedToken);
            CheckNamesAndRole(new string[] { defaultName, validationParameterName, delegateName }, new string[] { defaultRole, validationParameterRole, delegateRole }, principal);
        }

        /// <summary>
        /// First string is expected, others are not.
        /// </summary>
        /// <param name="names"></param>
        /// <param name="roles"></param>
        private void CheckNamesAndRole(string[] names, string[] roles, ClaimsPrincipal principal, string expectedNameClaimType = ClaimsIdentity.DefaultNameClaimType, string expectedRoleClaimType = ClaimsIdentity.DefaultRoleClaimType)
        {
            ClaimsIdentity identity = principal.Identity as ClaimsIdentity;
            Assert.Equal(identity.NameClaimType, expectedNameClaimType);
            Assert.Equal(identity.RoleClaimType, expectedRoleClaimType);
            Assert.True(principal.IsInRole(roles[0]));
            for (int i = 1; i < roles.Length; i++)
            {
                Assert.False(principal.IsInRole(roles[i]));
            }

            Assert.Equal(identity.Name, names[0]);
            for (int i = 1; i < names.Length; i++)
            {
                Assert.NotEqual(identity.Name, names[i]);
            }
        }

        /// <summary>
        /// First role is expected, others are not.
        /// </summary>
        /// <param name="names"></param>
        /// <param name="roles"></param>
        private void CheckForRoles(IEnumerable<string> expectedRoles, IEnumerable<string> unexpectedRoles, ClaimsPrincipal principal, string expectedRoleClaimType = ClaimsIdentity.DefaultRoleClaimType)
        {
            ClaimsIdentity identity = principal.Identity as ClaimsIdentity;
            Assert.Equal(identity.RoleClaimType, expectedRoleClaimType);
            foreach (var role in expectedRoles)
            {
                Assert.True(principal.IsInRole(role));
            }

            foreach (var role in unexpectedRoles)
            {
                Assert.False(principal.IsInRole(role));
            }
        }
    }
}
