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

using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.IdentityModel.Tokens.Jwt.Tests;
using System.IO;
using System.Security.Claims;
using System.Text;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerTests
    {
        [Theory, MemberData(nameof(SegmentTheoryData))]
        public void SegmentCanRead(JwtTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.SegmentCanRead", theoryData);

            var handler = new JsonWebTokenHandler();
            if (theoryData.CanRead != handler.CanReadToken(theoryData.Token))
                context.Diffs.Add($"theoryData.CanRead != handler.CanReadToken(theoryData.Token))");

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JwtTheoryData> SegmentTheoryData()
        {
            var theoryData = new TheoryData<JwtTheoryData>();

            JwtTestData.InvalidRegExSegmentsData(theoryData);
            JwtTestData.InvalidNumberOfSegmentsData("IDX14110:", theoryData);
            JwtTestData.InvalidEncodedSegmentsData("", theoryData);
            JwtTestData.ValidEncodedSegmentsData(theoryData);

            return theoryData;
        }

        // Tests checks to make sure that the token string created by the JsonWebTokenHandler is consistent with the 
        // token string created by the JwtSecurityTokenHandler.
        [Theory, MemberData(nameof(CreateJWETheoryData))]
        public void CreateJWE(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateJWE", theoryData);
            try
            {
                string jweFromJwtHandler = theoryData.JwtSecurityTokenHandler.CreateEncodedJwt(theoryData.TokenDescriptor);
                string jweFromJsonHandler = theoryData.JsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.TokenDescriptor.SigningCredentials, theoryData.TokenDescriptor.EncryptingCredentials);

                theoryData.JwtSecurityTokenHandler.ValidateToken(jweFromJwtHandler, theoryData.ValidationParameters, out SecurityToken validatedTokenFromJwtHandler);
                var validationResult = theoryData.JsonWebTokenHandler.ValidateToken(jweFromJsonHandler, theoryData.ValidationParameters);
                var validatedTokenFromJsonHandler = validationResult.SecurityToken;
                var validationResult2 = theoryData.JsonWebTokenHandler.ValidateToken(jweFromJwtHandler, theoryData.ValidationParameters);
                IdentityComparer.AreEqual((validatedTokenFromJwtHandler as JwtSecurityToken).Claims, (validatedTokenFromJsonHandler as JsonWebToken).Claims, context);

                theoryData.ExpectedException.ProcessNoException(context);
                context.PropertiesToIgnoreWhenComparing = new Dictionary<Type, List<string>>
                {
                    { typeof(JsonWebToken), new List<string> { "EncodedToken", "AuthenticationTag", "Ciphertext", "InitializationVector" } },
                };

                IdentityComparer.AreEqual(validationResult2.SecurityToken as JsonWebToken, validationResult.SecurityToken as JsonWebToken, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }


        public static TheoryData<CreateTokenTheoryData> CreateJWETheoryData
        {
            get
            {
                var tokenHandler = new JwtSecurityTokenHandler
                {
                    SetDefaultTimesOnTokenCreation = false
                };

                tokenHandler.InboundClaimTypeMap.Clear();

                return new TheoryData<CreateTokenTheoryData>
                {
                    new CreateTokenTheoryData
                    {
                        First = true,
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                            Subject = new ClaimsIdentity(Default.PayloadClaims),
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        JwtSecurityTokenHandler = tokenHandler,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        }
                    },
                };
            }
        }

        // Tests checks to make sure that the token string created by the JsonWebTokenHandler is consistent with the 
        // token string created by the JwtSecurityTokenHandler.
        [Theory, MemberData(nameof(CreateJWSTheoryData))]
        public void CreateJWS(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateJWS", theoryData);
            try
            {
                string jwsFromJwtHandler = theoryData.JwtSecurityTokenHandler.CreateEncodedJwt(theoryData.TokenDescriptor);
                string jwsFromJsonHandler = theoryData.JsonWebTokenHandler.CreateToken(theoryData.Payload, KeyingMaterial.JsonWebKeyRsa256SigningCredentials);

                theoryData.JwtSecurityTokenHandler.ValidateToken(jwsFromJwtHandler, theoryData.ValidationParameters, out SecurityToken validatedToken);
                theoryData.JsonWebTokenHandler.ValidateToken(jwsFromJsonHandler, theoryData.ValidationParameters);

                theoryData.ExpectedException.ProcessNoException(context);
                var jwsTokenFromJwtHandler = new JsonWebToken(jwsFromJwtHandler);
                var jwsTokenFromHandler = new JsonWebToken(jwsFromJsonHandler);
                IdentityComparer.AreEqual(jwsTokenFromJwtHandler, jwsTokenFromHandler, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }


        public static TheoryData<CreateTokenTheoryData> CreateJWSTheoryData
        {
            get
            {
                var tokenHandler = new JwtSecurityTokenHandler
                {
                    SetDefaultTimesOnTokenCreation = false
                };

                tokenHandler.InboundClaimTypeMap.Clear();

                return new TheoryData<CreateTokenTheoryData>
                {
                    new CreateTokenTheoryData
                    {
                        First = true,
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Subject = new ClaimsIdentity(Default.PayloadClaims)
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        JwtSecurityTokenHandler = tokenHandler,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        }
                    },
                };
            }
        }

        // Test checks to make sure that the token payload retrieved from ValidateToken is the same as the payload
        // the token was initially created with. 
        [Fact]
        public void RoundTripJWS()
        {
            TestUtilities.WriteHeader($"{this}.RoundTripToken");
            var context = new CompareContext();

            var tokenHandler = new JsonWebTokenHandler();
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = Default.Audience,
                ValidIssuer = Default.Issuer,
                IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
            };

            string jwtString = tokenHandler.CreateToken(Default.PayloadString, KeyingMaterial.JsonWebKeyRsa256SigningCredentials);
            var tokenValidationResult = tokenHandler.ValidateToken(jwtString, tokenValidationParameters);
            var validatedToken = tokenValidationResult.SecurityToken as JsonWebToken;
            IdentityComparer.AreEqual(Default.Payload, validatedToken.Payload, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(RoundTripJWEDirectEncryptionTheoryData))]
        public void RoundTripJWEDirectEncryption(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.RoundTripJWE", theoryData);
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var jweCreatedInMemory = jsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.SigningCredentials, theoryData.EncryptingCredentials);
            var jweCreatedInMemoryToken = new JsonWebToken(jweCreatedInMemory);
            try
            {
                var tokenValidationResult = jsonWebTokenHandler.ValidateToken(jweCreatedInMemory, theoryData.ValidationParameters);
                var outerToken = tokenValidationResult.SecurityToken as JsonWebToken;
                jwtSecurityTokenHandler.ValidateToken(jweCreatedInMemory, theoryData.ValidationParameters, out SecurityToken validatedTokenFromJwtHandler);

                IdentityComparer.AreEqual((validatedTokenFromJwtHandler as JwtSecurityToken).Claims, outerToken.Claims, context);

                Assert.True(outerToken != null, "ValidateToken should not return a null token for the JWE token.");
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(outerToken, theoryData.TestId);

                Assert.True(outerToken.InnerToken != null, "ValidateToken should not return a null token for the inner JWE token.");
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(outerToken.InnerToken, theoryData.TestId);

                context.PropertiesToIgnoreWhenComparing = new Dictionary<Type, List<string>>
                {
                    { typeof(JsonWebToken), new List<string> { "EncodedToken" } },
                };

                if (!IdentityComparer.AreEqual(jweCreatedInMemoryToken.Payload, outerToken.Payload, context))
                    context.Diffs.Add("jweCreatedInMemory.Payload != jweValidated.Payload");

                if (!IdentityComparer.AreEqual(jweCreatedInMemoryToken.Payload, outerToken.InnerToken.Payload, context))
                    context.Diffs.Add("jweCreatedInMemory.Payload != jweValidated.InnerToken.Payload");

                TestUtilities.AssertFailIfErrors(string.Format(CultureInfo.InvariantCulture, "RoundTripJWE: "), context.Diffs);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }
        }

        public static TheoryData<CreateTokenTheoryData> RoundTripJWEDirectEncryptionTheoryData
        {
            get
            {
                return new TheoryData<CreateTokenTheoryData>
                {
                    new CreateTokenTheoryData()
                    {
                        First = true,
                        TestId = "RoundTripJWEValid",
                        ValidationParameters = Default.SymmetricEncryptSignTokenValidationParameters,
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = Default.SymmetricEncryptingCredentials
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId =  "SigningKey-Not-Found",
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = NotDefault.SymmetricSigningKey256,
                            TokenDecryptionKey = Default.SymmetricEncryptionKey256,
                        },
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = Default.SymmetricEncryptingCredentials,
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10501:")
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "EncryptionKey-Not-Found",
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = Default.SymmetricSigningKey256,
                            TokenDecryptionKey = NotDefault.SymmetricEncryptionKey,
                        },
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = Default.SymmetricEncryptingCredentials,
                        ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException("IDX10603:")
                    },
                };
            }
        }


        [Theory, MemberData(nameof(RoundTripJWEKeyWrappingTheoryData))]
        public void RoundTripJWEKeyWrapping(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.RoundTripJWE", theoryData);
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var jweCreatedInMemory = jsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.SigningCredentials, theoryData.EncryptingCredentials);
            var jweCreatedInMemoryToken = new JsonWebToken(jweCreatedInMemory);
            try
            {
                var tokenValidationResult = jsonWebTokenHandler.ValidateToken(jweCreatedInMemory, theoryData.ValidationParameters);
                var outerToken = tokenValidationResult.SecurityToken as JsonWebToken;
                jwtSecurityTokenHandler.ValidateToken(jweCreatedInMemory, theoryData.ValidationParameters, out SecurityToken validatedTokenFromJwtHandler);

                IdentityComparer.AreEqual((validatedTokenFromJwtHandler as JwtSecurityToken).Claims, outerToken.Claims, context);

                Assert.True(outerToken != null, "ValidateToken should not return a null token for the JWE token.");
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(outerToken, theoryData.TestId);

                Assert.True(outerToken.InnerToken != null, "ValidateToken should not return a null token for the inner JWE token.");
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(outerToken.InnerToken, theoryData.TestId);

                context.PropertiesToIgnoreWhenComparing = new Dictionary<Type, List<string>>
                {
                    { typeof(JsonWebToken), new List<string> { "EncodedToken" } },
                };

                if (!IdentityComparer.AreEqual(jweCreatedInMemoryToken.Payload, outerToken.Payload, context))
                    context.Diffs.Add("jweCreatedInMemory.Payload != jweValidated.Payload");

                if (!IdentityComparer.AreEqual(jweCreatedInMemoryToken.Payload, outerToken.InnerToken.Payload, context))
                    context.Diffs.Add("jweCreatedInMemory.Payload != jweValidated.InnerToken.Payload");

                TestUtilities.AssertFailIfErrors(string.Format(CultureInfo.InvariantCulture, "RoundTripJWE: "), context.Diffs);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }
        }

        public static TheoryData<CreateTokenTheoryData> RoundTripJWEKeyWrappingTheoryData
        {
            get
            {
                return new TheoryData<CreateTokenTheoryData>
                {
                    new CreateTokenTheoryData()
                    {
                        First = true,
                        TestId = "RsaPKCS1-Aes128CbcHmacSha256",
                        ValidationParameters = Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256)
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "RsaPKCS1-Aes192CbcHmacSha384",
                        ValidationParameters = Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes192CbcHmacSha384)
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "RsaPKCS1-Aes256CbcHmacSha512",
                        ValidationParameters = Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes256CbcHmacSha512)
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "RsaOAEP-Aes128CbcHmacSha256",
                        ValidationParameters = Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes128CbcHmacSha256)
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "RsaOAEP-Aes192CbcHmacSha384",
                        ValidationParameters = Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes192CbcHmacSha384)
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "RsaOAEP-Aes256CbcHmacSha512",
                        ValidationParameters = Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512)
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "RsaOaepKeyWrap-Aes128CbcHmacSha256",
                        ValidationParameters = Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaOaepKeyWrap, SecurityAlgorithms.Aes128CbcHmacSha256)
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "RsaOaepKeyWrap-Aes192CbcHmacSha384",
                        ValidationParameters = Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaOaepKeyWrap, SecurityAlgorithms.Aes192CbcHmacSha384)
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "RsaOaepKeyWrap-Aes256CbcHmacSha512",
                        ValidationParameters = Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaOaepKeyWrap, SecurityAlgorithms.Aes256CbcHmacSha512)
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "SymmetricSecurityKey2_128-Aes128KW-Aes128CbcHmacSha256",
                        ValidationParameters = Default.TokenValidationParameters(KeyingMaterial.SymmetricSecurityKey2_128, Default.SymmetricSigningKey256),
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.SymmetricSecurityKey2_128, SecurityAlgorithms.Aes128KW, SecurityAlgorithms.Aes128CbcHmacSha256)
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "SymmetricEncryptionKey256-Aes256KW-Aes128CbcHmacSha256",
                        ValidationParameters = Default.SymmetricEncryptSignTokenValidationParameters,
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = new EncryptingCredentials(Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes128CbcHmacSha256)
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "RsaOaepKeyWrap-Aes192CbcHmacSha384",
                        ValidationParameters = Default.TokenValidationParameters(KeyingMaterial.RsaSecurityKey_2048, Default.SymmetricSigningKey256),
                        Payload = Default.PayloadString,
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaOaepKeyWrap, SecurityAlgorithms.Aes192CbcHmacSha384)
                    }
                };
            }
        }

        // Test checks to make sure that default times are correctly added to the token
        // upon token creation.
        [Fact]
        public void SetDefaultTimesOnTokenCreation()
        {
            TestUtilities.WriteHeader($"{this}.SetDefaultTimesOnTokenCreation");
            var context = new CompareContext();

            var tokenHandler = new JsonWebTokenHandler();
            var payloadWithoutTimeValues = new JObject()
            {
                { JwtRegisteredClaimNames.Email, "Bob@contoso.com" },
                { JwtRegisteredClaimNames.GivenName, "Bob" },
                { JwtRegisteredClaimNames.Iss, Default.Issuer },
                { JwtRegisteredClaimNames.Aud, Default.Audience },
            }.ToString();

            var jwtString = tokenHandler.CreateToken(payloadWithoutTimeValues, KeyingMaterial.JsonWebKeyRsa256SigningCredentials);
            var jwt = new JsonWebToken(jwtString);

            // DateTime.MinValue is returned if the value of a DateTime claim is not found in the payload
            Assert.NotEqual(DateTime.MinValue, jwt.IssuedAt);
            Assert.NotEqual(DateTime.MinValue, jwt.ValidFrom);
            Assert.NotEqual(DateTime.MinValue, jwt.ValidTo);
        }

        // Test checks to make sure that an access token can be successfully validated by the JsonWebTokenHandler.
        // Also ensures that a non-standard claim can be successfully retrieved from the payload and validated.
        [Fact]
        public void ValidateJWS()
        {
            TestUtilities.WriteHeader($"{this}.ValidateToken");

            var tokenHandler = new JsonWebTokenHandler();
            var accessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlJzYVNlY3VyaXR5S2V5XzIwNDgiLCJ0eXAiOiJKV1QifQ.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwibmJmIjoiMTQ4OTc3NTYxNyIsImV4cCI6IjE2MTYwMDYwMTcifQ.GcIi6FGp1JS5VF70_ULa8g6GTRos9Y7rUZvPAo4hm10bBNfGhdd5uXgsJspiQzS8vwJQyPlq8a_BpL9TVKQyFIRQMnoZWe90htmNWszNYbd7zbLJZ9AuiDqDzqzomEmgcfkIrJ0VfbER57U46XPnUZQNng2XgMXrXmIKUqEph_vLGXYRQ4ndfwtRrR6BxQFd1PS1T5KpEoUTusI4VEsMcutzfXUygLDiRKIcnLFA0kQpeoHllO4Nb_Sxv63GCb0d1076FfSEYtyRxF4YSCz1In-ee5dwEK8Mw3nHscu-1hn0Fe98RBs-4OrUzI0WcV8mq9IIB3i-U-CqCJEP_hVCiA";
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = "http://Default.Audience.com",
                ValidIssuer = "http://Default.Issuer.com",
                IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
            };
            var tokenValidationResult = tokenHandler.ValidateToken(accessToken, tokenValidationParameters);
            var jsonWebToken = tokenValidationResult.SecurityToken as JsonWebToken;
            var email = jsonWebToken.GetPayloadValue<string>(JwtRegisteredClaimNames.Email);

            if (!email.Equals("Bob@contoso.com"))
                throw new SecurityTokenException("Token does not contain the correct value for the 'email' claim.");
        }

        [Theory, MemberData(nameof(JWECompressionTheoryData))]
        public void JWECompressionTest(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.JWECompressionTest", theoryData);

            try
            {
                var handler = new JsonWebTokenHandler();
                CompressionProviderFactory.Default = theoryData.CompressionProviderFactory;
                var jwtToken = handler.CreateToken(theoryData.Payload, theoryData.SigningCredentials, theoryData.EncryptingCredentials, theoryData.CompressionAlgorithm);
                var validationResult = handler.ValidateToken(jwtToken, theoryData.ValidationParameters);

                IdentityComparer.AreEqual(theoryData.Payload, (validationResult.SecurityToken as JsonWebToken).Payload, context);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }
        }

        public static TheoryData<CreateTokenTheoryData> JWECompressionTheoryData
        {
            get
            {
                var compressionProviderFactoryForCustom = new CompressionProviderFactory
                {
                    CustomCompressionProvider = new SampleCustomCompressionProvider("MyAlgorithm")
                };

                var compressionProviderFactoryForCustom2 = new CompressionProviderFactory
                {
                    CustomCompressionProvider = new SampleCustomCompressionProviderDecompressAndCompressAlwaysFail("MyAlgorithm")
                };

                return new TheoryData<CreateTokenTheoryData>
                {
                    new CreateTokenTheoryData()
                    {
                        First = true,
                        TestId = "ValidAlgorithm",
                        CompressionAlgorithm = CompressionAlgorithms.Deflate,
                        CompressionProviderFactory = new CompressionProviderFactory(),
                        ValidationParameters = Default.JWECompressionTokenValidationParameters,
                        Payload = Default.PayloadString,
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256)
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "InvalidAlgorithm",
                        CompressionAlgorithm = "UNSUPPORTED",
                        CompressionProviderFactory = new CompressionProviderFactory(),
                        ValidationParameters = Default.JWECompressionTokenValidationParameters,
                        Payload = Default.PayloadString,
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256),
                        ExpectedException = new ExpectedException(typeof(SecurityTokenCompressionFailedException), "IDX10680:", typeof(NotSupportedException))
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "NullCompressionProviderFactory",
                        CompressionAlgorithm = CompressionAlgorithms.Deflate,
                        CompressionProviderFactory = null,
                        ValidationParameters = Default.JWECompressionTokenValidationParameters,
                        Payload = Default.PayloadString,
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256),
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:")
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "CustomCompressProviderSucceeds",
                        CompressionAlgorithm = CompressionAlgorithms.Deflate,
                        CompressionProviderFactory = compressionProviderFactoryForCustom,
                        ValidationParameters = Default.JWECompressionTokenValidationParameters,
                        Payload = Default.PayloadString,
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256),
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "CustomCompressionProviderFails",
                        CompressionAlgorithm = CompressionAlgorithms.Deflate,
                        CompressionProviderFactory = compressionProviderFactoryForCustom2,
                        ValidationParameters = Default.JWECompressionTokenValidationParameters,
                        Payload = Default.PayloadString,
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256),
                        ExpectedException = new ExpectedException(typeof(SecurityTokenCompressionFailedException), "IDX10680:", typeof(InvalidOperationException))
                    },
                };
            }
        }

        [Theory, MemberData(nameof(JWEDecompressionTheoryData))]
        public void JWEDecompressionTest(JWEDecompressionTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.JWEDecompressionTest", theoryData);

            try
            {
                var handler = new JsonWebTokenHandler();
                CompressionProviderFactory.Default = theoryData.CompressionProviderFactory;
                var validationResult = handler.ValidateToken(theoryData.JWECompressionString, theoryData.ValidationParameters);
                var validatedToken = validationResult.SecurityToken as JsonWebToken;

                Assert.NotEmpty(validatedToken.Claims);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }
        }

        public static TheoryData<JWEDecompressionTheoryData> JWEDecompressionTheoryData()
        {
            var compressionProviderFactoryForCustom = new CompressionProviderFactory()
            {
                CustomCompressionProvider = new SampleCustomCompressionProvider("MyAlgorithm")
            };

            var compressionProviderFactoryForCustom2 = new CompressionProviderFactory()
            {
                CustomCompressionProvider = new SampleCustomCompressionProviderDecompressAndCompressAlwaysFail("MyAlgorithm")
            };

            return new TheoryData<JWEDecompressionTheoryData>() {
                new JWEDecompressionTheoryData
                {
                    ValidationParameters = Default.JWECompressionTokenValidationParameters,
                    JWECompressionString = ReferenceTokens.JWECompressionTokenWithDEF,
                    CompressionProviderFactory = CompressionProviderFactory.Default,
                    TestId = "ValidAlgorithm"
                },
                new JWEDecompressionTheoryData
                {
                    ValidationParameters = Default.JWECompressionTokenValidationParameters,
                    JWECompressionString = ReferenceTokens.JWECompressionTokenWithUnsupportedAlgorithm,
                    CompressionProviderFactory = CompressionProviderFactory.Default,
                    TestId = "InvalidAlgorithm",
                    ExpectedException = new ExpectedException(typeof(SecurityTokenDecompressionFailedException), "IDX10679:", typeof(NotSupportedException))
                },
                new JWEDecompressionTheoryData
                {
                    ValidationParameters = Default.JWECompressionTokenValidationParameters,
                    JWECompressionString = ReferenceTokens.JWEInvalidCompressionTokenWithDEF,
                    CompressionProviderFactory = CompressionProviderFactory.Default,
                    TestId = "InvalidToken",
                    ExpectedException = new ExpectedException(typeof(SecurityTokenDecompressionFailedException), "IDX10679:", typeof(InvalidDataException))
                },
                new JWEDecompressionTheoryData
                {
                    ValidationParameters = Default.JWECompressionTokenValidationParameters,
                    JWECompressionString = ReferenceTokens.JWECompressionTokenWithDEF,
                    CompressionProviderFactory = null,
                    TestId = "NullCompressionProviderFactory",
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:")
                },
                new JWEDecompressionTheoryData
                {
                    ValidationParameters = Default.JWECompressionTokenValidationParameters,
                    CompressionProviderFactory = compressionProviderFactoryForCustom,
                    JWECompressionString = ReferenceTokens.JWECompressionTokenWithCustomAlgorithm,
                    TestId = "CustomCompressionProviderSucceeds"
                },
                new JWEDecompressionTheoryData
                {
                    ValidationParameters = Default.JWECompressionTokenValidationParameters,
                    JWECompressionString = ReferenceTokens.JWEInvalidCompressionTokenWithDEF,
                    CompressionProviderFactory = compressionProviderFactoryForCustom2,
                    TestId = "CustomCompressionProviderFails",
                    ExpectedException = new ExpectedException(typeof(SecurityTokenDecompressionFailedException), "IDX10679:", typeof(InvalidOperationException))
                }
            };
        }
    }

    public class CreateTokenTheoryData : TheoryDataBase
    {
        public string Payload { get; set; }

        public string CompressionAlgorithm { get; set; }

        public CompressionProviderFactory CompressionProviderFactory { get; set; }

        public EncryptingCredentials EncryptingCredentials { get; set; }

        public SigningCredentials SigningCredentials { get; set; }

        public SecurityTokenDescriptor TokenDescriptor { get; set; }

        public JsonWebTokenHandler JsonWebTokenHandler { get; set; }

        public JwtSecurityTokenHandler JwtSecurityTokenHandler { get; set; }

        public TokenValidationParameters ValidationParameters { get; set; }
    }

    public class JWEDecompressionTheoryData : TheoryDataBase
    {
        public CompressionProviderFactory CompressionProviderFactory;
        public TokenValidationParameters ValidationParameters;
        public string JWECompressionString;
    }

    /// <summary>
    /// A custom compression provider class implementing <see cref="ICompressionProvider"/>.
    /// </summary>
    public class SampleCustomCompressionProvider : ICompressionProvider
    {
        public SampleCustomCompressionProvider(string algorithm)
        {
            Algorithm = algorithm;

            if (!IsSupportedAlgorithm(algorithm))
                throw new NotSupportedException($"Algorithm '{algorithm}' is not supported.");
        }

        public string Algorithm { get; set; }

        public byte[] Compress(byte[] value)
        {
            // just return the same bytes that were passed in
            return value;
        }

        public byte[] Decompress(byte[] value)
        {
            // just return the same bytes that were passed in
            return value;
        }

        public bool IsSupportedAlgorithm(string algorithm)
        {
            return algorithm != null && algorithm.Equals(Algorithm);
        }
    }

    /// <summary>
    /// A custom compression provider class implementing <see cref="ICompressionProvider"/>, 
    /// which accepts any algorithm but always return null for decompression and compression.
    /// </summary>
    public class SampleCustomCompressionProviderDecompressAndCompressAlwaysFail : ICompressionProvider
    {
        public SampleCustomCompressionProviderDecompressAndCompressAlwaysFail(string algorithm)
        {
            Algorithm = algorithm;
        }

        public string Algorithm { get; set; }

        public byte[] Compress(byte[] value)
        {
            return null;
        }

        public byte[] Decompress(byte[] value)
        {
            return null;
        }

        public bool IsSupportedAlgorithm(string algorithm)
        {
            return true;
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
