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

using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IdentityModel.Tokens.Jwt.Tests;
using System.IO;
using System.Linq;
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
                IdentityComparer.AreEqual(validationResult.IsValid, theoryData.IsValid, context);
                var validatedTokenFromJsonHandler = validationResult.SecurityToken;
                var validationResult2 = theoryData.JsonWebTokenHandler.ValidateToken(jweFromJwtHandler, theoryData.ValidationParameters);
                IdentityComparer.AreEqual(validationResult.IsValid, theoryData.IsValid, context);
                IdentityComparer.AreEqual((validatedTokenFromJwtHandler as JwtSecurityToken).Claims, (validatedTokenFromJsonHandler as JsonWebToken).Claims, context);

                theoryData.ExpectedException.ProcessNoException(context);
                context.PropertiesToIgnoreWhenComparing = new Dictionary<Type, List<string>>
                {
                    { typeof(JsonWebToken), new List<string> { "EncodedToken", "AuthenticationTag", "Ciphertext", "InitializationVector" } },
                };

                IdentityComparer.AreEqual(validationResult2.SecurityToken as JsonWebToken, validationResult.SecurityToken as JsonWebToken, context);
                theoryData.ExpectedException.ProcessNoException(context);
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

        // Tests checks to make sure that the token string (JWE) created by calling 
        // CreateToken(string payload, SigningCredentials signingCredentials, EncryptingCredentials encryptingCredentials)
        // is equivalent to the token string created by calling CreateToken(SecurityTokenDescriptor tokenDescriptor).
        [Theory, MemberData(nameof(CreateJWEUsingSecurityTokenDescriptorTheoryData))]
        public void CreateJWEUsingSecurityTokenDescriptor(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateJWEUsingSecurityTokenDescriptor", theoryData);
            try
            {
                string jweFromSecurityTokenDescriptor = theoryData.JsonWebTokenHandler.CreateToken(theoryData.TokenDescriptor);
                string jweFromString = theoryData.JsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.TokenDescriptor.SigningCredentials, theoryData.TokenDescriptor.EncryptingCredentials);

                var validationResultFromSecurityTokenDescriptor = theoryData.JsonWebTokenHandler.ValidateToken(jweFromSecurityTokenDescriptor, theoryData.ValidationParameters);
                var validationResultFromString = theoryData.JsonWebTokenHandler.ValidateToken(jweFromString, theoryData.ValidationParameters);

                IdentityComparer.AreEqual(validationResultFromSecurityTokenDescriptor.IsValid, theoryData.IsValid, context);
                IdentityComparer.AreEqual(validationResultFromString.IsValid, theoryData.IsValid, context);

                var jweTokenFromSecurityTokenDescriptor = validationResultFromSecurityTokenDescriptor.SecurityToken as JsonWebToken;
                var jweTokenFromString = validationResultFromString.SecurityToken as JsonWebToken;

                // If the signing key used was an x509SecurityKey, make sure that the 'X5t' property was set properly and
                // that the values of 'X5t' and 'Kid' on the JsonWebToken are equal to each other.
                if (theoryData.TokenDescriptor.SigningCredentials.Key is X509SecurityKey x509SecurityKey)
                {
                    var innerTokenFromSecurityTokenDescriptor = jweTokenFromSecurityTokenDescriptor.InnerToken as JsonWebToken;
                    var innerTokenFromString = jweTokenFromString.InnerToken as JsonWebToken;

                    IdentityComparer.AreEqual(innerTokenFromSecurityTokenDescriptor.X5t, x509SecurityKey.X5t, context);
                    IdentityComparer.AreEqual(innerTokenFromSecurityTokenDescriptor.X5t, innerTokenFromSecurityTokenDescriptor.Kid, context);
                    IdentityComparer.AreEqual(innerTokenFromString.X5t, x509SecurityKey.X5t, context);
                    IdentityComparer.AreEqual(innerTokenFromString.X5t, innerTokenFromString.Kid, context);
                }

                context.PropertiesToIgnoreWhenComparing = new Dictionary<Type, List<string>>
                {
                    { typeof(JsonWebToken), new List<string> { "EncodedToken", "AuthenticationTag", "Ciphertext", "InitializationVector" } },
                };

                IdentityComparer.AreEqual(jweTokenFromSecurityTokenDescriptor, jweTokenFromString, context);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateTokenTheoryData> CreateJWEUsingSecurityTokenDescriptorTheoryData
        {
            get
            {
                return new TheoryData<CreateTokenTheoryData>
                {
                    new CreateTokenTheoryData
                    {
                        First = true,
                        TestId = "Valid",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                            Claims = Default.PayloadDictionary
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        }
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "ValidUsingX509SecurityKey",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
                            EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                            Claims = Default.PayloadDictionary
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        }
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "TokenDescriptorNull",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  null,
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        },
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:")
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "TokenDescriptorClaimsNull",
                        Payload = new JObject()
                        {
                            { JwtRegisteredClaimNames.Aud, Default.Audience }
                        }.ToString(Formatting.None),
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            Audience = Default.Audience,
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                            Claims = null
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
                            ValidAudience = Default.Audience,
                            ValidateIssuer = false
                        }
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "TokenDescriptorClaimsEmpty",
                        Payload = new JObject()
                        {
                            { JwtRegisteredClaimNames.Aud, Default.Audience }
                        }.ToString(Formatting.None),
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            Audience = Default.Audience,
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                            Claims = new Dictionary<string, object>()
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
                            ValidAudience = Default.Audience,
                            ValidateIssuer = false,
                        }
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "PayloadEmpty",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                            Claims = new Dictionary<string, object>()
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenException), "IDX14115:")
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "TokenDescriptorSigningCredentialsNull",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = null,
                            EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                            Claims = Default.PayloadDictionary
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        },
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:")
                    }
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
                string jwsFromJsonHandler = theoryData.JsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.TokenDescriptor.SigningCredentials);

                theoryData.JwtSecurityTokenHandler.ValidateToken(jwsFromJwtHandler, theoryData.ValidationParameters, out SecurityToken validatedToken);
                var tokenValidationResult = theoryData.JsonWebTokenHandler.ValidateToken(jwsFromJsonHandler, theoryData.ValidationParameters);
                IdentityComparer.AreEqual(tokenValidationResult.IsValid, theoryData.IsValid, context);

                theoryData.ExpectedException.ProcessNoException(context);
                var jwsTokenFromJwtHandler = new JsonWebToken(jwsFromJwtHandler);
                var jwsTokenFromHandler = new JsonWebToken(jwsFromJsonHandler);
                IdentityComparer.AreEqual(jwsTokenFromJwtHandler, jwsTokenFromHandler, context);
                theoryData.ExpectedException.ProcessNoException(context);
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

        // Tests checks to make sure that the token string (JWS) created by calling CreateToken(string payload, SigningCredentials signingCredentials)
        // is equivalent to the token string created by calling CreateToken(SecurityTokenDescriptor tokenDescriptor).
        [Theory, MemberData(nameof(CreateJWSUsingSecurityTokenDescriptorTheoryData))]
        public void CreateJWSUsingSecurityTokenDescriptor(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateJWSUsingSecurityTokenDescriptor", theoryData);
            try
            {
                string jwtFromSecurityTokenDescriptor = theoryData.JsonWebTokenHandler.CreateToken(theoryData.TokenDescriptor);
                string jwtFromString = theoryData.JsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.TokenDescriptor.SigningCredentials);

                var tokenValidationResultFromSecurityTokenDescriptor = theoryData.JsonWebTokenHandler.ValidateToken(jwtFromSecurityTokenDescriptor, theoryData.ValidationParameters);
                var tokenValidationResultFromString = theoryData.JsonWebTokenHandler.ValidateToken(jwtFromString, theoryData.ValidationParameters);

                IdentityComparer.AreEqual(tokenValidationResultFromSecurityTokenDescriptor.IsValid, theoryData.IsValid, context);
                IdentityComparer.AreEqual(tokenValidationResultFromString.IsValid, theoryData.IsValid, context);

                var jwsTokenFromSecurityTokenDescriptor = new JsonWebToken(jwtFromSecurityTokenDescriptor);
                var jwsTokenFromString = new JsonWebToken(jwtFromString);

                // If the signing key used was an x509SecurityKey, make sure that the 'X5t' property was set properly and
                // that the values of 'X5t' and 'Kid' on the JsonWebToken are equal to each other.
                if (theoryData.TokenDescriptor.SigningCredentials.Key is X509SecurityKey x509SecurityKey)
                {
                    IdentityComparer.AreEqual(jwsTokenFromSecurityTokenDescriptor.X5t, x509SecurityKey.X5t, context);
                    IdentityComparer.AreEqual(jwsTokenFromSecurityTokenDescriptor.X5t, jwsTokenFromSecurityTokenDescriptor.Kid, context);
                    IdentityComparer.AreEqual(jwsTokenFromString.X5t, x509SecurityKey.X5t, context);
                    IdentityComparer.AreEqual(jwsTokenFromString.X5t, jwsTokenFromString.Kid, context);
                }

                IdentityComparer.AreEqual(jwsTokenFromSecurityTokenDescriptor, jwsTokenFromString, context);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }


        public static TheoryData<CreateTokenTheoryData> CreateJWSUsingSecurityTokenDescriptorTheoryData
        {
            get
            {
                return new TheoryData<CreateTokenTheoryData>
                {
                    new CreateTokenTheoryData
                    {
                        First = true,
                        TestId = "Valid",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Claims = Default.PayloadDictionary
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        }
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "ValidUsingX509SecurityKey",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
                            Claims = Default.PayloadDictionary
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        }
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "TokenDescriptorNull",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  null,
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        },
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:")
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "TokenDescriptorClaimsNull",
                        Payload = new JObject()
                        {
                            { JwtRegisteredClaimNames.Aud, Default.Audience }
                        }.ToString(Formatting.None),
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            Audience = Default.Audience,
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Claims = null
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            ValidAudience = Default.Audience,
                            ValidateIssuer = false
                        }
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "TokenDescriptorClaimsEmpty",
                        Payload = new JObject()
                        {
                            { JwtRegisteredClaimNames.Aud, Default.Audience }
                        }.ToString(Formatting.None),
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            Audience = Default.Audience,
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Claims = new Dictionary<string, object>()
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            ValidAudience = Default.Audience,
                            ValidateIssuer = false
                        }
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "PayloadEmpty",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Claims = new Dictionary<string, object>()
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenException), "IDX14115:")
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "TokenDescriptorSigningCredentialsNull",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = null,
                            Claims = Default.PayloadDictionary
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        },
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:")
                    },
                    new CreateTokenTheoryData // Test checks that values in SecurityTokenDescriptor.Payload
                    // are properly replaced with the properties that are explicitly specified on the SecurityTokenDescriptor.
                    {
                        TestId = "UseSecurityTokenDescriptorProperties",
                        Payload = new JObject()
                        {
                            { JwtRegisteredClaimNames.Email, "Bob@contoso.com" },
                            { JwtRegisteredClaimNames.GivenName, "Bob" },
                            { JwtRegisteredClaimNames.Iss, "Issuer" },
                            { JwtRegisteredClaimNames.Aud, "Audience" },
                            { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.Parse("2018-03-17T18:33:37.080Z")).ToString() },
                            { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(DateTime.Parse("2018-03-17T18:33:37.080Z")).ToString() },
                            { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(DateTime.Parse("2023-03-17T18:33:37.080Z")).ToString() },
                        }.ToString(Formatting.None),
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Claims = Default.PayloadDictionary,
                            Issuer = "Issuer",
                            Audience = "Audience",
                            IssuedAt = DateTime.Parse("2018-03-17T18:33:37.080Z"),
                            NotBefore = DateTime.Parse("2018-03-17T18:33:37.080Z"),
                            Expires = DateTime.Parse("2023-03-17T18:33:37.080Z")
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            ValidAudience = "Audience",
                            ValidIssuer = "Issuer"
                        }
                    }
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
            var claimsIdentity = tokenValidationResult.ClaimsIdentity;
            IdentityComparer.AreEqual(Default.PayloadClaimsIdentity, claimsIdentity, context);
            IdentityComparer.AreEqual(Default.PayloadString, validatedToken.Payload.ToString(), context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(RoundTripJWEDirectEncryptionTheoryData))]
        public void RoundTripJWEDirectEncryption(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.RoundTripJWE", theoryData);
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            jwtSecurityTokenHandler.InboundClaimTypeMap.Clear();
            var jweCreatedInMemory = jsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.SigningCredentials, theoryData.EncryptingCredentials);
            try
            {
                var tokenValidationResult = jsonWebTokenHandler.ValidateToken(jweCreatedInMemory, theoryData.ValidationParameters);
                IdentityComparer.AreEqual(tokenValidationResult.IsValid, theoryData.IsValid, context);
                var outerToken = tokenValidationResult.SecurityToken as JsonWebToken;
                var claimsPrincipal = jwtSecurityTokenHandler.ValidateToken(jweCreatedInMemory, theoryData.ValidationParameters, out SecurityToken validatedTokenFromJwtHandler);

                IdentityComparer.AreEqual((validatedTokenFromJwtHandler as JwtSecurityToken).Claims, outerToken.Claims, context);
                IdentityComparer.AreEqual(claimsPrincipal.Identity, tokenValidationResult.ClaimsIdentity, context);

                Assert.True(outerToken != null, "ValidateToken should not return a null token for the JWE token.");
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(outerToken, theoryData.TestId);

                Assert.True(outerToken.InnerToken != null, "ValidateToken should not return a null token for the inner JWE token.");
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(outerToken.InnerToken, theoryData.TestId);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
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
                        IsValid = false,
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
                        IsValid = false,
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
            jwtSecurityTokenHandler.InboundClaimTypeMap.Clear();
            var jweCreatedInMemory = jsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.SigningCredentials, theoryData.EncryptingCredentials);
            try
            {
                var tokenValidationResult = jsonWebTokenHandler.ValidateToken(jweCreatedInMemory, theoryData.ValidationParameters);
                IdentityComparer.AreEqual(tokenValidationResult.IsValid, theoryData.IsValid, context);
                var outerToken = tokenValidationResult.SecurityToken as JsonWebToken;
                var claimsPrincipal = jwtSecurityTokenHandler.ValidateToken(jweCreatedInMemory, theoryData.ValidationParameters, out SecurityToken validatedTokenFromJwtHandler);

                IdentityComparer.AreEqual((validatedTokenFromJwtHandler as JwtSecurityToken).Claims, outerToken.Claims, context);
                IdentityComparer.AreEqual(claimsPrincipal.Identity, tokenValidationResult.ClaimsIdentity, context);

                Assert.True(outerToken != null, "ValidateToken should not return a null token for the JWE token.");
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(outerToken, theoryData.TestId);

                Assert.True(outerToken.InnerToken != null, "ValidateToken should not return a null token for the inner JWE token.");
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(outerToken.InnerToken, theoryData.TestId);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
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
            }.ToString(Formatting.None);

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

                IdentityComparer.AreEqual(theoryData.Payload, (validationResult.SecurityToken as JsonWebToken).InnerToken.Payload.ToString(), context);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
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

                if (validationResult.IsValid)
                {
                    if (!validatedToken.Claims.Any())
                        context.Diffs.Add("validatedToken.Claims is empty");
                }
                else
                {
                    theoryData.ExpectedException.ProcessException(validationResult.Exception, context);
                }
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
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
                    JWECompressionString = ReferenceTokens.JWECompressionTokenWithDEF,
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

        public bool IsValid { get; set; } = true;

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
