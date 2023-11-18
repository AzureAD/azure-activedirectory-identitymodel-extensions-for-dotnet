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

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IdentityModel.Tokens.Jwt.Tests;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerTests
    {
        static TimeSpan ClockSkewToEnableTestsWithHardcodedTokens = TimeSpan.FromDays(1000);

        // This test checks to make sure that the value of JsonWebTokenHandler.Base64UrlEncodedUnsignedJWSHeader has remained unchanged.
        [Fact]
        public void Base64UrlEncodedUnsignedJwtHeader()
        {
            TestUtilities.WriteHeader($"{this}.Base64UrlEncodedUnsignedJwtHeader");
            var context = new CompareContext();

            var header = new JObject
            {
                { JwtHeaderParameterNames.Alg, SecurityAlgorithms.None }
            };
            var rawHeader = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToString(Formatting.None)));

            if (!JsonWebTokenHandler.Base64UrlEncodedUnsignedJWSHeader.Equals(rawHeader))
                context.AddDiff("!JsonWebTokenHandler.Base64UrlEncodedUnsignedJWSHeader.Equals(rawHeader)");

            TestUtilities.AssertFailIfErrors(context);
        }

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

        [Theory, MemberData(nameof(CreateTokenWithEmptyPayloadUsingSecurityTokenDescriptorTheoryData))]
        public void CreateTokenWithEmptyPayloadUsingSecurityTokenDescriptor(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateEmptyJWSUsingSecurityTokenDescriptor", theoryData);
            try
            {
                string jwtFromSecurityTokenDescriptor = theoryData.JsonWebTokenHandler.CreateToken(theoryData.TokenDescriptor);
                var tokenValidationResultFromSecurityTokenDescriptor = theoryData.JsonWebTokenHandler.ValidateToken(jwtFromSecurityTokenDescriptor, theoryData.ValidationParameters);
                IdentityComparer.AreEqual(tokenValidationResultFromSecurityTokenDescriptor.IsValid, theoryData.IsValid, context);
                var jwsTokenFromSecurityTokenDescriptor = new JsonWebToken(jwtFromSecurityTokenDescriptor);

                if (theoryData.TokenDescriptor.SigningCredentials?.Key is X509SecurityKey x509SecurityKey)
                {
                    IdentityComparer.AreEqual(jwsTokenFromSecurityTokenDescriptor.X5t, x509SecurityKey.X5t, context);
                    IdentityComparer.AreEqual(jwsTokenFromSecurityTokenDescriptor.Kid, x509SecurityKey.KeyId, context);
                }

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateTokenTheoryData> CreateTokenWithEmptyPayloadUsingSecurityTokenDescriptorTheoryData()
        {
            return new TheoryData<CreateTokenTheoryData>()
            {
                new CreateTokenTheoryData
                {
                    TestId = "PayloadEmptyUnsignedJWSWithDefaultTimes",
                    TokenDescriptor = new SecurityTokenDescriptor
                    {
                        Claims = new Dictionary<string, object>()
                    },
                    JsonWebTokenHandler = new JsonWebTokenHandler(),
                    ValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateLifetime = false,
                        ValidateIssuer = false,
                        RequireSignedTokens = false
                    }
                },
                new CreateTokenTheoryData
                {
                    TestId = "PayloadEmptyUnsignedJWSWithoutDefaultTimes",
                    TokenDescriptor = new SecurityTokenDescriptor
                    {
                        Claims = new Dictionary<string, object>()
                    },
                    JsonWebTokenHandler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false },
                    ValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateLifetime = false,
                        ValidateIssuer = false,
                        RequireSignedTokens = false
                    }
                },
                new CreateTokenTheoryData
                {
                    TestId = "PayloadEmptyJWSWithDefaultTimes",
                    TokenDescriptor = new SecurityTokenDescriptor
                    {
                        SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                        Claims = new Dictionary<string, object>()
                    },
                    JsonWebTokenHandler = new JsonWebTokenHandler(),
                    ValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                        ValidateAudience = false,
                        ValidateLifetime = false,
                        ValidateIssuer = false
                    }
                },
                new CreateTokenTheoryData
                {
                    TestId = "PayloadEmptyJWSWithoutDefaultTimes",
                    TokenDescriptor = new SecurityTokenDescriptor
                    {
                        SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                        Claims = new Dictionary<string, object>()
                    },
                    JsonWebTokenHandler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false },
                    ValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                        ValidateAudience = false,
                        ValidateLifetime = false,
                        ValidateIssuer = false
                    }
                },
                new CreateTokenTheoryData
                {
                    TestId = "PayloadEmptyJWE",
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
                        ValidateAudience = false,
                        ValidateLifetime = false,
                        ValidateIssuer = false
                    },
                }
            };
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

                var claimsPrincipal = theoryData.JwtSecurityTokenHandler.ValidateToken(jweFromJwtHandler, theoryData.ValidationParameters, out SecurityToken validatedTokenFromJwtHandler);
                var validationResult = theoryData.JsonWebTokenHandler.ValidateToken(jweFromJsonHandler, theoryData.ValidationParameters);
                IdentityComparer.AreEqual(validationResult.IsValid, theoryData.IsValid, context);
                var validatedTokenFromJsonHandler = validationResult.SecurityToken;
                var validationResult2 = theoryData.JsonWebTokenHandler.ValidateToken(jweFromJwtHandler, theoryData.ValidationParameters);
                IdentityComparer.AreEqual(validationResult.IsValid, theoryData.IsValid, context);
                IdentityComparer.AreEqual(claimsPrincipal.Identity, validationResult.ClaimsIdentity, context);
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
                    new CreateTokenTheoryData
                    {
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
                            IssuerValidator = ValidationDelegates.IssuerValidatorReturnsDifferentIssuer,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        }
                    }
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
                string jweFromString;
                if (theoryData.TokenDescriptor.SigningCredentials == null)
                    jweFromString = theoryData.JsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.TokenDescriptor.EncryptingCredentials);
                else if (theoryData.TokenDescriptor.AdditionalHeaderClaims != null)
                    jweFromString = theoryData.JsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.TokenDescriptor.SigningCredentials, theoryData.TokenDescriptor.EncryptingCredentials, theoryData.TokenDescriptor.AdditionalHeaderClaims);
                else
                    jweFromString = theoryData.JsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.TokenDescriptor.SigningCredentials, theoryData.TokenDescriptor.EncryptingCredentials);

                var validationResultFromSecurityTokenDescriptor = theoryData.JsonWebTokenHandler.ValidateToken(jweFromSecurityTokenDescriptor, theoryData.ValidationParameters);
                var validationResultFromString = theoryData.JsonWebTokenHandler.ValidateToken(jweFromString, theoryData.ValidationParameters);

                IdentityComparer.AreEqual(validationResultFromSecurityTokenDescriptor.IsValid, theoryData.IsValid, context);
                IdentityComparer.AreEqual(validationResultFromString.IsValid, theoryData.IsValid, context);

                var jweTokenFromSecurityTokenDescriptor = validationResultFromSecurityTokenDescriptor.SecurityToken as JsonWebToken;
                var jweTokenFromString = validationResultFromString.SecurityToken as JsonWebToken;

                // If the signing key used was an x509SecurityKey, make sure that the 'X5t' property was set properly and
                // that the values of 'X5t' and 'Kid' on the JsonWebToken are equal to each other.
                if (theoryData.TokenDescriptor.SigningCredentials?.Key is X509SecurityKey x509SecurityKey)
                {
                    var innerTokenFromSecurityTokenDescriptor = jweTokenFromSecurityTokenDescriptor.InnerToken as JsonWebToken;
                    var innerTokenFromString = jweTokenFromString.InnerToken as JsonWebToken;

                    IdentityComparer.AreEqual(innerTokenFromSecurityTokenDescriptor.X5t, x509SecurityKey.X5t, context);
                    IdentityComparer.AreEqual(innerTokenFromSecurityTokenDescriptor.Kid, x509SecurityKey.KeyId, context);
                    IdentityComparer.AreEqual(innerTokenFromString.X5t, x509SecurityKey.X5t, context);
                    IdentityComparer.AreEqual(innerTokenFromString.Kid, x509SecurityKey.KeyId, context);
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
                            { JwtRegisteredClaimNames.Aud, Default.Audience },
                            { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(Default.Expires) },
                            { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(Default.IssueInstant) },
                            { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(Default.NotBefore) },
                        }.ToString(Formatting.None),
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            Audience = Default.Audience,
                            IssuedAt = Default.NotBefore,
                            NotBefore = Default.NotBefore,
                            Expires = Default.Expires,
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
                            { JwtRegisteredClaimNames.Aud, Default.Audience },
                            { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(Default.Expires) },
                            { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(Default.IssueInstant) },
                            { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(Default.NotBefore) },
                        }.ToString(Formatting.None),
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            Audience = Default.Audience,
                            IssuedAt = Default.NotBefore,
                            NotBefore = Default.NotBefore,
                            Expires = Default.Expires,
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
                        TestId = "TokenDescriptorSigningCredentialsNullRequireSignedTokensFalse",
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
                            ValidIssuer = Default.Issuer,
                            RequireSignedTokens = false,
                        },
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "TokenDescriptorSigningCredentialsNullRequireSignedTokensTrue",
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
                            ValidIssuer = Default.Issuer,
                        },
                        IsValid = false
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
                            { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.Parse("2018-03-17T18:33:37.080Z")) },
                            { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(DateTime.Parse("2018-03-17T18:33:37.080Z")) },
                            { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(DateTime.Parse("2025-03-17T18:33:37.080Z")) },
                        }.ToString(Formatting.None),
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                            Claims = Default.PayloadDictionary,
                            Issuer = "Issuer",
                            Audience = "Audience",
                            IssuedAt = DateTime.Parse("2018-03-17T18:33:37.080Z"),
                            NotBefore = DateTime.Parse("2018-03-17T18:33:37.080Z"),
                            Expires = DateTime.Parse("2025-03-17T18:33:37.080Z")
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
                            ValidAudience = "Audience",
                            ValidIssuer = "Issuer"
                        }
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "SingleAdditionalHeaderClaim",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                            Claims = Default.PayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object> () { { "int", 123 } }
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
                        TestId = "MultipleAdditionalHeaderClaims",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                            Claims = Default.PayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object> () { { "int", 123 }, { "string", "string" } }
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
                        TestId = "DuplicateAdditionalHeaderClaim",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                            Claims = Default.PayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object> () { { JwtHeaderParameterNames.Alg, "alg" } }
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        },
                        ExpectedException = ExpectedException.SecurityTokenException("IDX14116:")
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "DuplicateAdditionalHeaderClaimDifferentCase",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                            Claims = Default.PayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object> () { { JwtHeaderParameterNames.Alg.ToUpper(), "alg" } }
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        },
                        ExpectedException = ExpectedException.SecurityTokenException("IDX14116:")
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

                var claimsPrincipal = theoryData.JwtSecurityTokenHandler.ValidateToken(jwsFromJwtHandler, theoryData.ValidationParameters, out SecurityToken validatedToken);
                var tokenValidationResult = theoryData.JsonWebTokenHandler.ValidateToken(jwsFromJsonHandler, theoryData.ValidationParameters);
                IdentityComparer.AreEqual(tokenValidationResult.IsValid, theoryData.IsValid, context);
                IdentityComparer.AreEqual(claimsPrincipal.Identity, tokenValidationResult.ClaimsIdentity, context);

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

                var signingCredentialsNoKeyId = new SigningCredentials(KeyingMaterial.JsonWebKeyRsa_2048, SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256);
                signingCredentialsNoKeyId.Key.KeyId = null;

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
                    new CreateTokenTheoryData
                    {
                        TestId = "IssuerValidator",
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
                            IssuerValidator = ValidationDelegates.IssuerValidatorReturnsDifferentIssuer,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        }
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "NoKeyId",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = signingCredentialsNoKeyId,
                            Subject = new ClaimsIdentity(Default.PayloadClaims)
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        JwtSecurityTokenHandler = tokenHandler,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = signingCredentialsNoKeyId.Key,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        }
                    }
                };
            }
        }

        // This test checks to make sure that additional header claims are added as expected to the JWT token header.
        [Theory, MemberData(nameof(CreateJWSWithAdditionalHeaderClaimsTheoryData))]
        public void CreateJWSWithAdditionalHeaderClaims(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateJWSWithAdditionalHeaderClaims", theoryData);
            var jwtToken = new JsonWebTokenHandler().CreateToken(theoryData.TokenDescriptor);
            IdentityComparer.AreEqual(jwtToken, theoryData.JwtToken, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateTokenTheoryData> CreateJWSWithAdditionalHeaderClaimsTheoryData
        {
            get
            {
                return new TheoryData<CreateTokenTheoryData>
                {
                    new CreateTokenTheoryData
                    {
                        First = true,
                        TestId = "MultipleAdditionalHeaderClaims",
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            Claims = Default.ExpiredPayloadDictionary,
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            AdditionalHeaderClaims = new Dictionary<string, object>() { { "int", 123 }, { "string", "string" } }
                        },
                        JwtToken = ReferenceTokens.JWSWithMultipleAdditionalHeaderClaims
                    },
                    new CreateTokenTheoryData
                    {
                       TestId = "SingleAdditionalHeaderClaim",
                       TokenDescriptor =  new SecurityTokenDescriptor
                       {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Claims = Default.ExpiredPayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object> () { { "int", 123 } }
                       },
                       JwtToken = ReferenceTokens.JWSWithSingleAdditionalHeaderClaim
                    },
                    new CreateTokenTheoryData
                    {
                       TestId = "DifferentTypHeaderValue",
                       TokenDescriptor =  new SecurityTokenDescriptor
                       {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Claims = Default.ExpiredPayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object> () { { JwtHeaderParameterNames.Typ, "TEST" } }
                       },
                       JwtToken = ReferenceTokens.JWSWithDifferentTyp
                    },
                    new CreateTokenTheoryData
                    {
                       TestId = "EmptyAdditionalHeaderClaims",
                       TokenDescriptor =  new SecurityTokenDescriptor
                       {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Claims = Default.PayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object>()
                       },
                       JwtToken = new JsonWebTokenHandler().CreateToken(Default.PayloadString, KeyingMaterial.JsonWebKeyRsa256SigningCredentials)
                    },
                    new CreateTokenTheoryData
                    {
                       TestId = "UnsignedJWS",
                       TokenDescriptor =  new SecurityTokenDescriptor
                       {
                            Claims = Default.ExpiredPayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object> () { { "int", 123 } }
                       },
                       JwtToken = ReferenceTokens.UnsignedJWSWithSingleAdditionalHeaderClaim
                    },
                };
            }
        }

        // This test checks to make sure that additional header claims are added as expected to the outer token header.
        [Theory, MemberData(nameof(CreateJWEWithAdditionalHeaderClaimsTheoryData))]
        public void CreateJWEWithAdditionalHeaderClaims(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateJWEWithAdditionalHeaderClaims", theoryData);
            var handler = new JsonWebTokenHandler();

            var jwtTokenString = handler.CreateToken(theoryData.TokenDescriptor);
            var jwtToken = handler.ValidateToken(jwtTokenString, theoryData.ValidationParameters).SecurityToken as JsonWebToken;
            var jwtTokenToCompare = handler.ValidateToken(theoryData.JwtToken, theoryData.ValidationParameters).SecurityToken as JsonWebToken;

            context.PropertiesToIgnoreWhenComparing = new Dictionary<Type, List<string>>
            {
                { typeof(JsonWebToken), new List<string> { "EncodedToken", "AuthenticationTag", "Ciphertext", "InitializationVector", "EncryptedKey" } },
            };
            IdentityComparer.AreEqual(jwtToken, jwtTokenToCompare, context);

            foreach (var key in theoryData.TokenDescriptor.AdditionalHeaderClaims.Keys)
            {
                if (jwtToken.InnerToken.TryGetHeaderValue(key, out string headerValue) && !key.Equals(JwtHeaderParameterNames.Typ))
                    context.AddDiff($"Inner JWT header should not contain the '{key}' claim.");

                if (!jwtToken.TryGetHeaderValue(key, out headerValue))
                    context.AddDiff($"JWE header does not contain the '{key}' claim.");

                var headerValueToCompare = jwtTokenToCompare.GetHeaderValue<string>(key);

                if (headerValue != null && !headerValue.Equals(headerValueToCompare))
                    context.AddDiff($"The value for the '{key}' header claim should be '{headerValueToCompare}' but was '{headerValue}'.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateTokenTheoryData> CreateJWEWithAdditionalHeaderClaimsTheoryData
        {
            get
            {
                return new TheoryData<CreateTokenTheoryData>
                {
                    new CreateTokenTheoryData
                    {
                        First = true,
                        TestId = "JWEDirectEncryption",
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            Claims = Default.ExpiredPayloadDictionary,
                            SigningCredentials = Default.SymmetricSigningCredentials,
                            EncryptingCredentials = Default.SymmetricEncryptingCredentials,
                            AdditionalHeaderClaims = new Dictionary<string, object>() { { "int", 123 }, { "string", "string" } }
                        },
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
                            TokenDecryptionKey = Default.SymmetricEncryptingCredentials.Key,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            ClockSkew = ClockSkewToEnableTestsWithHardcodedTokens
                        },
                        JwtToken = ReferenceTokens.JWEDirectEcryptionWithAdditionalHeaderClaims
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "JWEDirectEncryptionWithDifferentTyp",
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            Claims = Default.ExpiredPayloadDictionary,
                            SigningCredentials = Default.SymmetricSigningCredentials,
                            EncryptingCredentials = Default.SymmetricEncryptingCredentials,
                            AdditionalHeaderClaims = new Dictionary<string, object>() { { JwtHeaderParameterNames.Typ, "TEST" } }
                        },
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
                            TokenDecryptionKey = Default.SymmetricEncryptingCredentials.Key,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            ClockSkew = ClockSkewToEnableTestsWithHardcodedTokens
                        },
                        JwtToken = ReferenceTokens.JWEDirectEcryptionWithDifferentTyp
                    },
                    new CreateTokenTheoryData
                    {
                       TestId = "JWEKeyWrapping",
                       TokenDescriptor =  new SecurityTokenDescriptor
                       {
                            SigningCredentials = Default.SymmetricSigningCredentials,
                            EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256),
                            Claims = Default.ExpiredPayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object>() { { "int", 123 }, { "string", "string" } }
                       },
                       ValidationParameters = new TokenValidationParameters
                       {
                            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
                            TokenDecryptionKey = KeyingMaterial.RsaSecurityKey_2048,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            ClockSkew = ClockSkewToEnableTestsWithHardcodedTokens
                       },
                       JwtToken = ReferenceTokens.JWEKeyWrappingWithAdditionalHeaderClaims
                    },
                    new CreateTokenTheoryData
                    {
                       TestId = "JWEKeyWrappingDifferentTyp",
                       TokenDescriptor =  new SecurityTokenDescriptor
                       {
                            SigningCredentials = Default.SymmetricSigningCredentials,
                            EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256),
                            Claims = Default.ExpiredPayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object>() { { JwtHeaderParameterNames.Typ, "TEST" } }
                       },
                       ValidationParameters = new TokenValidationParameters
                       {
                            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
                            TokenDecryptionKey = KeyingMaterial.RsaSecurityKey_2048,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            ClockSkew = ClockSkewToEnableTestsWithHardcodedTokens
                       },
                       JwtToken = ReferenceTokens.JWEKeyWrappingWithDifferentTyp
                    },
                    new CreateTokenTheoryData
                    {
                       TestId = "JWEKeyWrappingUnsignedInnerJwt",
                       TokenDescriptor =  new SecurityTokenDescriptor
                       {
                            EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256),
                            Claims = Default.ExpiredPayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object>() { { "int", 123 }, { "string", "string" } }
                       },
                       ValidationParameters = new TokenValidationParameters
                       {
                            TokenDecryptionKey = KeyingMaterial.RsaSecurityKey_2048,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            RequireSignedTokens = false,
                            ClockSkew = ClockSkewToEnableTestsWithHardcodedTokens
                       },
                       JwtToken = ReferenceTokens.JWEKeyWrappingUnsignedInnerJWTWithAdditionalHeaderClaims
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "JWEDirectEncryptionUnsignedInnerJWT",
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            Claims = Default.ExpiredPayloadDictionary,
                            EncryptingCredentials = Default.SymmetricEncryptingCredentials,
                            AdditionalHeaderClaims = new Dictionary<string, object>() { { "int", 123 }, { "string", "string" } }
                        },
                        ValidationParameters = new TokenValidationParameters
                        {
                            TokenDecryptionKey = Default.SymmetricEncryptingCredentials.Key,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer,
                            RequireSignedTokens = false,
                            ClockSkew = ClockSkewToEnableTestsWithHardcodedTokens
                        },
                        JwtToken = ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims
                    }
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
                string jwtFromString;
                if (theoryData.TokenDescriptor.SigningCredentials == null)
                    jwtFromString = theoryData.JsonWebTokenHandler.CreateToken(theoryData.Payload);
                else if (theoryData.TokenDescriptor.AdditionalHeaderClaims != null)
                    jwtFromString = theoryData.JsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.TokenDescriptor.SigningCredentials, theoryData.TokenDescriptor.AdditionalHeaderClaims);
                else
                    jwtFromString = theoryData.JsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.TokenDescriptor.SigningCredentials);

                var tokenValidationResultFromSecurityTokenDescriptor = theoryData.JsonWebTokenHandler.ValidateToken(jwtFromSecurityTokenDescriptor, theoryData.ValidationParameters);
                var tokenValidationResultFromString = theoryData.JsonWebTokenHandler.ValidateToken(jwtFromString, theoryData.ValidationParameters);

                IdentityComparer.AreEqual(tokenValidationResultFromSecurityTokenDescriptor.IsValid, theoryData.IsValid, context);
                IdentityComparer.AreEqual(tokenValidationResultFromString.IsValid, theoryData.IsValid, context);
                IdentityComparer.AreEqual(new JsonWebToken(jwtFromSecurityTokenDescriptor), new JsonWebToken(jwtFromString), context);

                var jwsTokenFromSecurityTokenDescriptor = new JsonWebToken(jwtFromSecurityTokenDescriptor);
                var jwsTokenFromString = new JsonWebToken(jwtFromString);

                // If the signing key used was an x509SecurityKey, make sure that the 'X5t' property was set properly and
                // that the values of 'X5t' and 'Kid' on the JsonWebToken are equal to each other.
                if (theoryData.TokenDescriptor.SigningCredentials?.Key is X509SecurityKey x509SecurityKey)
                {
                    IdentityComparer.AreEqual(jwsTokenFromSecurityTokenDescriptor.X5t, x509SecurityKey.X5t, context);
                    IdentityComparer.AreEqual(jwsTokenFromSecurityTokenDescriptor.Kid, x509SecurityKey.KeyId, context);
                    IdentityComparer.AreEqual(jwsTokenFromString.X5t, x509SecurityKey.X5t, context);
                    IdentityComparer.AreEqual(jwsTokenFromString.Kid, x509SecurityKey.KeyId, context);
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
                        TestId = "ValidUsingClaims",
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
                        TestId = "ValidUsingSubject",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Subject = Default.PayloadClaimsIdentity
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
                        TestId = "ValidUsingClaimsAndX509SecurityKey",
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
                            { JwtRegisteredClaimNames.Aud, Default.Audience },
                            { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(Default.Expires) },
                            { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(Default.IssueInstant) },
                            { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(Default.NotBefore) },
                        }.ToString(Formatting.None),
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            Audience = Default.Audience,
                            IssuedAt = Default.NotBefore,
                            NotBefore = Default.NotBefore,
                            Expires = Default.Expires,
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
                            { JwtRegisteredClaimNames.Aud, Default.Audience },
                            { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(Default.Expires) },
                            { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(Default.IssueInstant) },
                            { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(Default.NotBefore) },
                        }.ToString(Formatting.None),
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            Audience = Default.Audience,
                            IssuedAt = Default.NotBefore,
                            NotBefore = Default.NotBefore,
                            Expires = Default.Expires,
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
                        TestId = "TokenDescriptorSigningCredentialsNullRequireSignedTokensFalse",
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
                            ValidIssuer = Default.Issuer,
                            RequireSignedTokens = false
                        },
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "TokenDescriptorSigningCredentialsNullRequireSignedTokensTrue",
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
                            ValidIssuer = Default.Issuer,
                        },
                        IsValid = false
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
                            { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.Parse("2018-03-17T18:33:37.080Z")) },
                            { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(DateTime.Parse("2018-03-17T18:33:37.080Z")) },
                            { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(DateTime.Parse("2025-03-17T18:33:37.080Z")) },
                        }.ToString(Formatting.None),
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Claims = Default.PayloadDictionary,
                            Issuer = "Issuer",
                            Audience = "Audience",
                            IssuedAt = DateTime.Parse("2018-03-17T18:33:37.080Z"),
                            NotBefore = DateTime.Parse("2018-03-17T18:33:37.080Z"),
                            Expires = DateTime.Parse("2025-03-17T18:33:37.080Z")
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            ValidAudience = "Audience",
                            ValidIssuer = "Issuer"
                        }
                    },
                    // Test checks that the values in SecurityTokenDescriptor.Subject.Claims
                    // are properly combined with those specified in SecurityTokenDescriptor.Claims.
                    // Duplicate values (if present with different case) should not be overridden. 
                    // For example, the 'aud' claim on TokenDescriptor.Claims will not be overridden
                    // by the 'AUD' claim on TokenDescriptor.Subject.Claims, but the 'exp' claim will.
                    new CreateTokenTheoryData
                    {
                        TestId = "TokenDescriptorWithBothSubjectAndClaims",
                        Payload = new JObject()
                        {
                            { JwtRegisteredClaimNames.Email, "Bob@contoso.com" },
                            { JwtRegisteredClaimNames.GivenName, "Bob" },
                            { JwtRegisteredClaimNames.Iss, Default.Issuer },
                            { JwtRegisteredClaimNames.Aud.ToUpper(), JArray.FromObject(new List<string>() {"Audience1", "Audience2"}) },
                            { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(Default.IssueInstant).ToString() },
                            { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(Default.NotBefore).ToString()},
                            { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(Default.Expires).ToString() },
                            { JwtRegisteredClaimNames.Aud, JArray.FromObject(Default.Audiences) },
                        }.ToString(Formatting.None),
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Claims = new Dictionary<string, object>()
                            {
                                { JwtRegisteredClaimNames.Email, "Bob@contoso.com" },
                                { JwtRegisteredClaimNames.GivenName, "Bob" },
                                { JwtRegisteredClaimNames.Iss, Default.Issuer },
                                { JwtRegisteredClaimNames.Aud, JArray.FromObject(Default.Audiences) },
                                { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(Default.IssueInstant).ToString() },
                                { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(Default.NotBefore).ToString()},
                                { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(Default.Expires).ToString() },
                            },
                            Subject = new ClaimsIdentity(new List<Claim>()
                            {
                                new Claim(JwtRegisteredClaimNames.Email, "Bob@contoso.com", ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                                new Claim(JwtRegisteredClaimNames.GivenName, "Bob", ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                                new Claim(JwtRegisteredClaimNames.Iss, "Issuer", ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                                new Claim(JwtRegisteredClaimNames.Aud.ToUpper(), "Audience1", ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                                new Claim(JwtRegisteredClaimNames.Aud.ToUpper(), "Audience2", ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                                new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(Default.IssueInstant).ToString(), ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                                new Claim(JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(Default.NotBefore).ToString(), ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                                new Claim(JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(Default.Expires).ToString(), ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                            }, "AuthenticationTypes.Federation")
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            ValidAudience = Default.Audiences.First(),
                            ValidIssuer = Default.Issuer,
                        }
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "SingleAdditionalHeaderClaim",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Claims = Default.PayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object> () { { "int", 123 } }
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
                        TestId = "MultipleAdditionalHeaderClaims",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Claims = Default.PayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object> () { { "int", 123 }, { "string", "string" } }
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
                        TestId = "DuplicateAdditionalHeaderClaim",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Claims = Default.PayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object> () { { JwtHeaderParameterNames.Alg, "alg" } }
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        },
                        ExpectedException = ExpectedException.SecurityTokenException("IDX14116:")
                    },
                    new CreateTokenTheoryData
                    {
                        TestId = "DuplicateAdditionalHeaderClaimDifferentCase",
                        Payload = Default.PayloadString,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,

                            Claims = Default.PayloadDictionary,
                            AdditionalHeaderClaims = new Dictionary<string, object> () { { JwtHeaderParameterNames.Alg.ToUpper(), "alg" } }
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        },
                        ExpectedException = ExpectedException.SecurityTokenException("IDX14116:")
                    },
 #if NET461 || NET_CORE
                    // RsaPss is not supported on .NET < 4.6
                    new CreateTokenTheoryData
                    {
                        TestId = "RsaPss",
                        Payload = Default.PayloadString,
                        //RsaPss produces different signatures
                        PropertiesToIgnoreWhenComparing = new Dictionary<Type, List<string>>
                        {
                            { typeof(JsonWebToken), new List<string> { "EncodedToken", "EncodedSignature" } },
                        },
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            Claims = Default.PayloadDictionary,
                            SigningCredentials = new SigningCredentials(Default.AsymmetricSigningKey, SecurityAlgorithms.RsaSsaPssSha256),
                        },
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = Default.AsymmetricSigningKey,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            ValidateIssuer = false,
                        }
                    }
#endif
                };
            }
        }

        [Fact]
        public void CreateJWSWithDuplicateClaimsRoundTrip()
        {
            TestUtilities.WriteHeader($"{this}.CreateJWSWithDuplicateClaimsRoundTrip");
            var context = new CompareContext();

            var utcNow = DateTime.UtcNow;
            var jsonWebTokenHandler = new JsonWebTokenHandler();

            // This JObject has two duplicate claims (with different case): "aud"/"AUD" and "iat"/"IAT".
            var payload = new JObject()
            {
                { JwtRegisteredClaimNames.Email, "Bob@contoso.com" },
                { JwtRegisteredClaimNames.GivenName, "Bob" },
                { JwtRegisteredClaimNames.Iss, Default.Issuer },
                { JwtRegisteredClaimNames.Aud, Default.Audience },
                { JwtRegisteredClaimNames.Aud.ToUpper(), "Audience" },
                { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(Default.IssueInstant).ToString() },
                { JwtRegisteredClaimNames.Iat.ToUpper(), EpochTime.GetIntDate(utcNow).ToString() },
                { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(Default.NotBefore).ToString()},
                { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(Default.Expires).ToString() },
            };

            // This ClaimsIdentity has two duplicate claims (with different case): "aud"/"AUD" and "iat"/"IAT".
            var payloadClaimsIdentity = new ClaimsIdentity(new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Email, "Bob@contoso.com", ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                new Claim(JwtRegisteredClaimNames.GivenName, "Bob", ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                new Claim(JwtRegisteredClaimNames.Iss, Default.Issuer, ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                new Claim(JwtRegisteredClaimNames.Aud, Default.Audience, ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                new Claim(JwtRegisteredClaimNames.Aud.ToUpper(), "Audience", ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(Default.IssueInstant).ToString(), ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                new Claim(JwtRegisteredClaimNames.Iat.ToUpper(), EpochTime.GetIntDate(utcNow).ToString(), ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                new Claim(JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(Default.NotBefore).ToString(), ClaimValueTypes.String, Default.Issuer, Default.Issuer),
                new Claim(JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(Default.Expires).ToString(), ClaimValueTypes.String, Default.Issuer, Default.Issuer),
            });

            var securityTokenDescriptor = new SecurityTokenDescriptor()
            {
                Claims = payload.ToObject<Dictionary<string, object>>()
            };

            var jwtStringFromJObject = jsonWebTokenHandler.CreateToken(payload.ToString());
            var jwtStringFromDictionary = jsonWebTokenHandler.CreateToken(securityTokenDescriptor);

            securityTokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = payloadClaimsIdentity
            };

            var jwtStringFromSubject = jsonWebTokenHandler.CreateToken(securityTokenDescriptor);

            var jsonWebTokenFromPayload = new JsonWebToken(jwtStringFromJObject);
            var jsonWebTokenFromDictionary = new JsonWebToken(jwtStringFromDictionary);
            var jsonWebTokenFromSubject = new JsonWebToken(jwtStringFromSubject);

            IdentityComparer.AreEqual(payload, jsonWebTokenFromPayload.Payload, context);
            IdentityComparer.AreEqual(payload, jsonWebTokenFromDictionary.Payload, context);
            IdentityComparer.AreEqual(payload, jsonWebTokenFromSubject.Payload, context);

            TestUtilities.AssertFailIfErrors(context);
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
            IdentityComparer.AreEqual(Default.Payload, validatedToken.Payload, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(RoundTripJWEDirectEncryptionTheoryData))]
        public void RoundTripEncryptExistingJWSUsingDirectEncryption(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.RoundTripEncryptExistingJWSUsingDirectEncryption", theoryData);
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var innerJwt = jsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.SigningCredentials);
            var jweCreatedInMemory = jsonWebTokenHandler.EncryptToken(innerJwt, theoryData.EncryptingCredentials);
            try
            {
                var tokenValidationResult = jsonWebTokenHandler.ValidateToken(jweCreatedInMemory, theoryData.ValidationParameters);
                IdentityComparer.AreEqual(tokenValidationResult.IsValid, theoryData.IsValid, context);
                if (tokenValidationResult.Exception != null)
                    throw tokenValidationResult.Exception;

                var outerToken = tokenValidationResult.SecurityToken as JsonWebToken;

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

        [Theory, MemberData(nameof(RoundTripJWEDirectEncryptionTheoryData))]
        public void RoundTripJWEDirectEncryption(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.RoundTripJWEDirectEncryption", theoryData);
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            jwtSecurityTokenHandler.InboundClaimTypeMap.Clear();
            var jweCreatedInMemory = jsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.SigningCredentials, theoryData.EncryptingCredentials);
            try
            {
                var tokenValidationResult = jsonWebTokenHandler.ValidateToken(jweCreatedInMemory, theoryData.ValidationParameters);
                IdentityComparer.AreEqual(tokenValidationResult.IsValid, theoryData.IsValid, context);
                if (tokenValidationResult.Exception != null)
                    throw tokenValidationResult.Exception;

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
        public void RoundTripEncryptExistingJWSUsingKeyWrapping(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.RoundTripEncryptExistingJWSUsingKeyWrapping", theoryData);
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var innerJws = jsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.SigningCredentials);
            var jweCreatedInMemory = jsonWebTokenHandler.EncryptToken(innerJws, theoryData.EncryptingCredentials);
            try
            {
                var tokenValidationResult = jsonWebTokenHandler.ValidateToken(jweCreatedInMemory, theoryData.ValidationParameters);
                IdentityComparer.AreEqual(tokenValidationResult.IsValid, theoryData.IsValid, context);
                if (tokenValidationResult.Exception != null)
                    throw tokenValidationResult.Exception;

                var outerToken = tokenValidationResult.SecurityToken as JsonWebToken;

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

        [Theory, MemberData(nameof(RoundTripJWEKeyWrappingTheoryData))]
        public void RoundTripJWEKeyWrapping(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.RoundTripJWEKeyWrapping", theoryData);
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            jwtSecurityTokenHandler.InboundClaimTypeMap.Clear();
            var jweCreatedInMemory = jsonWebTokenHandler.CreateToken(theoryData.Payload, theoryData.SigningCredentials, theoryData.EncryptingCredentials);
            try
            {
                var tokenValidationResult = jsonWebTokenHandler.ValidateToken(jweCreatedInMemory, theoryData.ValidationParameters);
                IdentityComparer.AreEqual(tokenValidationResult.IsValid, theoryData.IsValid, context);
                if (tokenValidationResult.Exception != null)
                    throw tokenValidationResult.Exception;

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
            if (DateTime.MinValue.Equals(jwt.IssuedAt))
                context.AddDiff("DateTime.MinValue.Equals(jwt.IssuedAt). Value for the 'iat' claim not found in the payload.");
            if (DateTime.MinValue.Equals(jwt.ValidFrom))
                context.AddDiff("DateTime.MinValue.Equals(jwt.ValidFrom). Value for the 'nbf' claim not found in the payload.");
            if (DateTime.MinValue.Equals(jwt.ValidTo))
                context.AddDiff("DateTime.MinValue.Equals(jwt.ValidTo). Value for the 'exp' claim not found in the payload.");

            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that an access token can be successfully validated by the JsonWebTokenHandler.
        // Also ensures that a non-standard claim can be successfully retrieved from the payload and validated.
        [Fact]
        public void ValidateTokenClaims()
        {
            TestUtilities.WriteHeader($"{this}.ValidateTokenClaims");

            var tokenHandler = new JsonWebTokenHandler();
            var accessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlJzYVNlY3VyaXR5S2V5XzIwNDgiLCJ0eXAiOiJKV1QifQ.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwibmJmIjoiMTQ4OTc3NTYxNyIsImV4cCI6IjE2MTYwMDYwMTcifQ.GcIi6FGp1JS5VF70_ULa8g6GTRos9Y7rUZvPAo4hm10bBNfGhdd5uXgsJspiQzS8vwJQyPlq8a_BpL9TVKQyFIRQMnoZWe90htmNWszNYbd7zbLJZ9AuiDqDzqzomEmgcfkIrJ0VfbER57U46XPnUZQNng2XgMXrXmIKUqEph_vLGXYRQ4ndfwtRrR6BxQFd1PS1T5KpEoUTusI4VEsMcutzfXUygLDiRKIcnLFA0kQpeoHllO4Nb_Sxv63GCb0d1076FfSEYtyRxF4YSCz1In-ee5dwEK8Mw3nHscu-1hn0Fe98RBs-4OrUzI0WcV8mq9IIB3i-U-CqCJEP_hVCiA";
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = "http://Default.Audience.com",
                ValidIssuer = "http://Default.Issuer.com",
                IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                ClockSkew = ClockSkewToEnableTestsWithHardcodedTokens
            };
            var tokenValidationResult = tokenHandler.ValidateToken(accessToken, tokenValidationParameters);
            var jsonWebToken = tokenValidationResult.SecurityToken as JsonWebToken;
            var email = jsonWebToken.GetPayloadValue<string>(JwtRegisteredClaimNames.Email);

            if (!email.Equals("Bob@contoso.com"))
                throw new SecurityTokenException("Token does not contain the correct value for the 'email' claim.");
        }


        [Theory, MemberData(nameof(ValidateTypeTheoryData))]
        public void ValidateType(JwtTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateType", theoryData);

            var tokenValidationResult = new JsonWebTokenHandler().ValidateToken(theoryData.Token, theoryData.ValidationParameters);
            if (tokenValidationResult.Exception != null)
                theoryData.ExpectedException.ProcessException(tokenValidationResult.Exception);
            else
                theoryData.ExpectedException.ProcessNoException();

        }

        public static TheoryData<JwtTheoryData> ValidateTypeTheoryData = JwtSecurityTokenHandlerTests.ValidateTypeTheoryData;

        [Theory, MemberData(nameof(ValidateJwsTheoryData))]
        public void ValidateJWS(JwtTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateJWS", theoryData);

            try
            {
                var handler = new JsonWebTokenHandler();
                var validationResult = handler.ValidateToken(theoryData.Token, theoryData.ValidationParameters);
                if (validationResult.Exception != null)
                    throw validationResult.Exception;

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JwtTheoryData> ValidateJwsTheoryData
        {
            get
            {
                return new TheoryData<JwtTheoryData>
                {
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.SymmetricJws) + "RequireSignedTokens",
                        Token = Default.SymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            IssuerSigningKey = Default.SymmetricSigningKey,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new JwtTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10501:"),
                        TestId = nameof(Default.SymmetricJws) + "RequireSignedTokensNullSigningKey",
                        Token = Default.SymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            IssuerSigningKey = null,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.SymmetricJws) + "DontRequireSignedTokens",
                        Token = Default.SymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = false,
                            IssuerSigningKey = Default.SymmetricSigningKey,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.UnsignedJwt) + "DontRequireSignedTokensNullSigningKey",
                        Token = Default.UnsignedJwt,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = false,
                            IssuerSigningKey = null,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    }
                };
            }
        }

        [Theory, MemberData(nameof(JWECompressionTheoryData))]
        public void EncryptExistingJWSWithCompressionTest(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.EncryptExistingJWSWithCompressionTest", theoryData);

            try
            {
                var handler = new JsonWebTokenHandler();
                CompressionProviderFactory.Default = theoryData.CompressionProviderFactory;
                string innerJwt;
                if (theoryData.SigningCredentials != null)
                    innerJwt = handler.CreateToken(theoryData.Payload, theoryData.SigningCredentials);
                else
                    innerJwt = handler.CreateToken(theoryData.Payload);

                var jwtToken = handler.EncryptToken(innerJwt, theoryData.EncryptingCredentials, theoryData.CompressionAlgorithm);
                var validationResult = handler.ValidateToken(jwtToken, theoryData.ValidationParameters);
                if (validationResult.Exception != null)
                    throw validationResult.Exception;

                IdentityComparer.AreEqual(theoryData.Payload, (validationResult.SecurityToken as JsonWebToken).InnerToken.Payload.ToString(), context);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks that headers created with additional claims are not added to JsonWebTokenManager.KeyToHeaderCache.
        [Fact]
        public void HeaderCacheTest()
        {
            TestUtilities.WriteHeader($"{this}.HeaderCacheTest");
            var context = new CompareContext();
            var handler = new JsonWebTokenHandler();
            JsonWebTokenManager.KeyToHeaderCache.Clear();

            handler.CreateToken(Default.PayloadString, Default.AsymmetricSigningCredentials, new Dictionary<string, object> { { "string", "string" } });
            if (!JsonWebTokenManager.KeyToHeaderCache.IsEmpty)
                context.AddDiff("JsonWebTokenManager.KeyToHeaderCache is not empty. Headers created with additional claims SHOULD NOT be added to the cache.");

            handler.CreateToken(Default.PayloadString, Default.AsymmetricSigningCredentials);
            if (JsonWebTokenManager.KeyToHeaderCache.IsEmpty)
                context.AddDiff("JsonWebTokenManager.KeyToHeaderCache is empty. Headers created without additional claims SHOULD be added to the cache.");

            JsonWebTokenManager.KeyToHeaderCache.Clear();
            // If the the additionalHeaderClaims dictionary is empty we should still add a header to the cache.
            handler.CreateToken(Default.PayloadString, Default.AsymmetricSigningCredentials, new Dictionary<string, object>());
            if (JsonWebTokenManager.KeyToHeaderCache.IsEmpty)
                context.AddDiff("JsonWebTokenManager.KeyToHeaderCache is empty. Headers created without additional claims SHOULD be added to the cache.");

            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(JWECompressionTheoryData))]
        public void JWECompressionTest(CreateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.JWECompressionTest", theoryData);

            try
            {
                var handler = new JsonWebTokenHandler();
                CompressionProviderFactory.Default = theoryData.CompressionProviderFactory;
                string jwtToken;
                if (theoryData.SigningCredentials == null)
                    jwtToken = handler.CreateToken(theoryData.Payload, theoryData.EncryptingCredentials, theoryData.CompressionAlgorithm);
                else if (theoryData.AdditionalHeaderClaims != null)
                    jwtToken = handler.CreateToken(theoryData.Payload, theoryData.SigningCredentials, theoryData.EncryptingCredentials, theoryData.CompressionAlgorithm, theoryData.AdditionalHeaderClaims);
                else
                    jwtToken = handler.CreateToken(theoryData.Payload, theoryData.SigningCredentials, theoryData.EncryptingCredentials, theoryData.CompressionAlgorithm);

                var validationResult = handler.ValidateToken(jwtToken, theoryData.ValidationParameters);
                if (validationResult.Exception != null)
                    throw validationResult.Exception;

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

                var tokenValidationParametersRequireSignedTokensFalse = Default.TokenValidationParameters(KeyingMaterial.DefaultX509Key_2048, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key);
                tokenValidationParametersRequireSignedTokensFalse.ValidateLifetime = false;
                tokenValidationParametersRequireSignedTokensFalse.RequireSignedTokens = false;

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
                        TestId = "ValidAlgorithmWithAdditionalHeaderClaims",
                        AdditionalHeaderClaims = new Dictionary<string, object> () { { "int", 123 }, { "string", "string" } },
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
                        TestId = "NullSigningCredentialsRequireSignedTokensFalse",
                        CompressionAlgorithm = CompressionAlgorithms.Deflate,
                        CompressionProviderFactory = new CompressionProviderFactory(),
                        ValidationParameters = tokenValidationParametersRequireSignedTokensFalse,
                        Payload = Default.PayloadString,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256)
                    },
                    new CreateTokenTheoryData()
                    {
                        TestId = "NullSigningCredentialsRequireSignedTokensTrue",
                        CompressionAlgorithm = CompressionAlgorithms.Deflate,
                        CompressionProviderFactory = new CompressionProviderFactory(),
                        ValidationParameters = Default.JWECompressionTokenValidationParameters,
                        Payload = Default.PayloadString,
                        EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256),
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10504:")
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

        [Theory, MemberData(nameof(JweDecompressSizeTheoryData))]
        public void JWEDecompressionSizeTest(JWEDecompressionTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.JWEDecompressionTest", theoryData);

            try
            {
                var handler = new JsonWebTokenHandler();
                CompressionProviderFactory.Default = theoryData.CompressionProviderFactory;
                var validationResult = handler.ValidateToken(theoryData.JWECompressionString, theoryData.ValidationParameters);
                theoryData.ExpectedException.ProcessException(validationResult.Exception, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JWEDecompressionTheoryData> JweDecompressSizeTheoryData()
        {
            // The character 'U' compresses better because UUU in base 64, repeated characters compress best.
            JsonWebTokenHandler jwth = new JsonWebTokenHandler();
            SecurityKey key = new SymmetricSecurityKey(new byte[256 / 8]);
            EncryptingCredentials encryptingCredentials = new EncryptingCredentials(key, "dir", "A128CBC-HS256");
            TokenValidationParameters validationParameters = new TokenValidationParameters { TokenDecryptionKey = key };

            TheoryData<JWEDecompressionTheoryData> theoryData = new TheoryData<JWEDecompressionTheoryData>();
#if NETCOREAPP2_2
            string strU = new string('U', 20_000_000);
            string strUU = new string('U', 15_000_000);
#else
            string strU = new string('U', 100_000_000);
            string strUU = new string('U', 40_000_000);
#endif
            string payload = $@"{{""U"":""{strU}"", ""UU"":""{strUU}""}}";

            string token = jwth.CreateToken(payload, encryptingCredentials, "DEF");
            theoryData.Add(new JWEDecompressionTheoryData
            {
                CompressionProviderFactory = new CompressionProviderFactory(),
                ValidationParameters = validationParameters,
                JWECompressionString = token,
                TestId = "DeflateSizeExceeded",
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenDecompressionFailedException),
                    "IDX10679:",
                    typeof(SecurityTokenDecompressionFailedException))
            });

            strUU = new string('U', 50_000_000);
            payload = $@"{{""U"":""{strU}"", ""UU"":""{strUU}""}}";

            token = jwth.CreateToken(payload, encryptingCredentials, "DEF");
            theoryData.Add(new JWEDecompressionTheoryData
            {
                CompressionProviderFactory = new CompressionProviderFactory(),
                ValidationParameters = validationParameters,
                JWECompressionString = token,
                TestId = "TokenSizeExceeded",
                ExpectedException = new ExpectedException(
                    typeof(ArgumentException),
                    "IDX10209:")
            });

            return theoryData;
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
                if (validationResult.Exception != null)
                    throw validationResult.Exception;

                if (validationResult.IsValid)
                {
                    if (!validatedToken.Claims.Any())
                        context.Diffs.Add("validatedToken.Claims is empty.");
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

            var tokenValidationParametersRequireSignedTokensFalse = Default.TokenValidationParameters(KeyingMaterial.DefaultX509Key_2048, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key);
            tokenValidationParametersRequireSignedTokensFalse.ValidateLifetime = false;
            tokenValidationParametersRequireSignedTokensFalse.RequireSignedTokens = false;

            return new TheoryData<JWEDecompressionTheoryData>() {
                new JWEDecompressionTheoryData
                {
                    First = true,
                    ValidationParameters = Default.JWECompressionTokenValidationParameters,
                    JWECompressionString = ReferenceTokens.JWECompressionTokenWithDEF,
                    CompressionProviderFactory = CompressionProviderFactory.Default,
                    TestId = "ValidAlgorithm"
                },
                new JWEDecompressionTheoryData
                {
                    ValidationParameters = tokenValidationParametersRequireSignedTokensFalse,
                    JWECompressionString = ReferenceTokens.JWECompressionTokenWithUnsignedInnerJWS,
                    CompressionProviderFactory = CompressionProviderFactory.Default,
                    TestId = "ValidAlgorithmUnsignedInnerJWSRequireSignedTokensFalse"
                },
                new JWEDecompressionTheoryData
                {
                    ValidationParameters = Default.JWECompressionTokenValidationParameters,
                    JWECompressionString = ReferenceTokens.JWECompressionTokenWithUnsignedInnerJWS,
                    CompressionProviderFactory = CompressionProviderFactory.Default,
                    TestId = "ValidAlgorithmUnsignedInnerJWSRequireSignedTokensTrue",
                    ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10504:")
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
                }
                // Skip these tests as they set a static
                // We need to have a replacement model for custom compression
                //new JWEDecompressionTheoryData
                //{
                //    ValidationParameters = Default.JWECompressionTokenValidationParameters,
                //    JWECompressionString = ReferenceTokens.JWECompressionTokenWithDEF,
                //    CompressionProviderFactory = null,
                //    TestId = "NullCompressionProviderFactory",
                //    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:")
                //},
                //new JWEDecompressionTheoryData
                //{
                //    ValidationParameters = Default.JWECompressionTokenValidationParameters,
                //    CompressionProviderFactory = compressionProviderFactoryForCustom,
                //    JWECompressionString = ReferenceTokens.JWECompressionTokenWithCustomAlgorithm,
                //    TestId = "CustomCompressionProviderSucceeds"
                //},
                //new JWEDecompressionTheoryData
                //{
                //    ValidationParameters = Default.JWECompressionTokenValidationParameters,
                //    JWECompressionString = ReferenceTokens.JWECompressionTokenWithDEF,
                //    CompressionProviderFactory = compressionProviderFactoryForCustom2,
                //    TestId = "CustomCompressionProviderFails",
                //    ExpectedException = new ExpectedException(typeof(SecurityTokenDecompressionFailedException), "IDX10679:", typeof(SecurityTokenDecompressionFailedException))
                //}
            };
        }
    }

    public class CreateTokenTheoryData : TheoryDataBase
    {
        public Dictionary<string, object> AdditionalHeaderClaims { get; set; }

        public string Payload { get; set; }

        public string CompressionAlgorithm { get; set; }

        public CompressionProviderFactory CompressionProviderFactory { get; set; }

        public EncryptingCredentials EncryptingCredentials { get; set; }

        public bool IsValid { get; set; } = true;

        public SigningCredentials SigningCredentials { get; set; }

        public SecurityTokenDescriptor TokenDescriptor { get; set; }

        public JsonWebTokenHandler JsonWebTokenHandler { get; set; }

        public JwtSecurityTokenHandler JwtSecurityTokenHandler { get; set; }

        public string JwtToken { get; set; }

        public TokenValidationParameters ValidationParameters { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
