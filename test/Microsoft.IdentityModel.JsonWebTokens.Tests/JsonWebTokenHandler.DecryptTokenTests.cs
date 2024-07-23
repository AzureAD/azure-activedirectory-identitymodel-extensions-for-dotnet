// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt.Tests;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerDecryptTokenTests
    {
        [Theory, MemberData(nameof(JsonWebTokenHandlerDecryptTokenTestCases), DisableDiscoveryEnumeration = false)]
        public void DecryptToken(TokenDecryptingTheoryData theoryData)
        {
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();
            if (theoryData.Token == null)
            {
                string tokenString = null;
                if (theoryData.SecurityTokenDescriptor != null)
                    tokenString = jsonWebTokenHandler.CreateToken(theoryData.SecurityTokenDescriptor);
                else
                    tokenString = theoryData.TokenString;

                if (tokenString != null)
                    theoryData.Token = new JsonWebToken(tokenString);
            }

            if (theoryData.TestId == "Invalid_NoKeysProvided")
            {
#pragma warning disable CS0219 // Variable is assigned but its value is never used
                var something = 0;
#pragma warning restore CS0219 // Variable is assigned but its value is never used
            }

            CompareContext context = TestUtilities.WriteHeader($"{this}.JsonWebTokenHandlerDecryptTokenTests", theoryData);
            TokenDecryptingResult tokenDecryptingResult = jsonWebTokenHandler.DecryptToken(
                theoryData.Token,
                theoryData.ValidationParameters,
                theoryData.Configuration,
                new CallContext());

            if (tokenDecryptingResult.Exception != null)
                theoryData.ExpectedException.ProcessException(tokenDecryptingResult.Exception);
            else
                theoryData.ExpectedException.ProcessNoException();

            IdentityComparer.AreTokenDecryptingResultsEqual(
                tokenDecryptingResult,
                theoryData.TokenDecryptingResult,
                context);

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void DecryptToken_ThrowsIfAccessingSecurityTokenOnFailedRead()
        {
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();
            TokenDecryptingResult tokenDecryptingResult = jsonWebTokenHandler.DecryptToken(
                null,
                null,
                null,
                new CallContext());

            Assert.Throws<InvalidOperationException>(() => tokenDecryptingResult.DecryptedToken());
        }

        public static TheoryData<TokenDecryptingTheoryData> JsonWebTokenHandlerDecryptTokenTestCases
        {
            get
            {
                var validToken = EncodedJwts.LiveJwt;
                var token = new JsonWebToken(validToken);
#if NET472 || NET6_0_OR_GREATER
                var ecdsaEncryptingCredentials = new EncryptingCredentials(
                                new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, true),
                                SecurityAlgorithms.EcdhEsA256kw,
                                SecurityAlgorithms.Aes128CbcHmacSha256)
                {
                    KeyExchangePublicKey = KeyingMaterial.JsonWebKeyP256_Public
                };
                var ecdsaTokenDescriptor = new SecurityTokenDescriptor
                {
                    EncryptingCredentials = ecdsaEncryptingCredentials,
                    Expires = DateTime.MaxValue,
                    NotBefore = DateTime.MinValue,
                    IssuedAt = DateTime.MinValue,
                };

                var jsonWebTokenHandler = new JsonWebTokenHandler();
                var ecdsaToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(ecdsaTokenDescriptor));
#endif

                return new TheoryData<TokenDecryptingTheoryData>
                {
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Invalid_TokenIsNotEncrypted",
                        Token = token,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenException("IDX10612:"),
                        TokenDecryptingResult = new TokenDecryptingResult(
                            token,
                            ValidationFailureType.TokenDecryptingFailed,
                            new ExceptionDetail(
                                new MessageDetail(TokenLogMessages.IDX10612),
                                typeof(SecurityTokenException),
                                new StackFrame(), null)),
                    },
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Invalid_SecurityTokenIsNull",
                        Token = null,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        TokenDecryptingResult = new TokenDecryptingResult(
                            null,
                            ValidationFailureType.TokenDecryptingFailed,
                            new ExceptionDetail(
                                new MessageDetail(TokenLogMessages.IDX10000, "jwtToken"),
                                typeof(ArgumentNullException),
                                new StackFrame(true))),
                    },
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Invalid_ValidationParametersIsNull",
                        Token = token,
                        ValidationParameters = null,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        TokenDecryptingResult = new TokenDecryptingResult(
                            token,
                            ValidationFailureType.TokenDecryptingFailed,
                            new ExceptionDetail(
                                new MessageDetail(TokenLogMessages.IDX10000, "validationParameters"),
                                typeof(ArgumentNullException),
                                new StackFrame(true))),
                    },
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Valid_Aes128_FromValidationParameters",
                        TokenString = ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims,
                        ValidationParameters = new ValidationParameters
                        {
                            TokenDecryptionKeys = [Default.SymmetricEncryptingCredentials.Key],
                        },
                        TokenDecryptingResult = new TokenDecryptingResult(
                            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIyNTM0MDIzMDA3OTkifQ.",
                            new JsonWebToken(ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims)),
                    },
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Valid_Aes128_FromKeyResolver",
                        TokenString = ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims,
                        ValidationParameters = new ValidationParameters
                        {
                            TokenDecryptionKeyResolver = (tokenString, token, kid, validationParameters, callContext) => [Default.SymmetricEncryptingCredentials.Key]
                        },
                        TokenDecryptingResult = new TokenDecryptingResult(
                            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIyNTM0MDIzMDA3OTkifQ.",
                            new JsonWebToken(ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims)),
                    },
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Valid_Aes128_FromConfiguration",
                        TokenString = ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims,
                        ValidationParameters = new ValidationParameters(),
                        Configuration = new CustomConfiguration(Default.SymmetricEncryptingCredentials.Key),
                        TokenDecryptingResult = new TokenDecryptingResult(
                            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIyNTM0MDIzMDA3OTkifQ.",
                            new JsonWebToken(ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims)),
                    },
#if NET472 || NET6_0_OR_GREATER
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Valid_Ecdsa256_FromValidationParameters",
                        Token = ecdsaToken,
                        ValidationParameters = new ValidationParameters
                        {
                            TokenDecryptionKeys = [new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, true)],
                            EphemeralDecryptionKey = new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, true)
                        },
                        TokenDecryptingResult = new TokenDecryptingResult(
                            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjI1MzQwMjMwMDgwMCwiaWF0IjowLCJuYmYiOjB9.",
                            ecdsaToken),
                    },
#endif
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Valid_NullKeysFromResolver_DegeneratePath",
                        TokenString = ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims,
                        ValidationParameters = new ValidationParameters
                        {
                            TokenDecryptionKeyResolver = (tokenString, token, kid, validationParameters, callContext) => null,
                            TokenDecryptionKeys = [Default.SymmetricEncryptingCredentials.Key],
                        },
                        TokenDecryptingResult = new TokenDecryptingResult(
                            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIyNTM0MDIzMDA3OTkifQ.",
                            new JsonWebToken(ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims)),
                    },
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Invalid_NoKeysProvided",
                        TokenString = ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenException("IDX10609:"),
                        TokenDecryptingResult = new TokenDecryptingResult( 
                            new JsonWebToken(ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims),
                            ValidationFailureType.TokenDecryptingFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    TokenLogMessages.IDX10609,
                                    LogHelper.MarkAsSecurityArtifact(
                                        new JsonWebToken(ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims),
                                        JwtTokenUtilities.SafeLogJwtToken)),
                                typeof(SecurityTokenException),
                                new StackFrame(), null)),
                    }
                };
            }
        }
    }

    public class TokenDecryptingTheoryData : TheoryDataBase
    {
        public JsonWebToken Token { get; set; }
        public object TokenDecryptingResult { get; set; }
        public BaseConfiguration Configuration { get; internal set; }
        public SecurityTokenDescriptor SecurityTokenDescriptor { get; internal set; }
        public string TokenString { get; internal set; }
        internal ValidationParameters ValidationParameters { get; set; }
    }

    public class CustomConfiguration : BaseConfiguration
    {
        public CustomConfiguration(SecurityKey tokenDecryptionKey) : base()
        {
            TokenDecryptionKeys.Add(tokenDecryptionKey);
        }
    }
}
