// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
#if NET472_OR_GREATER || NET6_0_OR_GREATER
using System.Collections.Generic;
using Newtonsoft.Json.Linq;
#endif
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

            CompareContext context = TestUtilities.WriteHeader($"{this}.JsonWebTokenHandlerDecryptTokenTests", theoryData);
            Result<string> result = jsonWebTokenHandler.DecryptToken(
                theoryData.Token,
                theoryData.ValidationParameters,
                theoryData.Configuration,
                new CallContext());

            if (result.IsSuccess)
            {
                IdentityComparer.AreStringsEqual(
                    result.UnwrapResult(),
                    theoryData.Result.UnwrapResult(),
                    context);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            else
            {
                ExceptionDetail exceptionDetail = result.UnwrapError();
                IdentityComparer.AreStringsEqual(
                    exceptionDetail.FailureType.Name,
                    theoryData.Result.UnwrapError().FailureType.Name,
                    context);

                Exception exception = exceptionDetail.GetException();
                theoryData.ExpectedException.ProcessException(exception, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void DecryptToken_ThrowsIfAccessingSecurityTokenOnFailedRead()
        {
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();
            Result<string> tokenDecryptionResult = jsonWebTokenHandler.DecryptToken(
                null,
                null,
                null,
                new CallContext());

            Assert.Throws<InvalidOperationException>(() => tokenDecryptionResult.UnwrapResult());
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
                    AdditionalHeaderClaims = AdditionalEcdhEsHeaderParameters(KeyingMaterial.JsonWebKeyP256_Public),
                };

                var jsonWebTokenHandler = new JsonWebTokenHandler();
                var ecdsaToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(ecdsaTokenDescriptor));

                static Dictionary<string, object> AdditionalEcdhEsHeaderParameters(JsonWebKey publicKeySender)
                {
                    var epkJObject = new JObject();
                    epkJObject.Add(JsonWebKeyParameterNames.Kty, publicKeySender.Kty);
                    epkJObject.Add(JsonWebKeyParameterNames.Crv, publicKeySender.Crv);
                    epkJObject.Add(JsonWebKeyParameterNames.X, publicKeySender.X);
                    epkJObject.Add(JsonWebKeyParameterNames.Y, publicKeySender.Y);

                    Dictionary<string, object> additionalHeaderParams = new Dictionary<string, object>()
                    {
                        { JsonWebTokens.JwtHeaderParameterNames.Apu, Guid.NewGuid().ToString() },
                        { JsonWebTokens.JwtHeaderParameterNames.Apv, Guid.NewGuid().ToString() },
                        { JsonWebTokens.JwtHeaderParameterNames.Epk, epkJObject.ToString(Newtonsoft.Json.Formatting.None) }
                    };

                    return additionalHeaderParams;
                }
#endif

                return new TheoryData<TokenDecryptingTheoryData>
                {
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Invalid_TokenIsNotEncrypted",
                        Token = token,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenException("IDX10612:"),
                        Result = new ExceptionDetail(
                            new MessageDetail(TokenLogMessages.IDX10612),
                            ValidationFailureType.TokenDecryptionFailed,
                            typeof(SecurityTokenException),
                            null),
                    },
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Invalid_SecurityTokenIsNull",
                        Token = null,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Result = new ExceptionDetail(
                            new MessageDetail(TokenLogMessages.IDX10000, "jwtToken"),
                            ValidationFailureType.NullArgument,
                            typeof(ArgumentNullException),
                            null),
                    },
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Invalid_ValidationParametersIsNull",
                        Token = token,
                        ValidationParameters = null,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Result = new ExceptionDetail(
                            new MessageDetail(TokenLogMessages.IDX10000, "validationParameters"),
                            ValidationFailureType.NullArgument,
                            typeof(ArgumentNullException),
                            null),
                    },
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Valid_Aes128_FromValidationParameters",
                        TokenString = ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims,
                        ValidationParameters = new ValidationParameters
                        {
                            TokenDecryptionKeys = [Default.SymmetricEncryptingCredentials.Key],
                        },
                        Result = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIyNTM0MDIzMDA3OTkifQ.",
                    },
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Valid_Aes128_FromKeyResolver",
                        TokenString = ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims,
                        ValidationParameters = new ValidationParameters
                        {
                            TokenDecryptionKeyResolver = (tokenString, token, kid, validationParameters, callContext) => [Default.SymmetricEncryptingCredentials.Key]
                        },
                        Result = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIyNTM0MDIzMDA3OTkifQ.",
                    },
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Valid_Aes128_FromConfiguration",
                        TokenString = ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims,
                        ValidationParameters = new ValidationParameters(),
                        Configuration = new CustomConfiguration(Default.SymmetricEncryptingCredentials.Key),
                        Result = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIyNTM0MDIzMDA3OTkifQ.",
                    },
#if NET472 || NET6_0_OR_GREATER
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Valid_Ecdsa256_FromValidationParameters",
                        Token = ecdsaToken,
                        ValidationParameters = new ValidationParameters
                        {
                            TokenDecryptionKeys = [new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, true)],
                        },
                        Result = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjI1MzQwMjMwMDgwMCwiaWF0IjowLCJuYmYiOjB9."
                    },
#endif
                    new TokenDecryptingTheoryData
                    {
                        TestId = "Invalid_NoKeysProvided",
                        TokenString = ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException("IDX10609:"),
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                TokenLogMessages.IDX10609,
                                LogHelper.MarkAsSecurityArtifact(
                                    new JsonWebToken(ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims),
                                    JwtTokenUtilities.SafeLogJwtToken)),
                            ValidationFailureType.TokenDecryptionFailed,
                            typeof(SecurityTokenDecryptionFailedException),
                            null),
                    }
                };
            }
        }
    }

    public class TokenDecryptingTheoryData : TheoryDataBase
    {
        public JsonWebToken Token { get; set; }
        internal Result<string> Result { get; set; }
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
