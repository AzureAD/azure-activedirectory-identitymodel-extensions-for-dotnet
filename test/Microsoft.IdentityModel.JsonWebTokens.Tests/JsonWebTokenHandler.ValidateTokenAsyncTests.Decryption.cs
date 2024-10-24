// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
#if NET472 || NET6_0_OR_GREATER
using System;
using Newtonsoft.Json.Linq;
#endif
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public partial class JsonWebTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_DecryptionTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_Decryption(ValidateTokenAsyncDecryptionTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_Decryption", theoryData);

            string jwtString = CreateEncryptedToken(theoryData.EncryptingCredentials, theoryData.AdditionalHeaderClaims);

            await ValidateAndCompareResults(jwtString, theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenAsyncDecryptionTheoryData> ValidateTokenAsync_DecryptionTestCases
        {
            get
            {
                var theoryData = new TheoryData<ValidateTokenAsyncDecryptionTheoryData>();

                theoryData.Add(new ValidateTokenAsyncDecryptionTheoryData("Valid_JWE_Aes128Cbc_HmacSha256")
                {
                    EncryptingCredentials = new EncryptingCredentials(
                        KeyingMaterial.DefaultX509Key_2048,
                        SecurityAlgorithms.RsaPKCS1,
                        SecurityAlgorithms.Aes128CbcHmacSha256),
                    TokenValidationParameters = CreateTokenValidationParameters(KeyingMaterial.DefaultX509Key_2048),
                    ValidationParameters = CreateValidationParameters(KeyingMaterial.DefaultX509Key_2048),
                });

#if NET472 || NET6_0_OR_GREATER
                theoryData.Add(new ValidateTokenAsyncDecryptionTheoryData("Valid_JWE_EcdhEs")
                {
                    EncryptingCredentials = new EncryptingCredentials(
                                    new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP521, true),
                                    SecurityAlgorithms.EcdhEsA256kw,
                                    SecurityAlgorithms.Aes128CbcHmacSha256)
                    {
                        KeyExchangePublicKey = KeyingMaterial.JsonWebKeyP521_Public
                    },
                    AdditionalHeaderClaims = AdditionalEcdhEsHeaderParameters(KeyingMaterial.JsonWebKeyP521_Public),
                    TokenValidationParameters = CreateTokenValidationParameters(new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP521, true)),
                    ValidationParameters = CreateValidationParameters(new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP521, true)),
                });
#endif

                theoryData.Add(new ValidateTokenAsyncDecryptionTheoryData("Invalid_JWE_NoDecryptionKeys")
                {
                    EncryptingCredentials = new EncryptingCredentials(
                            KeyingMaterial.DefaultX509Key_2048,
                            SecurityAlgorithms.RsaPKCS1,
                            SecurityAlgorithms.Aes128CbcHmacSha256),
                    TokenValidationParameters = CreateTokenValidationParameters(),
                    ValidationParameters = CreateValidationParameters(),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException("IDX10609:"),
                });

                theoryData.Add(new ValidateTokenAsyncDecryptionTheoryData("Invalid_JWE_WrongDecryptionKey")
                {
                    EncryptingCredentials = new EncryptingCredentials(
                            KeyingMaterial.DefaultX509Key_2048,
                            SecurityAlgorithms.RsaPKCS1,
                            SecurityAlgorithms.Aes128CbcHmacSha256),
                    TokenValidationParameters = CreateTokenValidationParameters(KeyingMaterial.DefaultRsaSecurityKey1),
                    ValidationParameters = CreateValidationParameters(KeyingMaterial.DefaultRsaSecurityKey1),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenKeyWrapException("IDX10618:"),
                    // Avoid comparing the full exception message as the stack traces for the inner exceptions are different.
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenKeyWrapException("IDX10618:"),
                });

                return theoryData;

                static TokenValidationParameters CreateTokenValidationParameters(
                    SecurityKey? tokenDecryptionKey = null, bool tryAllKeys = false)
                {
                    // Skip all validations. We just want to decrypt the JWE.
                    var tokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = false,
                        ValidateTokenReplay = false,
                        ValidateIssuerSigningKey = false,
                        RequireSignedTokens = false,
                        TokenDecryptionKey = tokenDecryptionKey,
                    };

                    return tokenValidationParameters;
                }

                static ValidationParameters CreateValidationParameters(SecurityKey? tokenDecryptionKey = null)
                {
                    ValidationParameters validationParameters = new ValidationParameters();

                    if (tokenDecryptionKey is not null)
                        validationParameters.TokenDecryptionKeys = [tokenDecryptionKey];


                    // Skip all validations. We just want to decrypt the JWE
                    validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
                    validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
                    validationParameters.IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
                    validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
                    validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
                    validationParameters.SignatureValidator = SkipValidationDelegates.SkipSignatureValidation;
                    validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;
                    validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;

                    return validationParameters;
                }


#if NET472 || NET6_0_OR_GREATER
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
            }
        }

        public class ValidateTokenAsyncDecryptionTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            public ValidateTokenAsyncDecryptionTheoryData(string testId) : base(testId) { }

            public EncryptingCredentials? EncryptingCredentials { get; set; }

            public Dictionary<string, object>? AdditionalHeaderClaims { get; set; } = null;
        }

        private static string CreateEncryptedToken(
            EncryptingCredentials? encryptingCredentials,
            Dictionary<string, object>? additionalHeaderClaims = null)
        {
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = Default.ClaimsIdentity,
                EncryptingCredentials = encryptingCredentials,
                AdditionalHeaderClaims = additionalHeaderClaims,
            };

            return jsonWebTokenHandler.CreateToken(securityTokenDescriptor);
        }
    }
}
#nullable restore
