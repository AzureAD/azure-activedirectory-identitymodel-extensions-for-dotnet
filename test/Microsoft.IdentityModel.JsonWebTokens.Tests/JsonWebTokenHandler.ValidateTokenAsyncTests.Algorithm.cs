// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public partial class JsonWebTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_AlgorithmTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_Algorithm(ValidateTokenAsyncAlgorithmTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_Algorithm", theoryData);

            string jwtString = CreateTokenWithSigningCredentials(theoryData.SigningCredentials);

            await ValidateAndCompareResults(jwtString, theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenAsyncAlgorithmTheoryData> ValidateTokenAsync_AlgorithmTestCases
        {
            get
            {
                var theoryData = new TheoryData<ValidateTokenAsyncAlgorithmTheoryData>();

                theoryData.Add(new ValidateTokenAsyncAlgorithmTheoryData("Valid_AlgorithmIsValid")
                {
                    SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
                    TokenValidationParameters = CreateTokenValidationParameters(
                        KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key,
                        validAlgorithms: [SecurityAlgorithms.RsaSha256Signature]),
                    ValidationParameters = CreateValidationParameters(
                        KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key,
                        validAlgorithms: [SecurityAlgorithms.RsaSha256Signature]),
                });

                theoryData.Add(new ValidateTokenAsyncAlgorithmTheoryData("Valid_ValidAlgorithmsIsNull")
                {
                    SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
                    TokenValidationParameters = CreateTokenValidationParameters(
                        KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key,
                        validAlgorithms: null),
                    ValidationParameters = CreateValidationParameters(
                        KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key,
                        validAlgorithms: null),
                });

                theoryData.Add(new ValidateTokenAsyncAlgorithmTheoryData("Valid_ValidAlgorithmsIsEmptyList")
                {
                    SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
                    TokenValidationParameters = CreateTokenValidationParameters(
                        KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key, validAlgorithms: []),
                    ValidationParameters = CreateValidationParameters(
                        KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key, validAlgorithms: []),
                });

                theoryData.Add(new ValidateTokenAsyncAlgorithmTheoryData("Invalid_TokenIsSignedWithAnInvalidAlgorithm")
                {
                    // Token is signed with HmacSha256 but only sha256 is considered valid for this test's purposes
                    SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                    TokenValidationParameters = CreateTokenValidationParameters(
                            KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            validAlgorithms: [SecurityAlgorithms.Sha256]),
                    ValidationParameters = CreateValidationParameters(
                            KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            validAlgorithms: [SecurityAlgorithms.Sha256]),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10511:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidAlgorithmException(
                        "IDX10518:",
                        propertiesExpected: new() { { "InvalidAlgorithm", SecurityAlgorithms.HmacSha256Signature } }),
                });

                return theoryData;

                static TokenValidationParameters CreateTokenValidationParameters(
                    SecurityKey? signingKey = null, List<string>? validAlgorithms = null)
                {
                    // only validate the signature and algorithm
                    var tokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = false,
                        ValidateTokenReplay = false,
                        ValidateIssuerSigningKey = false,
                        RequireSignedTokens = true,
                        IssuerSigningKey = signingKey,
                    };

                    tokenValidationParameters.ValidAlgorithms = validAlgorithms;

                    return tokenValidationParameters;
                }

                static ValidationParameters CreateValidationParameters(
                    SecurityKey? signingKey = null, List<string>? validAlgorithms = null)
                {
                    ValidationParameters validationParameters = new ValidationParameters();

                    if (signingKey is not null)
                        validationParameters.IssuerSigningKeys.Add(signingKey);

                    validationParameters.ValidAlgorithms = validAlgorithms;

                    // Skip all validations except signature and algorithm
                    validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
                    validationParameters.IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
                    validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
                    validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
                    validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;
                    validationParameters.TypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;

                    return validationParameters;
                }
            }
        }

        public class ValidateTokenAsyncAlgorithmTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            public ValidateTokenAsyncAlgorithmTheoryData(string testId) : base(testId) { }

            public SigningCredentials? SigningCredentials { get; set; }
        }
    }
}
#nullable restore
