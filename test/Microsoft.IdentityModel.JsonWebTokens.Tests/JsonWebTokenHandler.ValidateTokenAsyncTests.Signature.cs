// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public partial class JsonWebTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_SignatureTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_Signature(ValidateTokenAsyncSignatureTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_Signature", theoryData);

            string jwtString = CreateTokenWithSigningCredentials(theoryData.SigningCredentials);

            await ValidateAndCompareResults(jwtString, theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenAsyncSignatureTheoryData> ValidateTokenAsync_SignatureTestCases
        {
            get
            {
                var theoryData = new TheoryData<ValidateTokenAsyncSignatureTheoryData>();

                theoryData.Add(new ValidateTokenAsyncSignatureTheoryData("Valid_SignatureIsValid")
                {
                    SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
                    TokenValidationParameters = CreateTokenValidationParameters(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key),
                    ValidationParameters = CreateValidationParameters(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key),
                });

                theoryData.Add(new ValidateTokenAsyncSignatureTheoryData("Invalid_TokenIsNotSigned")
                {
                    SigningCredentials = null,
                    TokenValidationParameters = CreateTokenValidationParameters(),
                    ValidationParameters = CreateValidationParameters(),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10504:"),
                });

                theoryData.Add(new ValidateTokenAsyncSignatureTheoryData("Invalid_TokenSignedWithDifferentKey_KeyIdPresent_TryAllKeysFalse")
                {
                    SigningCredentials = Default.SymmetricSigningCredentials,
                    TokenValidationParameters = CreateTokenValidationParameters(Default.AsymmetricSigningKey),
                    ValidationParameters = CreateValidationParameters(Default.AsymmetricSigningKey),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10500:"),
                    // ValidateTokenAsync with ValidationParameters returns a different error message in the case where a
                    // key is not found in the IssuerSigningKeys collection and TryAllKeys is false.
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10502:"),
                });

                theoryData.Add(new ValidateTokenAsyncSignatureTheoryData("Invalid_TokenSignedWithDifferentKey_KeyIdPresent_TryAllKeysTrue")
                {
                    SigningCredentials = Default.SymmetricSigningCredentials,
                    TokenValidationParameters = CreateTokenValidationParameters(Default.AsymmetricSigningKey, tryAllKeys: true),
                    ValidationParameters = CreateValidationParameters(Default.AsymmetricSigningKey, tryAllKeys: true),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10503:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10503:"),
                });

                theoryData.Add(new ValidateTokenAsyncSignatureTheoryData("Invalid_TokenSignedWithDifferentKey_KeyIdNotPresent_TryAllKeysFalse")
                {
                    SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId,
                    TokenValidationParameters = CreateTokenValidationParameters(Default.AsymmetricSigningKey),
                    ValidationParameters = CreateValidationParameters(Default.AsymmetricSigningKey),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10500:"),
                });

                theoryData.Add(new ValidateTokenAsyncSignatureTheoryData("Invalid_TokenSignedWithDifferentKey_KeyIdNotPresent_TryAllKeysTrue")
                {
                    SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId,
                    TokenValidationParameters = CreateTokenValidationParameters(Default.AsymmetricSigningKey, tryAllKeys: true),
                    ValidationParameters = CreateValidationParameters(Default.AsymmetricSigningKey, tryAllKeys: true),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10517:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10517:"),
                });

                return theoryData;

                static TokenValidationParameters CreateTokenValidationParameters(SecurityKey? signingKey = null, bool tryAllKeys = false)
                {
                    // only validate the signature
                    var tokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = false,
                        ValidateTokenReplay = false,
                        ValidateIssuerSigningKey = false,
                        RequireSignedTokens = true,
                        IssuerSigningKey = signingKey,
                        TryAllIssuerSigningKeys = tryAllKeys,
                    };

                    return tokenValidationParameters;
                }

                static ValidationParameters CreateValidationParameters(
                    SecurityKey? signingKey = null, bool tryAllKeys = false)
                {
                    ValidationParameters validationParameters = new ValidationParameters();

                    if (signingKey is not null)
                        validationParameters.IssuerSigningKeys.Add(signingKey);

                    // Skip all validations except signature
                    validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
                    validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
                    validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
                    validationParameters.IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
                    validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
                    validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;
                    validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;
                    validationParameters.TryAllIssuerSigningKeys = tryAllKeys;

                    return validationParameters;
                }
            }
        }

        public class ValidateTokenAsyncSignatureTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            public ValidateTokenAsyncSignatureTheoryData(string testId) : base(testId) { }

            public SigningCredentials? SigningCredentials { get; set; }
        }
    }
}
#nullable restore
