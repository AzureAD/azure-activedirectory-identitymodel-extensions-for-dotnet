// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
#nullable enable
    public partial class SamlSecurityTokenHandlerTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_Algorithm_TestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_AlgorithmComparison(ValidateTokenAsyncAlgorithmTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_AlgorithmComparison", theoryData);

            SamlSecurityTokenHandler samlTokenHandler = new SamlSecurityTokenHandler();

            var samlToken = CreateTokenForSignatureValidation(theoryData.SigningCredentials);

            // Validate the token using TokenValidationParameters
            TokenValidationResult tokenValidationResult =
                await samlTokenHandler.ValidateTokenAsync(samlToken.Assertion.CanonicalString, theoryData.TokenValidationParameters);

            // Validate the token using ValidationParameters.
            ValidationResult<ValidatedToken> validationResult =
                await samlTokenHandler.ValidateTokenAsync(
                    samlToken,
                    theoryData.ValidationParameters!,
                    theoryData.CallContext,
                    CancellationToken.None);

            // Ensure the validity of the results match the expected result.
            if (tokenValidationResult.IsValid != validationResult.IsValid)
            {
                context.AddDiff($"tokenValidationResult.IsValid != validationResult.IsSuccess");
                theoryData.ExpectedExceptionValidationParameters!.ProcessException(validationResult.UnwrapError().GetException(), context);
                theoryData.ExpectedException.ProcessException(tokenValidationResult.Exception, context);
            }
            else
            {
                if (tokenValidationResult.IsValid)
                {
                    // Verify that the validated tokens from both paths match.
                    ValidatedToken validatedToken = validationResult.UnwrapResult();
                    IdentityComparer.AreEqual(validatedToken.SecurityToken, tokenValidationResult.SecurityToken, context);
                }
                else
                {
                    // Verify the exception provided by both paths match.
                    var tokenValidationResultException = tokenValidationResult.Exception;
                    var validationResultException = validationResult.UnwrapError().GetException();

                    if (theoryData.TestId == "Invalid_TokenSignedWithDifferentKey_KeyIdPresent_TryAllKeysFalse")
                        Console.WriteLine($"tokenValidationResultException: {tokenValidationResultException}");

                    theoryData.ExpectedException.ProcessException(tokenValidationResult.Exception, context);
                    theoryData.ExpectedExceptionValidationParameters!.ProcessException(validationResult.UnwrapError().GetException(), context);
                }

                TestUtilities.AssertFailIfErrors(context);
            }
        }

        public static TheoryData<ValidateTokenAsyncAlgorithmTheoryData> ValidateTokenAsync_Algorithm_TestCases
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

                theoryData.Add(new ValidateTokenAsyncAlgorithmTheoryData("Invalid_TokenIsSignedWithAnInvalidAlgorithm_TryAllKeysFalse")
                {
                    // Token is signed with HmacSha256 but only sha256 is considered valid for this test's purposes
                    SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                    TokenValidationParameters = CreateTokenValidationParameters(
                            KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            validAlgorithms: [SecurityAlgorithms.Sha256],
                            tryAllKeys: false),
                    ValidationParameters = CreateValidationParameters(
                            KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            validAlgorithms: [SecurityAlgorithms.Sha256],
                            tryAllKeys: false),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10500:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10500:"),
                });

                theoryData.Add(new ValidateTokenAsyncAlgorithmTheoryData("Invalid_TokenIsSignedWithAnInvalidAlgorithm_TryAllKeysTrue")
                {
                    // Token is signed with HmacSha256 but only sha256 is considered valid for this test's purposes
                    SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                    TokenValidationParameters = CreateTokenValidationParameters(
                            KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            validAlgorithms: [SecurityAlgorithms.Sha256],
                            tryAllKeys: true),
                    ValidationParameters = CreateValidationParameters(
                            KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            validAlgorithms: [SecurityAlgorithms.Sha256],
                            tryAllKeys: true),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10512:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10512:"),
                });

                return theoryData;

                static ValidationParameters CreateValidationParameters(
                    SecurityKey? signingKey = null, List<string>? validAlgorithms = null, bool tryAllKeys = false)
                {
                    ValidationParameters validationParameters = new ValidationParameters();

                    if (signingKey is not null)
                        validationParameters.IssuerSigningKeys.Add(signingKey);

                    validationParameters.ValidAlgorithms = validAlgorithms;

                    validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
                    validationParameters.IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
                    validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
                    validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
                    validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;
                    validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;
                    validationParameters.TryAllIssuerSigningKeys = tryAllKeys;

                    return validationParameters;
                }

                static TokenValidationParameters CreateTokenValidationParameters(
                    SecurityKey? signingKey = null, List<string>? validAlgorithms = null, bool tryAllKeys = false)
                {
                    return new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = false,
                        ValidateTokenReplay = false,
                        ValidateIssuerSigningKey = false,
                        RequireSignedTokens = true,
                        RequireAudience = false,
                        IssuerSigningKey = signingKey,
                        ValidAlgorithms = validAlgorithms,
                        TryAllIssuerSigningKeys = tryAllKeys,
                    };
                }
            }
        }

        public class ValidateTokenAsyncAlgorithmTheoryData : TheoryDataBase
        {
            public ValidateTokenAsyncAlgorithmTheoryData(string testId) : base(testId) { }

            internal ExpectedException? ExpectedExceptionValidationParameters { get; set; } = ExpectedException.NoExceptionExpected;

            internal SigningCredentials? SigningCredentials { get; set; } = null;

            internal bool ExpectedIsValid { get; set; } = true;

            internal ValidationParameters? ValidationParameters { get; set; }

            internal TokenValidationParameters? TokenValidationParameters { get; set; }
        }

    }
}
#nullable restore
