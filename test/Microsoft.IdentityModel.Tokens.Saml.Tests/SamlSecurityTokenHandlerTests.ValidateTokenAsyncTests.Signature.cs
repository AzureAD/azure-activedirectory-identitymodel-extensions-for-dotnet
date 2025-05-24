// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
#nullable enable
    public partial class SamlSecurityTokenHandlerTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_Signature_TestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_SignatureComparison(ValidateTokenAsyncSignatureTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_SignatureComparison", theoryData);

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

        public static TheoryData<ValidateTokenAsyncSignatureTheoryData> ValidateTokenAsync_Signature_TestCases
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
                    ExpectedException = ExpectedException.SecurityTokenValidationException("IDX10504:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenValidationException("IDX10504:"),
                });

                theoryData.Add(new ValidateTokenAsyncSignatureTheoryData("Invalid_TokenSignedWithDifferentKey_KeyIdPresent_TryAllKeysFalse")
                {
                    SigningCredentials = Default.SymmetricSigningCredentials,
                    TokenValidationParameters = CreateTokenValidationParameters(Default.AsymmetricSigningKey),
                    ValidationParameters = CreateValidationParameters(Default.AsymmetricSigningKey),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10500:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10500:"),
                });

                theoryData.Add(new ValidateTokenAsyncSignatureTheoryData("Invalid_TokenSignedWithDifferentKey_KeyIdPresent_TryAllKeysTrue")
                {
                    SigningCredentials = Default.SymmetricSigningCredentials,
                    TokenValidationParameters = CreateTokenValidationParameters(Default.AsymmetricSigningKey, tryAllKeys: true),
                    ValidationParameters = CreateValidationParameters(Default.AsymmetricSigningKey, tryAllKeys: true),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10512:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10512:"),
                });

                theoryData.Add(new ValidateTokenAsyncSignatureTheoryData("Invalid_TokenSignedWithDifferentKey_KeyIdNotPresent_TryAllKeysFalse")
                {
                    SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId,
                    TokenValidationParameters = CreateTokenValidationParameters(Default.AsymmetricSigningKey),
                    ValidationParameters = CreateValidationParameters(Default.AsymmetricSigningKey),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10500:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10500:"),
                });

                theoryData.Add(new ValidateTokenAsyncSignatureTheoryData("Invalid_TokenSignedWithDifferentKey_KeyIdNotPresent_TryAllKeysTrue")
                {
                    SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId,
                    TokenValidationParameters = CreateTokenValidationParameters(Default.AsymmetricSigningKey, tryAllKeys: true),
                    ValidationParameters = CreateValidationParameters(Default.AsymmetricSigningKey, tryAllKeys: true),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10512:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10512:"),
                });

                theoryData.Add(new ValidateTokenAsyncSignatureTheoryData("Invalid_TokenValidationParametersAndValidationParametersAreNull")
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                    ExpectedIsValid = false,
                });

                return theoryData;

                static ValidationParameters CreateValidationParameters(
                    SecurityKey? issuerSigingKey = null, bool tryAllKeys = false)
                {
                    ValidationParameters validationParameters = new ValidationParameters();
                    validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
                    validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
                    validationParameters.IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
                    validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
                    validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
                    validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;
                    validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;
                    validationParameters.TryAllIssuerSigningKeys = tryAllKeys;

                    if (issuerSigingKey is not null)
                        validationParameters.IssuerSigningKeys.Add(issuerSigingKey);

                    return validationParameters;
                }

                static TokenValidationParameters CreateTokenValidationParameters(
                    SecurityKey? issuerSigningKey = null, bool tryAllKeys = false)
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
                        IssuerSigningKey = issuerSigningKey,
                        TryAllIssuerSigningKeys = tryAllKeys,
                    };
                }
            }
        }

        public class ValidateTokenAsyncSignatureTheoryData : TheoryDataBase
        {
            public ValidateTokenAsyncSignatureTheoryData(string testId) : base(testId) { }

            internal ExpectedException? ExpectedExceptionValidationParameters { get; set; } = ExpectedException.NoExceptionExpected;

            internal SigningCredentials? SigningCredentials { get; set; } = null;

            internal bool ExpectedIsValid { get; set; } = true;

            internal ValidationParameters? ValidationParameters { get; set; }

            internal TokenValidationParameters? TokenValidationParameters { get; set; }
        }

        private static SamlSecurityToken CreateTokenForSignatureValidation(SigningCredentials? signingCredentials)
        {
            SamlSecurityTokenHandler samlTokenHandler = new SamlSecurityTokenHandler();

            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = Default.SamlClaimsIdentity,
                SigningCredentials = signingCredentials,
                Issuer = Default.Issuer,
            };

            SamlSecurityToken samlToken = (SamlSecurityToken)samlTokenHandler.CreateToken(securityTokenDescriptor);

            return samlTokenHandler.ReadSamlToken(samlToken.Assertion.CanonicalString);
        }
    }
}
#nullable restore
