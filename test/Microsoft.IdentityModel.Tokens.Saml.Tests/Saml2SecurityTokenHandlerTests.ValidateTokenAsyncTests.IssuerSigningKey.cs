// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Saml2;
using Xunit;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    public partial class Saml2SecurityTokenHandlerTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_IssuerSigningKey_TestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_IssuerSigningKeyComparison(ValidateTokenAsyncIssuerSigningKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_IssuerSigningKeyComparison", theoryData);

            Saml2SecurityTokenHandler saml2TokenHandler = new Saml2SecurityTokenHandler();

            var saml2Token = CreateTokenForSignatureValidation(theoryData.SigningCredentials);

            // Validate the token using TokenValidationParameters
            TokenValidationResult tokenValidationResult =
                await saml2TokenHandler.ValidateTokenAsync(saml2Token.Assertion.CanonicalString, theoryData.TokenValidationParameters!);

            // Validate the token using ValidationParameters.
            ValidationResult<ValidatedToken> validationResult =
                await saml2TokenHandler.ValidateTokenAsync(
                    saml2Token,
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
                    theoryData.ExpectedException.ProcessException(tokenValidationResultException, context);
                    var validationResultException = validationResult.UnwrapError().GetException();
                    theoryData.ExpectedExceptionValidationParameters!.ProcessException(validationResultException, context);
                }

                TestUtilities.AssertFailIfErrors(context);
            }
        }

        public static TheoryData<ValidateTokenAsyncIssuerSigningKeyTheoryData> ValidateTokenAsync_IssuerSigningKey_TestCases
        {
            get
            {
                int currentYear = DateTime.UtcNow.Year;
                // Mock time provider, 100 years in the future
                TimeProvider futureTimeProvider = new MockTimeProvider(new DateTimeOffset(currentYear + 100, 1, 1, 0, 0, 0, new(0)));
                // Mock time provider, 100 years in the past
                TimeProvider pastTimeProvider = new MockTimeProvider(new DateTimeOffset(currentYear - 100, 9, 16, 0, 0, 0, new(0)));

                var theoryData = new TheoryData<ValidateTokenAsyncIssuerSigningKeyTheoryData>();

                theoryData.Add(new ValidateTokenAsyncIssuerSigningKeyTheoryData("Valid_IssuerSigningKeyIsValid")
                {
                    SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
                    TokenValidationParameters = CreateTokenValidationParameters(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key),
                    ValidationParameters = CreateValidationParameters(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key),
                });

                theoryData.Add(new ValidateTokenAsyncIssuerSigningKeyTheoryData("Invalid_IssuerSigningKeyIsExpired")
                {
                    // Signing key is valid between September 2011 and December 2039
                    // Mock time provider is set to 100 years in the future, after the key expired
                    SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
                    TokenValidationParameters = CreateTokenValidationParameters(
                            KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key, futureTimeProvider),
                    ValidationParameters = CreateValidationParameters(
                            KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key, futureTimeProvider),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException("IDX10249:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidSigningKeyException("IDX10249:"),
                });

                theoryData.Add(new ValidateTokenAsyncIssuerSigningKeyTheoryData("Invalid_IssuerSigningKeyNotYetValid")
                {
                    // Signing key is valid between September 2011 and December 2039
                    // Mock time provider is set to 100 years in the past, before the key was valid.
                    SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
                    TokenValidationParameters = CreateTokenValidationParameters(
                            KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key, pastTimeProvider),
                    ValidationParameters = CreateValidationParameters(
                            KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key, pastTimeProvider),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException("IDX10248:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidSigningKeyException("IDX10248:"),
                });

                theoryData.Add(new ValidateTokenAsyncIssuerSigningKeyTheoryData("Invalid_TokenValidationParametersAndValidationParametersAreNull")
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                    ExpectedIsValid = false,
                });

                return theoryData;

                static ValidationParameters CreateValidationParameters(
                    SecurityKey issuerSigingKey, TimeProvider? timeProvider = null)
                {
                    ValidationParameters validationParameters = new ValidationParameters();
                    validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
                    validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
                    validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
                    validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
                    validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;
                    validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;
                    validationParameters.SignatureValidator = (
                        SecurityToken token,
                        ValidationParameters validationParameters,
                        BaseConfiguration? configuration,
                        CallContext callContext) =>
                    {
                        // Set the signing key for validation
                        token.SigningKey = issuerSigingKey;
                        return issuerSigingKey;
                    };

                    if (issuerSigingKey is not null)
                        validationParameters.IssuerSigningKeys.Add(issuerSigingKey);

                    if (timeProvider is not null)
                        validationParameters.TimeProvider = timeProvider;

                    return validationParameters;
                }

                static TokenValidationParameters CreateTokenValidationParameters(
                    SecurityKey? issuerSigningKey = null, TimeProvider? timeProvider = null)
                {
                    var tokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = false,
                        ValidateTokenReplay = false,
                        ValidateIssuerSigningKey = true,
                        RequireSignedTokens = true,
                        RequireAudience = false,
                        IssuerSigningKey = issuerSigningKey,
                    };

                    tokenValidationParameters.SignatureValidator = (token, tokenValidationParameters) =>
                    {
                        // Set the signing key for validation
                        Saml2SecurityTokenHandler saml2SecurityTokenHandler = new Saml2SecurityTokenHandler();
                        Saml2SecurityToken saml2SecurityToken = saml2SecurityTokenHandler.ReadSaml2Token(token);
                        saml2SecurityToken.SigningKey = issuerSigningKey;

                        return saml2SecurityToken;
                    };

                    if (timeProvider is not null)
                        tokenValidationParameters.TimeProvider = timeProvider;

                    return tokenValidationParameters;
                }
            }
        }

        public class ValidateTokenAsyncIssuerSigningKeyTheoryData : TheoryDataBase
        {
            public ValidateTokenAsyncIssuerSigningKeyTheoryData(string testId) : base(testId) { }

            internal ExpectedException? ExpectedExceptionValidationParameters { get; set; } = ExpectedException.NoExceptionExpected;

            internal bool ExpectedIsValid { get; set; } = true;

            internal ValidationParameters? ValidationParameters { get; set; }

            internal TokenValidationParameters? TokenValidationParameters { get; set; }

            internal SigningCredentials? SigningCredentials { get; set; }
        }
    }
}
#nullable restore
