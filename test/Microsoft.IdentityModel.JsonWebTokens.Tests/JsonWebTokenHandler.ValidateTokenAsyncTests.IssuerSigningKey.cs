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
        [Theory, MemberData(nameof(ValidateTokenAsync_IssuerSigningKeyTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_IssuerSigningKey(ValidateTokenAsyncIssuerSigningKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_IssuerSigningKey", theoryData);

            string jwtString = CreateTokenWithSigningCredentials(theoryData.SigningCredentials);

            await ValidateAndCompareResults(jwtString, theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenAsyncIssuerSigningKeyTheoryData> ValidateTokenAsync_IssuerSigningKeyTestCases
        {
            get
            {
                int currentYear = DateTime.UtcNow.Year;
                // Mock time provider, 100 years in the future
                TimeProvider futureTimeProvider = new MockTimeProvider(new DateTimeOffset(currentYear + 100, 1, 1, 0, 0, 0, new(0)));
                // Mock time provider, 100 years in the past
                TimeProvider pastTimeProvider = new MockTimeProvider(new DateTimeOffset(currentYear - 100, 9, 16, 0, 0, 0, new(0)));

                return new TheoryData<ValidateTokenAsyncIssuerSigningKeyTheoryData>
                {
                    new ValidateTokenAsyncIssuerSigningKeyTheoryData("Valid_IssuerSigningKeyIsValid")
                    {
                        SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
                        TokenValidationParameters = CreateTokenValidationParameters(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key),
                        ValidationParameters = CreateValidationParameters(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key),
                    },
                    new ValidateTokenAsyncIssuerSigningKeyTheoryData("Invalid_IssuerSigningKeyIsExpired")
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
                    },
                    new ValidateTokenAsyncIssuerSigningKeyTheoryData("Invalid_IssuerSigningKeyNotYetValid")
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
                    },
                };

                static TokenValidationParameters CreateTokenValidationParameters(
                    SecurityKey? signingKey = null, TimeProvider? timeProvider = null)
                {
                    // only validate the signature and issuer signing key
                    var tokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = false,
                        ValidateTokenReplay = false,
                        ValidateIssuerSigningKey = true,
                        RequireSignedTokens = true,
                        IssuerSigningKey = signingKey,
                    };

                    if (timeProvider is not null)
                        tokenValidationParameters.TimeProvider = timeProvider;

                    return tokenValidationParameters;
                }

                static ValidationParameters CreateValidationParameters(
                    SecurityKey? signingKey = null, TimeProvider? timeProvider = null)
                {
                    ValidationParameters validationParameters = new ValidationParameters();

                    if (signingKey is not null)
                        validationParameters.IssuerSigningKeys.Add(signingKey);

                    if (timeProvider is not null)
                        validationParameters.TimeProvider = timeProvider;

                    // Skip all validations except signature and issuer signing key
                    validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
                    validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
                    validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
                    validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
                    validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;
                    validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;

                    return validationParameters;
                }
            }
        }

        public class ValidateTokenAsyncIssuerSigningKeyTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            public ValidateTokenAsyncIssuerSigningKeyTheoryData(string testId) : base(testId) { }

            public SigningCredentials? SigningCredentials { get; set; }
        }

        // Tokens must be signed in order to validate the issuer signing key.
        // While the ValidationParameters path allows us to test the issuer signing key without a signature,
        // the TokenValidationParameters path requires a signature or it will skip the issuer signing key validation.
        private static string CreateTokenWithSigningCredentials(SigningCredentials? signingCredentials)
        {
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = Default.ClaimsIdentity,
                SigningCredentials = signingCredentials,
            };

            return jsonWebTokenHandler.CreateToken(securityTokenDescriptor);
        }
    }
}
#nullable restore
