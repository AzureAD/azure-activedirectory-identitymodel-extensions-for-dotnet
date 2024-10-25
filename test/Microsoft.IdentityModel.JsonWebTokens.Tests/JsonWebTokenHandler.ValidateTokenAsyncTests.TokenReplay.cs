// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public partial class JsonWebTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_TokenReplayTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_TokenReplay(ValidateTokenAsyncTokenReplayTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_TokenReplay", theoryData);

            string jwtString = CreateTokenForTokenReplayValidation(theoryData.TokenHasExpiration);

            await ValidateAndCompareResults(jwtString, theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenAsyncTokenReplayTheoryData> ValidateTokenAsync_TokenReplayTestCases
        {
            get
            {
                var successfulTokenReplayCache = new TokenReplayCache
                {
                    OnAddReturnValue = true,
                    OnFindReturnValue = false,
                };

                var failToAddTokenReplayCache = new TokenReplayCache
                {
                    OnAddReturnValue = false,
                    OnFindReturnValue = false,
                };

                var tokenAlreadySavedTokenReplayCache = new TokenReplayCache
                {
                    OnAddReturnValue = true,
                    OnFindReturnValue = true,
                };

                var theoryData = new TheoryData<ValidateTokenAsyncTokenReplayTheoryData>();

                theoryData.Add(new ValidateTokenAsyncTokenReplayTheoryData("Valid_TokenHasNotBeenReplayed")
                {
                    TokenValidationParameters = CreateTokenValidationParameters(successfulTokenReplayCache),
                    ValidationParameters = CreateValidationParameters(successfulTokenReplayCache),
                });

                theoryData.Add(new ValidateTokenAsyncTokenReplayTheoryData("Valid_TokenHasNoExpiration_TokenReplayCacheIsNull")
                {
                    TokenHasExpiration = false,
                    TokenValidationParameters = CreateTokenValidationParameters(null),
                    ValidationParameters = CreateValidationParameters(null),
                });

                theoryData.Add(new ValidateTokenAsyncTokenReplayTheoryData("Invalid_TokenHasNoExpiration_TokenReplayCacheIsNotNull")
                {
                    TokenHasExpiration = false,
                    TokenValidationParameters = CreateTokenValidationParameters(successfulTokenReplayCache),
                    ValidationParameters = CreateValidationParameters(successfulTokenReplayCache),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenNoExpirationException("IDX10227:"),
                });

                theoryData.Add(new ValidateTokenAsyncTokenReplayTheoryData("Invalid_TokenCouldNotBeAdded")
                {
                    TokenValidationParameters = CreateTokenValidationParameters(failToAddTokenReplayCache),
                    ValidationParameters = CreateValidationParameters(failToAddTokenReplayCache),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenReplayAddFailedException("IDX10229:"),
                });

                theoryData.Add(new ValidateTokenAsyncTokenReplayTheoryData("Invalid_TokenHasBeenReplayed")
                {
                    TokenValidationParameters = CreateTokenValidationParameters(tokenAlreadySavedTokenReplayCache),
                    ValidationParameters = CreateValidationParameters(tokenAlreadySavedTokenReplayCache),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenReplayDetectedException("IDX10228:"),
                });

                return theoryData;

                static TokenValidationParameters CreateTokenValidationParameters(ITokenReplayCache? tokenReplayCache)
                {
                    // only validate that the token has not been replayed
                    var tokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = false,
                        ValidateTokenReplay = true,
                        ValidateIssuerSigningKey = false,
                        RequireSignedTokens = false,
                        TokenReplayCache = tokenReplayCache
                    };

                    return tokenValidationParameters;
                }

                static ValidationParameters CreateValidationParameters(ITokenReplayCache? tokenReplayCache)
                {
                    ValidationParameters validationParameters = new ValidationParameters();
                    validationParameters.TokenReplayCache = tokenReplayCache;

                    // Skip all validations except token replay
                    validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
                    validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
                    validationParameters.IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
                    validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
                    validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
                    validationParameters.SignatureValidator = SkipValidationDelegates.SkipSignatureValidation;
                    validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;

                    return validationParameters;
                }
            }
        }

        public class ValidateTokenAsyncTokenReplayTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            public ValidateTokenAsyncTokenReplayTheoryData(string testId) : base(testId) { }

            public bool TokenHasExpiration { get; set; } = true;
        }

        private static string CreateTokenForTokenReplayValidation(bool hasExpiration = true)
        {
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();
            // If the token has expiration, we use the default times.
            jsonWebTokenHandler.SetDefaultTimesOnTokenCreation = hasExpiration;

            SecurityTokenDescriptor securityTokenDescriptor;

            if (!hasExpiration)
            {
                securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = Default.ClaimsIdentity,
                    Expires = null,
                    NotBefore = null,
                    IssuedAt = null,
                };
            }
            else
            {
                securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = Default.ClaimsIdentity,
                };
            }

            return jsonWebTokenHandler.CreateToken(securityTokenDescriptor);
        }
    }
}
#nullable restore
