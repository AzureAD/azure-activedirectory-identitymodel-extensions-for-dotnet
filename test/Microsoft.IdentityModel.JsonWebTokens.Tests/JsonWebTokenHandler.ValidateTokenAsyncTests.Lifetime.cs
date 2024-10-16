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
        [Theory, MemberData(nameof(ValidateTokenAsync_LifetimeTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_Lifetime(ValidateTokenAsyncLifetimeTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_Lifetime", theoryData);

            string jwtString = CreateTokenWithLifetime(theoryData.IssuedAt, theoryData.NotBefore, theoryData.Expires);

            await ValidateAndCompareResults(jwtString, theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenAsyncLifetimeTheoryData> ValidateTokenAsync_LifetimeTestCases
        {
            get
            {
                DateTime now = DateTime.UtcNow;
                DateTime nowPlus1Hour = now.AddHours(1);
                DateTime nowMinus1Hour = now.AddHours(-1);
                DateTime nowPlus3Minutes = now.AddMinutes(3);
                DateTime nowMinus3Minutes = now.AddMinutes(-3);

                return new TheoryData<ValidateTokenAsyncLifetimeTheoryData>
                {
                    new ValidateTokenAsyncLifetimeTheoryData("Valid_LifetimeIsValid")
                    {
                        IssuedAt = now,
                        NotBefore = nowMinus1Hour,
                        Expires = nowPlus1Hour,
                        TokenValidationParameters = CreateTokenValidationParameters(),
                        ValidationParameters = CreateValidationParameters(),
                    },
                    new ValidateTokenAsyncLifetimeTheoryData("Invalid_TokenHasNoExpiration")
                    {
                        IssuedAt = now,
                        NotBefore = nowMinus1Hour,
                        Expires = null,
                        TokenValidationParameters = CreateTokenValidationParameters(),
                        ValidationParameters = CreateValidationParameters(),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenNoExpirationException("IDX10225:"),
                    },
                    new ValidateTokenAsyncLifetimeTheoryData("Invalid_NotBeforeIsAfterExpires")
                    {
                        IssuedAt = nowMinus1Hour,
                        NotBefore = nowPlus1Hour,
                        Expires = now,
                        TokenValidationParameters = CreateTokenValidationParameters(),
                        ValidationParameters = CreateValidationParameters(),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException("IDX10224:"),
                    },
                    new ValidateTokenAsyncLifetimeTheoryData("Valid_ExpiredThreeMinutesAgoButSkewIsFiveMinutes")
                    {
                        // Default clock skew is 5 minutes.
                        IssuedAt = nowMinus1Hour,
                        NotBefore = nowMinus1Hour,
                        Expires = nowMinus3Minutes,
                        TokenValidationParameters = CreateTokenValidationParameters(),
                        ValidationParameters = CreateValidationParameters(),
                    },
                    new ValidateTokenAsyncLifetimeTheoryData("Invalid_ExpiredThreeMinutesAgoButSkewIsTwoMinutes")
                    {
                        // We override the clock skew to 2 minutes.
                        IssuedAt = nowMinus1Hour,
                        NotBefore = nowMinus1Hour,
                        Expires = nowMinus3Minutes,
                        TokenValidationParameters = CreateTokenValidationParameters(TimeSpan.FromMinutes(2)),
                        ValidationParameters = CreateValidationParameters(TimeSpan.FromMinutes(2)),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenExpiredException("IDX10223:"),
                    },
                    new ValidateTokenAsyncLifetimeTheoryData("Valid_ValidInThreeMinutesButSkewIsFiveMinutes")
                    {
                        // Default clock skew is 5 minutes.
                        IssuedAt = nowMinus1Hour,
                        NotBefore = nowPlus3Minutes,
                        Expires = nowPlus1Hour,
                        TokenValidationParameters = CreateTokenValidationParameters(),
                        ValidationParameters = CreateValidationParameters(),
                    },
                    new ValidateTokenAsyncLifetimeTheoryData("Invalid_ValidInThreeMinutesButSkewIsTwoMinutes")
                    {
                        // We override the clock skew to 2 minutes.
                        IssuedAt = nowMinus1Hour,
                        NotBefore = nowPlus3Minutes,
                        Expires = nowPlus1Hour,
                        TokenValidationParameters = CreateTokenValidationParameters(TimeSpan.FromMinutes(2)),
                        ValidationParameters = CreateValidationParameters(TimeSpan.FromMinutes(2)),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenNotYetValidException("IDX10222:"),
                    },
                };

                static TokenValidationParameters CreateTokenValidationParameters(TimeSpan? clockSkew = null)
                {
                    // only validate the lifetime
                    var tokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = true,
                        ValidateTokenReplay = false,
                        ValidateIssuerSigningKey = false,
                        RequireSignedTokens = false,
                    };

                    if (clockSkew is not null)
                        tokenValidationParameters.ClockSkew = clockSkew.Value;

                    return tokenValidationParameters;
                }

                static ValidationParameters CreateValidationParameters(TimeSpan? clockSkew = null)
                {
                    ValidationParameters validationParameters = new ValidationParameters();

                    if (clockSkew is not null)
                        validationParameters.ClockSkew = clockSkew.Value;

                    // Skip all validations except lifetime
                    validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
                    validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
                    validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
                    validationParameters.IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
                    validationParameters.SignatureValidator = SkipValidationDelegates.SkipSignatureValidation;

                    return validationParameters;
                }
            }
        }

        public class ValidateTokenAsyncLifetimeTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            public ValidateTokenAsyncLifetimeTheoryData(string testId) : base(testId) { }

            public DateTime? IssuedAt { get; set; }

            public DateTime? NotBefore { get; set; }

            public DateTime? Expires { get; set; }
        }

        private static string CreateTokenWithLifetime(DateTime? issuedAt, DateTime? notBefore, DateTime? expires)
        {
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();
            jsonWebTokenHandler.SetDefaultTimesOnTokenCreation = false; // Allow for null values to be passed in to validate.

            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = Default.ClaimsIdentity,
                IssuedAt = issuedAt,
                NotBefore = notBefore,
                Expires = expires,
            };

            return jsonWebTokenHandler.CreateToken(securityTokenDescriptor);
        }
    }
}
#nullable restore
