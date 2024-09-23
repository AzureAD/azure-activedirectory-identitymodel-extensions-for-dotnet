// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public partial class JsonWebTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_LifetimeTestCases))]
        public async Task ValidateTokenAsync_Lifetime(ValidateTokenAsyncLifetimeTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_Lifetime", theoryData);

            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();
            jsonWebTokenHandler.SetDefaultTimesOnTokenCreation = false; // Allow for null values to be passed in to validate.

            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = Default.ClaimsIdentity,
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Audience = Default.Audience,
                Issuer = Default.Issuer,
                IssuedAt = theoryData.IssuedAt,
                NotBefore = theoryData.NotBefore,
                Expires = theoryData.Expires,
            };

            string jwtString = jsonWebTokenHandler.CreateToken(securityTokenDescriptor);

            TokenValidationResult tokenValidationParametersResult =
                    await jsonWebTokenHandler.ValidateTokenAsync(jwtString, theoryData.TokenValidationParameters);
            ValidationResult<ValidatedToken> validationParametersResult =
                await jsonWebTokenHandler.ValidateTokenAsync(
                    jwtString, theoryData.ValidationParameters!, theoryData.CallContext, CancellationToken.None);

            if (tokenValidationParametersResult.IsValid != theoryData.ExpectedIsValid)
                context.AddDiff($"tokenValidationParametersResult.IsValid != theoryData.ExpectedIsValid");

            if (validationParametersResult.IsSuccess != theoryData.ExpectedIsValid)
                context.AddDiff($"validationParametersResult.IsSuccess != theoryData.ExpectedIsValid");

            if (theoryData.ExpectedIsValid &&
                tokenValidationParametersResult.IsValid &&
                validationParametersResult.IsSuccess)
            {
                IdentityComparer.AreEqual(
                    tokenValidationParametersResult.ClaimsIdentity,
                    validationParametersResult.UnwrapResult().ClaimsIdentity,
                    context);
                IdentityComparer.AreEqual(
                    tokenValidationParametersResult.Claims,
                    validationParametersResult.UnwrapResult().Claims,
                    context);
            }
            else
            {
                theoryData.ExpectedException.ProcessException(tokenValidationParametersResult.Exception, context);

                if (!validationParametersResult.IsSuccess)
                {
                    // If there is a special case for the ValidationParameters path, use that.
                    if (theoryData.ExpectedExceptionValidationParameters != null)
                        theoryData.ExpectedExceptionValidationParameters
                            .ProcessException(validationParametersResult.UnwrapError().GetException(), context);
                    else
                        theoryData.ExpectedException
                            .ProcessException(validationParametersResult.UnwrapError().GetException(), context);
                }
            }

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
                    var tokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = true,
                        ValidateIssuer = true,
                        ValidateLifetime = true,
                        ValidateTokenReplay = true,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = Default.AsymmetricSigningKey,
                        ValidAudiences = [Default.Audience],
                        ValidIssuer = Default.Issuer,
                    };

                    if (clockSkew is not null)
                        tokenValidationParameters.ClockSkew = clockSkew.Value;

                    return tokenValidationParameters;
                }

                static ValidationParameters CreateValidationParameters(TimeSpan? clockSkew = null)
                {
                    ValidationParameters validationParameters = new ValidationParameters();
                    validationParameters.ValidIssuers.Add(Default.Issuer);
                    validationParameters.ValidAudiences.Add(Default.Audience);
                    validationParameters.IssuerSigningKeys.Add(Default.AsymmetricSigningKey);

                    if (clockSkew is not null)
                        validationParameters.ClockSkew = clockSkew.Value;

                    return validationParameters;
                }
            }
        }

        public class ValidateTokenAsyncLifetimeTheoryData : TheoryDataBase
        {
            public ValidateTokenAsyncLifetimeTheoryData(string testId) : base(testId) { }

            public DateTime? IssuedAt { get; set; }

            public DateTime? NotBefore { get; set; }

            public DateTime? Expires { get; set; }

            internal bool ExpectedIsValid { get; set; } = true;

            internal TokenValidationParameters? TokenValidationParameters { get; set; }

            internal ValidationParameters? ValidationParameters { get; set; }

            // only set if we expect a different message on this path
            internal ExpectedException? ExpectedExceptionValidationParameters { get; set; } = null;
        }
    }
}
#nullable restore
