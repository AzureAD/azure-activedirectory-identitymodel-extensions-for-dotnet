// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Saml2;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
#nullable enable
    public partial class Saml2SecurityTokenHandlerTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_LifetimeTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_Lifetime(ValidateTokenAsyncLifetimeTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_Lifetime", theoryData);

            var saml2Token = CreateToken(theoryData.IssuedAt, theoryData.NotBefore, theoryData.Expires, theoryData.Saml2Condition!);

            var tokenValidationParameters = CreateTokenValidationParameters(saml2Token, theoryData.ClockSkew);

            await ValidateAndCompareResults(saml2Token, tokenValidationParameters, theoryData, context);

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
                        ValidationParameters = CreateValidationParameters()
                    },
                    new ValidateTokenAsyncLifetimeTheoryData("Invalid_TokenHasNoExpiration")
                    {
                        IssuedAt = now,
                        NotBefore = nowMinus1Hour,
                        Expires = null,
                        ValidationParameters = CreateValidationParameters(),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenNoExpirationException("IDX10225:"),
                    },
                    new ValidateTokenAsyncLifetimeTheoryData("Invalid_NotBeforeIsAfterExpires") //TODO: This test need to be revised after we clarify if we should still check the same condition when we create SAMLConditions
                    {
                        IssuedAt = nowMinus1Hour,
                        NotBefore = nowPlus1Hour,
                        Expires = now,
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
                        ValidationParameters = CreateValidationParameters()
                    },
                    new ValidateTokenAsyncLifetimeTheoryData("Invalid_ExpiredThreeMinutesAgoButSkewIsTwoMinutes")
                    {
                        // We override the clock skew to 2 minutes.
                        IssuedAt = nowMinus1Hour,
                        NotBefore = nowMinus1Hour,
                        Expires = nowMinus3Minutes,
                        ClockSkew = TimeSpan.FromMinutes(2),
                        ValidationParameters = CreateValidationParameters(TimeSpan.FromMinutes(2)),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenExpiredException("IDX10223:")
                    },
                    new ValidateTokenAsyncLifetimeTheoryData("Valid_ValidInThreeMinutesButSkewIsFiveMinutes")
                    {
                        // Default clock skew is 5 minutes.
                        IssuedAt = nowMinus1Hour,
                        NotBefore = nowPlus3Minutes,
                        Expires = nowPlus1Hour,
                        ValidationParameters = CreateValidationParameters()
                    },
                    new ValidateTokenAsyncLifetimeTheoryData("Invalid_ValidInThreeMinutesButSkewIsTwoMinutes")
                    {
                        // We override the clock skew to 2 minutes.
                        IssuedAt = nowMinus1Hour,
                        NotBefore = nowPlus3Minutes,
                        Expires = nowPlus1Hour,
                        ClockSkew = TimeSpan.FromMinutes(2),
                        ValidationParameters = CreateValidationParameters(TimeSpan.FromMinutes(2)),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenNotYetValidException("IDX10222:")
                    }
                };

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

            public Saml2Conditions? Saml2Condition { get; internal set; }

            public TimeSpan? ClockSkew { get; internal set; } = null;

            public DateTime? IssuedAt { get; set; }

            public DateTime? NotBefore { get; set; }

            public DateTime? Expires { get; set; }
        }

        private static Saml2SecurityToken CreateToken(DateTime? issuedAt, DateTime? notBefore, DateTime? expires, Saml2Conditions saml2Conditions)
        {
            Saml2SecurityTokenHandler saml2TokenHandler = new Saml2SecurityTokenHandler();

            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                IssuedAt = issuedAt,
                NotBefore = notBefore,
                Expires = expires,
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Audience = Default.Audience,
                Issuer = Default.Issuer,
                Subject = Default.SamlClaimsIdentity
            };

            Saml2SecurityToken saml2Token = (Saml2SecurityToken)saml2TokenHandler.CreateToken(securityTokenDescriptor);

            /*
                    if (saml2Conditions != null)
                        saml2Token.Assertion.Conditions = saml2Conditions;*/ //TODO: Will adapt this to work with scenarios such as TokenReplay in Jwt or OneTimeUse in SAML.

            return saml2Token;
        }

        private static TokenValidationParameters CreateTokenValidationParameters(
            Saml2SecurityToken saml2SecurityToken,
            TimeSpan? clockSkew = null)
        {
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = true,
                ValidateTokenReplay = false,
                ValidateIssuerSigningKey = false,
                RequireSignedTokens = false,
                SignatureValidator = delegate (string token, TokenValidationParameters validationParameters)
                {
                    return saml2SecurityToken;
                }
            };

            if (clockSkew is not null)
                tokenValidationParameters.ClockSkew = clockSkew.Value;

            return tokenValidationParameters;
        }
    }
}
#nullable restore
