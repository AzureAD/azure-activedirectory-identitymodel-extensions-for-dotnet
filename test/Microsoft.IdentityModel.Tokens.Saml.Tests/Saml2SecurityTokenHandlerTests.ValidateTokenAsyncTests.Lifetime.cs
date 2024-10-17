// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
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
        public async Task ValidateTokenAsync_LifetimeComparison(ValidateTokenAsyncLifetimeTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_LifetimeComparison", theoryData);

            var saml2Token = CreateToken(
                theoryData.IssuedAt,
                theoryData.NotBefore,
                theoryData.Expires);

            var tokenValidationParameters = CreateTokenValidationParameters(
                saml2Token,
                theoryData.NullTokenValidationParameters,
                theoryData.ClockSkew);

            Saml2SecurityTokenHandler saml2TokenHandler = new Saml2SecurityTokenHandler();

            // Validate token using TokenValidationParameters
            TokenValidationResult tokenValidationResult =
                await saml2TokenHandler.ValidateTokenAsync(saml2Token.Assertion.CanonicalString, tokenValidationParameters);

            // Validate token using ValidationParameters.
            ValidationResult<ValidatedToken> validationResult =
                await saml2TokenHandler.ValidateTokenAsync(
                    saml2Token,
                    theoryData.ValidationParameters!,
                    theoryData.CallContext,
                    CancellationToken.None);

            // Ensure validity of the results match the expected result.
            if (tokenValidationResult.IsValid != validationResult.IsSuccess)
            {
                context.AddDiff($"tokenValidationResult.IsValid != validationResult.IsSuccess");
                theoryData.ExpectedExceptionValidationParameters!.ProcessException(validationResult.UnwrapError().GetException(), context);
                theoryData.ExpectedException.ProcessException(tokenValidationResult.Exception, context);
            }
            else
            {
                if (tokenValidationResult.IsValid)
                {
                    // Verify validated tokens from both paths match.
                    ValidatedToken validatedToken = validationResult.UnwrapResult();
                    IdentityComparer.AreEqual(validatedToken.SecurityToken, tokenValidationResult.SecurityToken, context);
                }
                else
                {
                    // Verify the exception provided by both paths match.
                    var tokenValidationResultException = tokenValidationResult.Exception;
                    theoryData.ExpectedException.ProcessException(tokenValidationResult.Exception, context);
                    var validationResultException = validationResult.UnwrapError().GetException();
                    theoryData.ExpectedExceptionValidationParameters!.ProcessException(validationResult.UnwrapError().GetException(), context);
                }

                TestUtilities.AssertFailIfErrors(context);
            }
        }

        public static TheoryData<ValidateTokenAsyncLifetimeTheoryData> ValidateTokenAsync_LifetimeTestCases
        {
            get
            {
                var theoryData = new TheoryData<ValidateTokenAsyncLifetimeTheoryData>();

                DateTime now = DateTime.UtcNow;
                DateTime nowPlus1Hour = now.AddHours(1);
                DateTime nowMinus1Hour = now.AddHours(-1);
                DateTime nowPlus3Minutes = now.AddMinutes(3);
                DateTime nowMinus3Minutes = now.AddMinutes(-3);

                theoryData.Add(new ValidateTokenAsyncLifetimeTheoryData("Valid_LifetimeIsValid")
                {
                    IssuedAt = now,
                    NotBefore = nowMinus1Hour,
                    Expires = nowPlus1Hour,
                    ValidationParameters = CreateValidationParameters()
                });

                theoryData.Add(new ValidateTokenAsyncLifetimeTheoryData("Valid_ExpiredThreeMinutesAgoButSkewIsFiveMinutes")
                {
                    // Default clock skew is 5 minutes.
                    IssuedAt = nowMinus1Hour,
                    NotBefore = nowMinus1Hour,
                    Expires = nowMinus3Minutes,
                    ValidationParameters = CreateValidationParameters()
                });

                theoryData.Add(new ValidateTokenAsyncLifetimeTheoryData("Valid_ValidInThreeMinutesButSkewIsFiveMinutes")
                {
                    // Default clock skew is 5 minutes.
                    IssuedAt = nowMinus1Hour,
                    NotBefore = nowPlus3Minutes,
                    Expires = nowPlus1Hour,
                    ValidationParameters = CreateValidationParameters()
                });

                theoryData.Add(new ValidateTokenAsyncLifetimeTheoryData("Invalid_TokenHasNoExpiration")
                {
                    IssuedAt = now,
                    NotBefore = nowMinus1Hour,
                    Expires = null,
                    ValidationParameters = CreateValidationParameters(),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenNoExpirationException("IDX10225:")
                });

                theoryData.Add(new ValidateTokenAsyncLifetimeTheoryData("Invalid_NotBeforeIsAfterExpires")
                {
                    IssuedAt = nowMinus1Hour,
                    NotBefore = nowPlus1Hour,
                    Expires = now,
                    ValidationParameters = CreateValidationParameters(),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException("IDX10224:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidLifetimeException("IDX10224:")
                });

                theoryData.Add(new ValidateTokenAsyncLifetimeTheoryData("Invalid_ExpiredThreeMinutesAgoButSkewIsTwoMinutes")
                {
                    // We override the clock skew to 2 minutes.
                    IssuedAt = nowMinus1Hour,
                    NotBefore = nowMinus1Hour,
                    Expires = nowMinus3Minutes,
                    ClockSkew = TimeSpan.FromMinutes(2),
                    ValidationParameters = CreateValidationParameters(TimeSpan.FromMinutes(2)),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenExpiredException("IDX10223:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenExpiredException("IDX10223:")
                });

                theoryData.Add(new ValidateTokenAsyncLifetimeTheoryData("Invalid_ValidInThreeMinutesButSkewIsTwoMinutes")
                {
                    // We override the clock skew to 2 minutes.
                    IssuedAt = nowMinus1Hour,
                    NotBefore = nowPlus3Minutes,
                    Expires = nowPlus1Hour,
                    ClockSkew = TimeSpan.FromMinutes(2),
                    ValidationParameters = CreateValidationParameters(TimeSpan.FromMinutes(2)),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenNotYetValidException("IDX10222:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenNotYetValidException("IDX10222:")
                });

                theoryData.Add(new ValidateTokenAsyncLifetimeTheoryData("Invalid_TokenValidationParametersAndValidationParametersAreNull")
                {
                    IssuedAt = nowMinus1Hour,
                    NotBefore = nowPlus3Minutes,
                    Expires = nowPlus1Hour,
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                    ExpectedIsValid = false,
                    ValidationParameters = null,
                    NullTokenValidationParameters = true
                });

                return theoryData;

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

        public class ValidateTokenAsyncLifetimeTheoryData : TheoryDataBase
        {
            public ValidateTokenAsyncLifetimeTheoryData(string testId) : base(testId) { }

            internal ValidationParameters? ValidationParameters { get; set; }

            internal ExpectedException? ExpectedExceptionValidationParameters { get; set; } = ExpectedException.NoExceptionExpected;

            internal bool ExpectedIsValid { get; set; } = true;

            public TimeSpan? ClockSkew { get; internal set; } = null;

            public DateTime? IssuedAt { get; set; }

            public DateTime? NotBefore { get; set; }

            public DateTime? Expires { get; set; }

            public bool NullTokenValidationParameters { get; internal set; } = false;
        }

        private static Saml2SecurityToken CreateToken(DateTime? issuedAt, DateTime? notBefore, DateTime? expires)
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

            return (Saml2SecurityToken)saml2TokenHandler.CreateToken(securityTokenDescriptor);
        }

        private static TokenValidationParameters? CreateTokenValidationParameters(
            Saml2SecurityToken saml2SecurityToken,
            bool nullTokenValidationParameters,
            TimeSpan? clockSkew = null)
        {
            if (nullTokenValidationParameters)
            {
                return null;
            }

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
