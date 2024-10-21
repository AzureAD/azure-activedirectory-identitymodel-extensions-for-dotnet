// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
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

        [Theory, MemberData(nameof(ValidateTokenAsync_Audience_TestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_AudienceComparison(ValidateTokenAsyncAudienceTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_AudienceComparison", theoryData);

            Saml2SecurityTokenHandler saml2TokenHandler = new Saml2SecurityTokenHandler();

            var saml2Token = CreateTokenForAudienceValidation(theoryData.TokenAudience!, theoryData.Saml2Condition!);

            var tokenValidationParameters = CreateTokenValidationParameters(
                theoryData.TVPAudiences,
                saml2Token,
                theoryData.NullTokenValidationParameters,
                theoryData.IgnoreTrailingSlashWhenValidatingAudience);

            // Validate the token using TokenValidationParameters
            TokenValidationResult tokenValidationResult =
                await saml2TokenHandler.ValidateTokenAsync(saml2Token.Assertion.CanonicalString, tokenValidationParameters);

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
                    theoryData.ExpectedException.ProcessException(tokenValidationResult.Exception, context);
                    var validationResultException = validationResult.UnwrapError().GetException();
                    theoryData.ExpectedExceptionValidationParameters!.ProcessException(validationResult.UnwrapError().GetException(), context);
                }

                TestUtilities.AssertFailIfErrors(context);
            }
        }

        public static TheoryData<ValidateTokenAsyncAudienceTheoryData> ValidateTokenAsync_Audience_TestCases
        {
            get
            {

                var theoryData = new TheoryData<ValidateTokenAsyncAudienceTheoryData>();

                theoryData.Add(new ValidateTokenAsyncAudienceTheoryData("Valid_AudiencesMatch")
                {
                    TokenAudience = Default.Audience,
                    TVPAudiences = [Default.Audience],
                    ValidationParameters = CreateValidationParameters([Default.Audience])
                });

                theoryData.Add(new ValidateTokenAsyncAudienceTheoryData("Valid_AudienceWithinValidAudiences")
                {
                    TokenAudience = Default.Audience,
                    TVPAudiences = ["ExtraAudience", Default.Audience, "AnotherAudience"],
                    ValidationParameters = CreateValidationParameters(["ExtraAudience", Default.Audience, "AnotherAudience"]),
                });

                theoryData.Add(new ValidateTokenAsyncAudienceTheoryData("Valid_AudienceWithSlash_IgnoreTrailingSlashTrue")
                {
                    // Audience has a trailing slash, but IgnoreTrailingSlashWhenValidatingAudience is true.
                    TokenAudience = Default.Audience + "/",
                    TVPAudiences = [Default.Audience],
                    IgnoreTrailingSlashWhenValidatingAudience = true,
                    ValidationParameters = CreateValidationParameters([Default.Audience], true),
                });

                theoryData.Add(new ValidateTokenAsyncAudienceTheoryData("Valid_ValidAudiencesWithSlash_IgnoreTrailingSlashTrue")
                {
                    // ValidAudiences has a trailing slash, but IgnoreTrailingSlashWhenValidatingAudience is true.
                    TokenAudience = Default.Audience,
                    IgnoreTrailingSlashWhenValidatingAudience = true,
                    TVPAudiences = [Default.Audience + "/"],
                    ValidationParameters = CreateValidationParameters([Default.Audience + "/"], true),
                });

                theoryData.Add(new ValidateTokenAsyncAudienceTheoryData("Invalid_AudiencesDoNotMatch")
                {
                    ValidationParameters = CreateValidationParameters([Default.Audience]),
                    TokenAudience = "InvalidAudience",
                    TVPAudiences = [Default.Audience],
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                });

                theoryData.Add(new ValidateTokenAsyncAudienceTheoryData("Invalid_TokenAudienceIsWhiteSpace")
                {
                    ValidationParameters = CreateValidationParameters([Default.Audience]),
                    TokenAudience = " ",
                    TVPAudiences = [Default.Audience],
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                });

                theoryData.Add(new ValidateTokenAsyncAudienceTheoryData("Invalid_AudienceWithSlash_IgnoreTrailingSlashFalse")
                {
                    // Audience has a trailing slash and IgnoreTrailingSlashWhenValidatingAudience is false.
                    TokenAudience = Default.Audience + "/",
                    TVPAudiences = [Default.Audience],
                    ValidationParameters = CreateValidationParameters([Default.Audience], false),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                });

                theoryData.Add(new ValidateTokenAsyncAudienceTheoryData("Invalid_ValidAudiencesWithSlash_IgnoreTrailingSlashFalse")
                {
                    // ValidAudiences has a trailing slash and IgnoreTrailingSlashWhenValidatingAudience is false.
                    TokenAudience = Default.Audience,
                    TVPAudiences = [Default.Audience + "/"],
                    ValidationParameters = CreateValidationParameters([Default.Audience + "/"], false),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                });

                theoryData.Add(new ValidateTokenAsyncAudienceTheoryData("Invalid_TokenValidationParametersAndValidationParametersAreNull")
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                    ExpectedIsValid = false,
                    TokenAudience = Default.Audience,
                    TVPAudiences = [Default.Audience],
                    ValidationParameters = null,
                    NullTokenValidationParameters = true
                });

                return theoryData;

                static ValidationParameters CreateValidationParameters(
                    List<string>? audiences,
                    bool ignoreTrailingSlashWhenValidatingAudience = false)
                {
                    ValidationParameters validationParameters = new ValidationParameters();
                    audiences?.ForEach(audience => validationParameters.ValidAudiences.Add(audience));
                    validationParameters.IgnoreTrailingSlashWhenValidatingAudience = ignoreTrailingSlashWhenValidatingAudience;
                    validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
                    validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;

                    return validationParameters;
                }
            }
        }

        public class ValidateTokenAsyncAudienceTheoryData : TheoryDataBase
        {
            public ValidateTokenAsyncAudienceTheoryData(string testId) : base(testId) { }

            internal ExpectedException? ExpectedExceptionValidationParameters { get; set; } = ExpectedException.NoExceptionExpected;

            internal bool ExpectedIsValid { get; set; } = true;

            public bool IgnoreTrailingSlashWhenValidatingAudience { get; internal set; } = false;

            public bool NullTokenValidationParameters { get; internal set; } = false;

            internal ValidationParameters? ValidationParameters { get; set; }

            public Saml2Conditions? Saml2Condition { get; internal set; }

            public string? TokenAudience { get; internal set; }

            public List<string>? TVPAudiences { get; internal set; }
        }

        private static Saml2SecurityToken CreateTokenForAudienceValidation(string audience, Saml2Conditions saml2Conditions)
        {
            Saml2SecurityTokenHandler saml2TokenHandler = new Saml2SecurityTokenHandler();

            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                Audience = audience,
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Issuer = Default.Issuer,
                Subject = Default.SamlClaimsIdentity
            };

            Saml2SecurityToken saml2Token = (Saml2SecurityToken)saml2TokenHandler.CreateToken(securityTokenDescriptor);

            return saml2Token;
        }

        private static TokenValidationParameters? CreateTokenValidationParameters(
            List<string>? audiences,
            Saml2SecurityToken saml2SecurityToken,
            bool nullTokenValidationParameters,
            bool ignoreTrailingSlashWhenValidatingAudience = false)
        {
            if (nullTokenValidationParameters)
            {
                return null;
            }

            return new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = false,
                ValidateLifetime = false,
                ValidateTokenReplay = false,
                ValidateIssuerSigningKey = false,
                RequireSignedTokens = false,
                ValidAudiences = audiences,
                IgnoreTrailingSlashWhenValidatingAudience = ignoreTrailingSlashWhenValidatingAudience,
                SignatureValidator = delegate (string token, TokenValidationParameters validationParameters)
                {
                    return saml2SecurityToken;
                },
                RequireAudience = true
            };
        }
    }
}
#nullable restore
