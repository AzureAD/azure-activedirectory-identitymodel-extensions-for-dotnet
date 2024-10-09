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

            var saml2Token = CreateToken(theoryData.TokenAudience!, theoryData.Saml2Condition!);

            var tokenValidationParameters = CreateTokenValidationParameters(
                theoryData.TVPAudiences,
                saml2Token,
                theoryData.IgnoreTrailingSlashWhenValidatingAudience);

            // Validate the token using TokenValidationParameters
            TokenValidationResult tokenValidationResult =
                await saml2TokenHandler.ValidateTokenAsync(saml2Token.Assertion.CanonicalString, tokenValidationParameters);

            // Validate the token using ValidationParameters.
            ValidationResult<ValidatedToken> validationResult =
                await saml2TokenHandler.ValidateTokenAsync(
                    saml2Token, theoryData.ValidationParameters!, theoryData.CallContext, CancellationToken.None);

            // Ensure the validity of the results match the expected result.
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
                    //Verify the validated tokens by both paths match match.
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
                return new TheoryData<ValidateTokenAsyncAudienceTheoryData>
                {
                    new ValidateTokenAsyncAudienceTheoryData("Valid_AudiencesMatch")
                    {
                        TokenAudience = Default.Audience,
                        TVPAudiences = [Default.Audience],
                        ValidationParameters = CreateValidationParameters([Default.Audience])
                    },
                    new ValidateTokenAsyncAudienceTheoryData("Invalid_AudiencesDoNotMatch")
                    {
                        // This scenario is the same if the token audience is an empty string or whitespace.
                        // As long as the token audience and the valid audience are not equal, the validation fails.
                        ValidationParameters = CreateValidationParameters([Default.Audience]),
                        TokenAudience = "InvalidAudience",
                        TVPAudiences = [Default.Audience],
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:"),
                        // ValidateTokenAsync with ValidationParameters returns a different error message to account for the
                        // removal of the ValidAudience property from the ValidationParameters class.
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                    },
                    new ValidateTokenAsyncAudienceTheoryData("Valid_AudienceWithinValidAudiences")
                    {
                        TokenAudience = Default.Audience,
                        TVPAudiences = ["ExtraAudience", Default.Audience, "AnotherAudience"],
                        ValidationParameters = CreateValidationParameters(["ExtraAudience", Default.Audience, "AnotherAudience"]),
                    },
                    new ValidateTokenAsyncAudienceTheoryData("Valid_AudienceWithSlash_IgnoreTrailingSlashTrue")
                    {
                        // Audience has a trailing slash, but IgnoreTrailingSlashWhenValidatingAudience is true.
                        TokenAudience = Default.Audience + "/",
                        TVPAudiences = [Default.Audience],
                        IgnoreTrailingSlashWhenValidatingAudience = true,
                        ValidationParameters = CreateValidationParameters([Default.Audience], true),
                    },
                    new ValidateTokenAsyncAudienceTheoryData("Invalid_AudienceWithSlash_IgnoreTrailingSlashFalse")
                    {
                        // Audience has a trailing slash and IgnoreTrailingSlashWhenValidatingAudience is false.
                        TokenAudience = Default.Audience + "/",
                        TVPAudiences = [Default.Audience],
                        ValidationParameters = CreateValidationParameters([Default.Audience], false),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:"),
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                    },
                    new ValidateTokenAsyncAudienceTheoryData("Valid_ValidAudiencesWithSlash_IgnoreTrailingSlashTrue")
                    {
                        // ValidAudiences has a trailing slash, but IgnoreTrailingSlashWhenValidatingAudience is true.
                        TokenAudience = Default.Audience,
                        IgnoreTrailingSlashWhenValidatingAudience = true,
                        TVPAudiences = [Default.Audience + "/"],
                        ValidationParameters = CreateValidationParameters([Default.Audience + "/"], true),
                    },
                    new ValidateTokenAsyncAudienceTheoryData("Invalid_ValidAudiencesWithSlash_IgnoreTrailingSlashFalse")
                    {
                        // ValidAudiences has a trailing slash and IgnoreTrailingSlashWhenValidatingAudience is false.
                        TokenAudience = Default.Audience,
                        TVPAudiences = [Default.Audience + "/"],
                        ValidationParameters = CreateValidationParameters([Default.Audience + "/"], false),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:"),
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                    }
                };

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

            internal ValidationParameters? ValidationParameters { get; set; }

            public Saml2Conditions? Saml2Condition { get; internal set; }

            public string? TokenAudience { get; internal set; } = Default.Audience;

            public List<string>? TVPAudiences { get; internal set; }
        }

        private static Saml2SecurityToken CreateToken(string audience, Saml2Conditions saml2Conditions)
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

        private static TokenValidationParameters CreateTokenValidationParameters(
            List<string>? audiences,
            Saml2SecurityToken saml2SecurityToken,
            bool ignoreTrailingSlashWhenValidatingAudience = false)
        {
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
                }
            };
        }
    }
}
#nullable restore
