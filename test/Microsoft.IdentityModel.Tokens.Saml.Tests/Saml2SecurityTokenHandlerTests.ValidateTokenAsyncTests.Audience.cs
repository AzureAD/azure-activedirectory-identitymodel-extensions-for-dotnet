// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
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
        public async Task ValidateTokenAsync_Audience(ValidateTokenAsyncAudienceTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_Audience", theoryData);

            Saml2SecurityTokenHandler saml2TokenHandler = new Saml2SecurityTokenHandler();

            var saml2Token = CreateToken(theoryData.TokenAudience!, theoryData.Saml2Condition!);

            var validationParameters = CreateTokenValidationParameters(
                theoryData.TVPAudiences,
                saml2Token,
                theoryData.ignoreTrailingSlashWhenValidatingAudience);

            await ValidateAndCompareResults(saml2Token, validationParameters, theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
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
                        ignoreTrailingSlashWhenValidatingAudience = true,
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
                        ignoreTrailingSlashWhenValidatingAudience = true,
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

        public class ValidateTokenAsyncAudienceTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            public ValidateTokenAsyncAudienceTheoryData(string testId) : base(testId) { }

            public string? TokenAudience { get; internal set; } = Default.Audience;

            public List<string>? TVPAudiences { get; internal set; }

            public Saml2Conditions? Saml2Condition { get; internal set; }

            public bool ignoreTrailingSlashWhenValidatingAudience { get; internal set; } = false;
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

            /*
                    if (saml2Conditions != null)
                        saml2Token.Assertion.Conditions = saml2Conditions;*/ //TODO: Will adapt this to work with scenarios such as TokenReplay in Jwt or OneTimeUse in SAML.

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
