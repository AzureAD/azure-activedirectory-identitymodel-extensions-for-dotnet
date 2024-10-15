// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public partial class JsonWebTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_AudienceTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_Audience(ValidateTokenAsyncAudienceTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_Audience", theoryData);

            string jwtString = CreateTokenWithAudience(theoryData.Audience);

            await ValidateAndCompareResults(jwtString, theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenAsyncAudienceTheoryData> ValidateTokenAsync_AudienceTestCases
        {
            get
            {
                return new TheoryData<ValidateTokenAsyncAudienceTheoryData>
                {
                    new ValidateTokenAsyncAudienceTheoryData("Valid_AudiencesMatch")
                    {
                        Audience = Default.Audience,
                        TokenValidationParameters = CreateTokenValidationParameters([Default.Audience]),
                        ValidationParameters = CreateValidationParameters([Default.Audience]),
                    },
                    new ValidateTokenAsyncAudienceTheoryData("Invalid_AudiencesDontMatch")
                    {
                        // This scenario is the same if the token audience is an empty string or whitespace.
                        // As long as the token audience and the valid audience are not equal, the validation fails.
                        TokenValidationParameters = CreateTokenValidationParameters([Default.Audience]),
                        ValidationParameters = CreateValidationParameters([Default.Audience]),
                        Audience = "InvalidAudience",
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:"),
                        // ValidateTokenAsync with ValidationParameters returns a different error message to account for the
                        // removal of the ValidAudience property from the ValidationParameters class.
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                    },
                    new ValidateTokenAsyncAudienceTheoryData("Valid_AudienceWithinValidAudiences")
                    {
                        Audience = Default.Audience,
                        TokenValidationParameters = CreateTokenValidationParameters(["ExtraAudience", Default.Audience, "AnotherAudience"]),
                        ValidationParameters = CreateValidationParameters(["ExtraAudience", Default.Audience, "AnotherAudience"]),
                    },
                    new ValidateTokenAsyncAudienceTheoryData("Valid_AudienceWithSlash_IgnoreTrailingSlashTrue")
                    {
                        // Audience has a trailing slash, but IgnoreTrailingSlashWhenValidatingAudience is true.
                        Audience = Default.Audience + "/",
                        TokenValidationParameters = CreateTokenValidationParameters([Default.Audience], true),
                        ValidationParameters = CreateValidationParameters([Default.Audience], true),
                    },
                    new ValidateTokenAsyncAudienceTheoryData("Invalid_AudienceWithSlash_IgnoreTrailingSlashFalse")
                    {
                        // Audience has a trailing slash and IgnoreTrailingSlashWhenValidatingAudience is false.
                        Audience = Default.Audience + "/",
                        TokenValidationParameters = CreateTokenValidationParameters([Default.Audience], false),
                        ValidationParameters = CreateValidationParameters([Default.Audience], false),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:"),
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                    },
                    new ValidateTokenAsyncAudienceTheoryData("Valid_ValidAudiencesWithSlash_IgnoreTrailingSlashTrue")
                    {
                        // ValidAudiences has a trailing slash, but IgnoreTrailingSlashWhenValidatingAudience is true.
                        Audience = Default.Audience,
                        TokenValidationParameters = CreateTokenValidationParameters([Default.Audience + "/"], true),
                        ValidationParameters = CreateValidationParameters([Default.Audience + "/"], true),
                    },
                    new ValidateTokenAsyncAudienceTheoryData("Invalid_ValidAudiencesWithSlash_IgnoreTrailingSlashFalse")
                    {
                        // ValidAudiences has a trailing slash and IgnoreTrailingSlashWhenValidatingAudience is false.
                        Audience = Default.Audience,
                        TokenValidationParameters = CreateTokenValidationParameters([Default.Audience + "/"], false),
                        ValidationParameters = CreateValidationParameters([Default.Audience + "/"], false),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:"),
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                    },
                    new ValidateTokenAsyncAudienceTheoryData("Invalid_AudienceNullIsTreatedAsEmptyList")
                    {
                        // JsonWebToken.Audiences defaults to an empty list if no audiences are provided.
                        TokenValidationParameters = CreateTokenValidationParameters([Default.Audience]),
                        ValidationParameters = CreateValidationParameters([Default.Audience]),
                        Audience = null,
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10206:"),
                    },
                    new ValidateTokenAsyncAudienceTheoryData("Invalid_ValidAudiencesIsNull")
                    {
                        TokenValidationParameters = CreateTokenValidationParameters(null),
                        ValidationParameters = CreateValidationParameters(null),
                        Audience = string.Empty,
                        ExpectedIsValid = false,
                        // TVP path has a special case when ValidAudience is null or empty and ValidAudiences is null.
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10208:"),
                        // VP path has a default empty List for ValidAudiences, so it will always return IDX10206 if no audiences are provided.
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidAudienceException("IDX10206:"),
                    },
                };

                static TokenValidationParameters CreateTokenValidationParameters(
                    List<string>? audiences,
                    bool ignoreTrailingSlashWhenValidatingAudience = false) =>

                    // Only validate the audience.
                    new TokenValidationParameters
                    {
                        ValidateAudience = true,
                        ValidateIssuer = false,
                        ValidateLifetime = false,
                        ValidateTokenReplay = false,
                        ValidateIssuerSigningKey = false,
                        RequireSignedTokens = false,
                        ValidAudiences = audiences,
                        IgnoreTrailingSlashWhenValidatingAudience = ignoreTrailingSlashWhenValidatingAudience,
                    };

                static ValidationParameters CreateValidationParameters(
                    List<string>? audiences,
                    bool ignoreTrailingSlashWhenValidatingAudience = false)
                {
                    ValidationParameters validationParameters = new ValidationParameters();
                    audiences?.ForEach(audience => validationParameters.ValidAudiences.Add(audience));
                    validationParameters.IgnoreTrailingSlashWhenValidatingAudience = ignoreTrailingSlashWhenValidatingAudience;

                    // Skip all validations except audience
                    validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
                    validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
                    validationParameters.IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
                    validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
                    validationParameters.SignatureValidator = SkipValidationDelegates.SkipSignatureValidation;

                    return validationParameters;
                }
            }
        }

        public class ValidateTokenAsyncAudienceTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            public ValidateTokenAsyncAudienceTheoryData(string testId) : base(testId) { }

            public string? Audience { get; internal set; } = Default.Audience;
        }

        private static string CreateTokenWithAudience(string? audience)
        {
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = Default.ClaimsIdentity,
                Audience = audience,
            };

            return jsonWebTokenHandler.CreateToken(securityTokenDescriptor);
        }
    }
}
#nullable restore
