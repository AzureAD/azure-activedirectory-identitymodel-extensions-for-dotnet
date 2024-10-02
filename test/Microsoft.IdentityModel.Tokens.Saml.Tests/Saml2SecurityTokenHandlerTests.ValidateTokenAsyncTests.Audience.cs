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

            var saml2Token = CreateToken(theoryData.Audience!, theoryData.Saml2Condition!);

            var validationParameters = CreateTokenValidationParameters(
                new List<string> { theoryData.Audience! },
                saml2Token,
                false); //TODO: continue looking into improving this approach

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
                        Audience = Default.Audience,
                        Saml2Condition = new Saml2Conditions
                        {
                            OneTimeUse = false,
                            NotOnOrAfter = DateTime.UtcNow.AddMinutes(5),
                        },
                        ValidationParameters = CreateValidationParameters([Default.Audience])
                    }
                };

                static ValidationParameters CreateValidationParameters(
                    List<string> audiences,
                    bool ignoreTrailingSlashWhenValidatingAudience = false)
                {
                    ValidationParameters validationParameters = new ValidationParameters();
                    audiences.ForEach(audience => validationParameters.ValidAudiences.Add(audience));
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

            public string? Audience { get; internal set; } = Default.Audience;

            public Saml2Conditions? Saml2Condition { get; internal set; }

            public Saml2SecurityToken? Saml2SecurityToken { get; internal set; }

            public bool ignoreTrailingSlashWhenValidatingAudience { get; internal set; }
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
                        saml2Token.Assertion.Conditions = saml2Conditions;*/ //TODO: Figure out how to adapt thisto more complex scenarios

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
