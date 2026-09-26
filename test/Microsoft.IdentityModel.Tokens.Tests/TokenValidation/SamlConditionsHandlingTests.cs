// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Xunit;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.TokenValidation.Tests
{
    public class SamlConditionsHandlingTests
    {
        [Theory]
        [InlineData(false, false, false)]
        [InlineData(false, true, true)]
        [InlineData(true, false, false)]
        [InlineData(true, true, false)]
        public async Task SamlConditionsHandling(
            bool conditionsWithoutExpiration,
            bool replayCachePresent,
            bool expectNoExpirationError)
        {
            string token = conditionsWithoutExpiration
                ? AddConditionsWithoutExpiration(
                    ReferenceTokens.SamlToken_NoConditions_NoSignature,
                    "<Conditions NotBefore=\"2017-08-25T21:17:29.554Z\"></Conditions>")
                : ReferenceTokens.SamlToken_NoConditions_NoSignature;

            Assert.Equal(conditionsWithoutExpiration, token.Contains("<Conditions "));

            var handler = new SamlSecurityTokenHandler();
            TrackingTokenReplayCache? tokenReplayCache = replayCachePresent ? new TrackingTokenReplayCache() : null;
            TokenValidationParameters tokenValidationParameters = CreateTokenValidationParameters(tokenReplayCache);

            if (expectNoExpirationError)
            {
                Assert.Throws<SecurityTokenNoExpirationException>(
                    () => handler.ValidateToken(token, tokenValidationParameters, out _));
            }
            else
            {
                handler.ValidateToken(token, tokenValidationParameters, out _);
            }

            AssertCacheUsage(tokenReplayCache, conditionsWithoutExpiration && replayCachePresent);

            await ValidateResultModelAsync(
                new SamlSecurityTestingTokenHandler(),
                token,
                replayCachePresent,
                expectNoExpirationError,
                conditionsWithoutExpiration && replayCachePresent);
        }

        [Theory]
        [InlineData(false, false, false)]
        [InlineData(false, true, true)]
        [InlineData(true, false, false)]
        [InlineData(true, true, true)]
        public async Task Saml2ConditionsHandling(
            bool conditionsWithoutExpiration,
            bool replayCachePresent,
            bool expectNoExpirationError)
        {
            string token = conditionsWithoutExpiration
                ? AddConditionsWithoutExpiration(
                    ReferenceTokens.Saml2Token_NoConditions_NoSignature,
                    "<Conditions NotBefore=\"2017-03-20T15:47:31.957Z\"></Conditions>")
                : ReferenceTokens.Saml2Token_NoConditions_NoSignature;

            Assert.Equal(conditionsWithoutExpiration, token.Contains("<Conditions "));

            var handler = new Saml2SecurityTokenHandler();
            TrackingTokenReplayCache? tokenReplayCache = replayCachePresent ? new TrackingTokenReplayCache() : null;
            TokenValidationParameters tokenValidationParameters = CreateTokenValidationParameters(tokenReplayCache);

            if (expectNoExpirationError)
            {
                Assert.Throws<SecurityTokenNoExpirationException>(
                    () => handler.ValidateToken(token, tokenValidationParameters, out _));
            }
            else
            {
                handler.ValidateToken(token, tokenValidationParameters, out _);
            }

            AssertCacheUsage(tokenReplayCache, false);

            await ValidateResultModelAsync(
                new Saml2SecurityTestingTokenHandler(),
                token,
                replayCachePresent,
                expectNoExpirationError,
                false);
        }

        private static string AddConditionsWithoutExpiration(string token, string conditions)
        {
            return token.Replace("<AttributeStatement>", conditions + "<AttributeStatement>");
        }

        private static TokenValidationParameters CreateTokenValidationParameters(TrackingTokenReplayCache? tokenReplayCache)
        {
            return new TokenValidationParameters
            {
                RequireAudience = false,
                RequireSignedTokens = false,
                TokenReplayCache = tokenReplayCache,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
                ValidateTokenReplay = true,
            };
        }

        private static ValidationParameters CreateValidationParameters(TrackingTokenReplayCache? tokenReplayCache)
        {
            return new ValidationParameters
            {
                AlgorithmValidator = SkipValidationValidators.SkipAlgorithmValidation,
                AudienceValidator = SkipValidationValidators.SkipAudienceValidation,
                IssuerValidatorAsync = SkipValidationValidators.SkipIssuerValidation,
                LifetimeValidator = SkipValidationValidators.SkipLifetimeValidation,
                SignatureKeyValidator = SkipValidationValidators.SkipIssuerSigningKeyValidation,
                SignatureValidator = SkipValidationValidators.SkipSignatureValidation,
                TokenReplayCache = tokenReplayCache,
            };
        }

        private static void AssertCacheUsage(TrackingTokenReplayCache? tokenReplayCache, bool expectedToAdd)
        {
            if (tokenReplayCache is null)
                return;

            Assert.Equal(expectedToAdd ? 1 : 0, tokenReplayCache.FindCount);
            Assert.Equal(expectedToAdd ? 1 : 0, tokenReplayCache.AddCount);

            if (expectedToAdd)
                Assert.Equal(DateTime.MaxValue, tokenReplayCache.Expiration);
        }

        private static async Task ValidateResultModelAsync(
            ITestingTokenHandler handler,
            string token,
            bool replayCachePresent,
            bool expectNoExpirationError,
            bool expectCacheAdd)
        {
            TrackingTokenReplayCache? tokenReplayCache = replayCachePresent ? new TrackingTokenReplayCache() : null;
            ValidationResult<ValidatedToken, ValidationError> result = await handler.ValidateTokenAsync(
                token,
                CreateValidationParameters(tokenReplayCache),
                new CallContext(),
                CancellationToken.None);

            if (expectNoExpirationError)
            {
                Assert.False(result.Succeeded);
                TokenReplayValidationError error = Assert.IsType<TokenReplayValidationError>(result.Error);
                Assert.Equal(TokenReplayValidationFailure.NoExpiration.Name, error.FailureType.Name);
            }
            else
            {
                Assert.True(result.Succeeded, result.Error?.Message);
            }

            AssertCacheUsage(tokenReplayCache, expectCacheAdd);
        }

        private sealed class TrackingTokenReplayCache : ITokenReplayCache
        {
            public int AddCount { get; private set; }

            public DateTime Expiration { get; private set; }

            public int FindCount { get; private set; }

            public bool TryAdd(string securityToken, DateTime expiresOn)
            {
                AddCount++;
                Expiration = expiresOn;
                return true;
            }

            public bool TryFind(string securityToken)
            {
                FindCount++;
                return false;
            }
        }
    }
}
#nullable restore
