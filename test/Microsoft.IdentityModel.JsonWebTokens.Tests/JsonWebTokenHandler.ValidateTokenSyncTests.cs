// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable disable
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.TestExtensions;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    // Tests for the synchronous, result-based JsonWebTokenHandler.ValidateToken(...) fast path added for issue #3459.
    // These validate keys-direct (no ConfigurationManager) tokens, so the synchronous path runs end-to-end without
    // ever falling back to the asynchronous path.
    public class JsonWebTokenHandlerValidateTokenSyncTests
    {
        private readonly TestTokenCreator testTokenCreator = new TestTokenCreator()
        {
            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials
        };

        private readonly JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

        private IResultBasedValidation ResultBasedHandler => jsonWebTokenHandler;

        private static ValidationParameters CreateDefaultValidationParameters() =>
            ValidationUtils.CreateValidationParameters(
                audiences: ["http://Default.Audience.com"],
                issuers: ["http://Default.Issuer.com"],
                signingKeys: [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]);

        // The synchronous ValidateToken must classify a token identically to the asynchronous result-based
        // ValidateTokenAsync (same success/failure and same error type). Stack frames are intentionally not compared:
        // ValidationError.GetCurrentStackFrame captures the (different) synchronous call site by design.
        private void AssertSyncMatchesAsync(string token)
        {
            // Arrange
            ValidationParameters syncParameters = CreateDefaultValidationParameters();
            ValidationParameters asyncParameters = CreateDefaultValidationParameters();

            // Act
            ValidationResult<ValidatedToken, ValidationError> syncResult =
                jsonWebTokenHandler.ValidateToken(token, syncParameters, new CallContext());
            ValidationResult<ValidatedToken, ValidationError> asyncResult =
                ResultBasedHandler.ValidateTokenAsync(token, asyncParameters, new CallContext(), default).GetAwaiter().GetResult();

            // Assert
            Assert.Equal(asyncResult.Succeeded, syncResult.Succeeded);
            if (asyncResult.Succeeded)
            {
                Assert.NotNull(syncResult.Result);
                Assert.Null(syncResult.Error);
            }
            else
            {
                Assert.NotNull(syncResult.Error);
                Assert.Equal(asyncResult.Error.GetType(), syncResult.Error.GetType());
            }
        }

        [Fact]
        public void ValidateToken_DefaultValidToken_SucceedsLikeAsync()
        {
            AssertSyncMatchesAsync(testTokenCreator.CreateDefaultValidToken());
        }

        [Fact]
        public void ValidateToken_ExpiredToken_FailsLikeAsync()
        {
            AssertSyncMatchesAsync(testTokenCreator.CreateExpiredToken());
        }

        [Fact]
        public void ValidateToken_NotYetValidToken_FailsLikeAsync()
        {
            AssertSyncMatchesAsync(testTokenCreator.CreateNotYetValidToken());
        }

        [Fact]
        public void ValidateToken_BadAudience_FailsLikeAsync()
        {
            AssertSyncMatchesAsync(testTokenCreator.CreateTokenWithBadAudience());
        }

        [Fact]
        public void ValidateToken_BadIssuer_FailsLikeAsync()
        {
            AssertSyncMatchesAsync(testTokenCreator.CreateTokenWithBadIssuer());
        }

        [Fact]
        public void ValidateToken_InvalidSignature_FailsLikeAsync()
        {
            AssertSyncMatchesAsync(testTokenCreator.CreateTokenWithInvalidSignature());
        }

        [Fact]
        public void ValidateToken_DefaultValidToken_Succeeds()
        {
            // Arrange
            ValidationParameters validationParameters = CreateDefaultValidationParameters();

            // Act
            ValidationResult<ValidatedToken, ValidationError> result =
                jsonWebTokenHandler.ValidateToken(testTokenCreator.CreateDefaultValidToken(), validationParameters, new CallContext());

            // Assert
            Assert.True(result.Succeeded);
            Assert.NotNull(result.Result);
            Assert.Null(result.Error);
        }

        [Fact]
        public void ValidateToken_NullToken_ReturnsError()
        {
            // Arrange
            ValidationParameters validationParameters = CreateDefaultValidationParameters();

            // Act
            ValidationResult<ValidatedToken, ValidationError> result =
                jsonWebTokenHandler.ValidateToken((string)null, validationParameters, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.NotNull(result.Error);
        }

        [Fact]
        public void ValidateToken_NullValidationParameters_ReturnsError()
        {
            // Act
            ValidationResult<ValidatedToken, ValidationError> result =
                jsonWebTokenHandler.ValidateToken(testTokenCreator.CreateDefaultValidToken(), (ValidationParameters)null, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.NotNull(result.Error);
        }

        [Fact]
        public void ValidateToken_SecurityTokenOverload_SucceedsLikeStringOverload()
        {
            // Arrange
            string token = testTokenCreator.CreateDefaultValidToken();
            JsonWebToken jsonWebToken = new JsonWebToken(token);

            // Act
            ValidationResult<ValidatedToken, ValidationError> fromString =
                jsonWebTokenHandler.ValidateToken(token, CreateDefaultValidationParameters(), new CallContext());
            ValidationResult<ValidatedToken, ValidationError> fromSecurityToken =
                jsonWebTokenHandler.ValidateToken(jsonWebToken, CreateDefaultValidationParameters(), new CallContext());

            // Assert
            Assert.True(fromString.Succeeded);
            Assert.True(fromSecurityToken.Succeeded);
            Assert.Equal(fromString.Succeeded, fromSecurityToken.Succeeded);
        }

        [Fact]
        public async Task ValidateToken_CachedConfiguration_UsesSyncPeekAndMatchesAsync()
        {
            // Arrange - configuration is cached, so the synchronous peek hits and the sync pipeline runs end-to-end
            // (issuer matched from configuration, signature validated with the configuration's signing keys).
            string token = testTokenCreator.CreateDefaultValidToken();

            ValidationParameters syncParameters = ValidationUtils.CreateValidationParameters(audiences: ["http://Default.Audience.com"]);
            syncParameters.ConfigurationManager = new PeekableConfigurationManager(CreateConfiguration());

            ValidationParameters asyncParameters = ValidationUtils.CreateValidationParameters(audiences: ["http://Default.Audience.com"]);
            asyncParameters.ConfigurationManager = new PeekableConfigurationManager(CreateConfiguration());

            // Act
            ValidationResult<ValidatedToken, ValidationError> syncResult =
                jsonWebTokenHandler.ValidateToken(token, syncParameters, new CallContext());
            ValidationResult<ValidatedToken, ValidationError> asyncResult =
                await ResultBasedHandler.ValidateTokenAsync(token, asyncParameters, new CallContext(), default);

            // Assert
            Assert.True(syncResult.Succeeded);
            Assert.Equal(asyncResult.Succeeded, syncResult.Succeeded);
            Assert.NotNull(syncResult.Result);
            // On success with a ConfigurationManager present, the cached configuration is recorded as last-known-good.
            Assert.NotNull(syncParameters.ConfigurationManager.LastKnownGoodConfiguration);
        }

        private static OpenIdConnectConfiguration CreateConfiguration()
        {
            OpenIdConnectConfiguration configuration = new OpenIdConnectConfiguration { Issuer = "http://Default.Issuer.com" };
            configuration.SigningKeys.Add(KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key);
            return configuration;
        }

        // Minimal BaseConfigurationManager whose synchronous peek always hits with a fixed configuration, so the
        // synchronous ValidateToken fast path is exercised without any network retrieval.
        private sealed class PeekableConfigurationManager : BaseConfigurationManager
        {
            private readonly BaseConfiguration _configuration;

            public PeekableConfigurationManager(BaseConfiguration configuration)
            {
                _configuration = configuration;
            }

            public override bool TryGetCurrentConfiguration(out BaseConfiguration configuration)
            {
                configuration = _configuration;
                return true;
            }

            public override Task<BaseConfiguration> GetBaseConfigurationAsync(CancellationToken cancel)
            {
                return Task.FromResult(_configuration);
            }

            public override void RequestRefresh()
            {
            }
        }
    }
}
