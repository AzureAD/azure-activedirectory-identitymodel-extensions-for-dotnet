// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable disable
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
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

        [Fact]
        public async Task ValidateToken_PeekMissConfiguration_FallsBackToAsyncAndMatchesAsync()
        {
            // Arrange - MockConfigurationManager does not override the synchronous peek, so TryGetCurrentConfiguration
            // misses and the sync fast path must fall back to the asynchronous pipeline, which resolves the configuration.
            string token = testTokenCreator.CreateDefaultValidToken();

            ValidationParameters syncParameters = ValidationUtils.CreateValidationParameters(audiences: ["http://Default.Audience.com"]);
            syncParameters.ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(CreateConfiguration());

            ValidationParameters asyncParameters = ValidationUtils.CreateValidationParameters(audiences: ["http://Default.Audience.com"]);
            asyncParameters.ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(CreateConfiguration());

            // Act
            ValidationResult<ValidatedToken, ValidationError> syncResult =
                jsonWebTokenHandler.ValidateToken(token, syncParameters, new CallContext());
            ValidationResult<ValidatedToken, ValidationError> asyncResult =
                await ResultBasedHandler.ValidateTokenAsync(token, asyncParameters, new CallContext(), default);

            // Assert
            Assert.True(syncResult.Succeeded);
            Assert.Equal(asyncResult.Succeeded, syncResult.Succeeded);
        }

        [Fact]
        public async Task ValidateToken_RecoverableFailureOnStaleConfig_FallsBackToAsyncAndSucceeds()
        {
            // Arrange - the synchronous peek returns a stale configuration whose signing key cannot validate the token,
            // producing a recoverable signature failure. The sync fast path must route to the async pipeline, which
            // supplies the good configuration and succeeds - the recovery is never duplicated on the sync path.
            string token = testTokenCreator.CreateDefaultValidToken();

            ValidationParameters syncParameters = ValidationUtils.CreateValidationParameters(audiences: ["http://Default.Audience.com"], signingKeys: []);
            syncParameters.ConfigurationManager = new StalePeekFreshAsyncConfigurationManager(CreateStaleConfiguration(), CreateConfiguration());

            ValidationParameters asyncParameters = ValidationUtils.CreateValidationParameters(audiences: ["http://Default.Audience.com"], signingKeys: []);
            asyncParameters.ConfigurationManager = new StalePeekFreshAsyncConfigurationManager(CreateStaleConfiguration(), CreateConfiguration());

            // Act
            ValidationResult<ValidatedToken, ValidationError> syncResult =
                jsonWebTokenHandler.ValidateToken(token, syncParameters, new CallContext());
            ValidationResult<ValidatedToken, ValidationError> asyncResult =
                await ResultBasedHandler.ValidateTokenAsync(token, asyncParameters, new CallContext(), default);

            // Assert
            Assert.True(syncResult.Succeeded);
            Assert.Equal(asyncResult.Succeeded, syncResult.Succeeded);
        }

        [Fact]
        public void ValidateToken_ReplayCacheConfigured_RoutesToAsyncAndConsumesReplayOnce()
        {
            // Arrange - a replay cache is configured together with a stale cached configuration that would force a
            // recoverable signature failure on the sync path. Without the replay guard the sync fast path would consume
            // the replay cache during its speculative attempt and then again on the async fallback, spuriously reporting
            // the token as replayed. The guard routes straight to the async path so the token is recorded exactly once.
            string token = testTokenCreator.CreateDefaultValidToken();

            ValidationParameters syncParameters = ValidationUtils.CreateValidationParameters(audiences: ["http://Default.Audience.com"], signingKeys: []);
            syncParameters.ConfigurationManager = new StalePeekFreshAsyncConfigurationManager(CreateStaleConfiguration(), CreateConfiguration());
            syncParameters.TokenReplayCache = new CountingTokenReplayCache();

            // Act
            ValidationResult<ValidatedToken, ValidationError> syncResult =
                jsonWebTokenHandler.ValidateToken(token, syncParameters, new CallContext());

            // Assert - the token validates (it was not double-counted as a replay).
            Assert.True(syncResult.Succeeded);
        }

        [Fact]
        public async Task ValidateToken_EncryptedToken_Succeeds_MatchesAsync()
        {
            // Arrange
            string token = CreateEncryptedToken();

            ValidationParameters syncParameters = CreateDefaultValidationParameters();
            syncParameters.DecryptionKeys.Add(KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key);
            ValidationParameters asyncParameters = CreateDefaultValidationParameters();
            asyncParameters.DecryptionKeys.Add(KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key);

            // Act
            ValidationResult<ValidatedToken, ValidationError> syncResult =
                jsonWebTokenHandler.ValidateToken(token, syncParameters, new CallContext());
            ValidationResult<ValidatedToken, ValidationError> asyncResult =
                await ResultBasedHandler.ValidateTokenAsync(token, asyncParameters, new CallContext(), default);

            // Assert
            Assert.True(syncResult.Succeeded);
            Assert.Equal(asyncResult.Succeeded, syncResult.Succeeded);
        }

        [Fact]
        public async Task ValidateToken_EncryptedToken_WrongDecryptionKey_FailsLikeAsync()
        {
            // Arrange
            string token = CreateEncryptedToken();

            ValidationParameters syncParameters = CreateDefaultValidationParameters();
            syncParameters.DecryptionKeys.Add(KeyingMaterial.DefaultSymmetricSecurityKey_128);
            ValidationParameters asyncParameters = CreateDefaultValidationParameters();
            asyncParameters.DecryptionKeys.Add(KeyingMaterial.DefaultSymmetricSecurityKey_128);

            // Act
            ValidationResult<ValidatedToken, ValidationError> syncResult =
                jsonWebTokenHandler.ValidateToken(token, syncParameters, new CallContext());
            ValidationResult<ValidatedToken, ValidationError> asyncResult =
                await ResultBasedHandler.ValidateTokenAsync(token, asyncParameters, new CallContext(), default);

            // Assert
            Assert.False(syncResult.Succeeded);
            Assert.Equal(asyncResult.Succeeded, syncResult.Succeeded);
            Assert.Equal(asyncResult.Error.GetType(), syncResult.Error.GetType());
        }

        [Fact]
        public async Task ValidateToken_CustomAsyncOnlyIssuerValidator_Succeeds_MatchesAsync()
        {
            // Arrange - a custom issuer validator that implements only the asynchronous IIssuerValidator (not
            // ISynchronousIssuerValidator). The sync path completes it synchronously; issuer validation itself does no I/O.
            string token = testTokenCreator.CreateDefaultValidToken();

            ValidationParameters syncParameters = CreateDefaultValidationParameters();
            syncParameters.IssuerValidatorAsync = new AsyncOnlyIssuerValidator(succeed: true);
            ValidationParameters asyncParameters = CreateDefaultValidationParameters();
            asyncParameters.IssuerValidatorAsync = new AsyncOnlyIssuerValidator(succeed: true);

            // Act
            ValidationResult<ValidatedToken, ValidationError> syncResult =
                jsonWebTokenHandler.ValidateToken(token, syncParameters, new CallContext());
            ValidationResult<ValidatedToken, ValidationError> asyncResult =
                await ResultBasedHandler.ValidateTokenAsync(token, asyncParameters, new CallContext(), default);

            // Assert
            Assert.True(syncResult.Succeeded);
            Assert.Equal(asyncResult.Succeeded, syncResult.Succeeded);
        }

        [Fact]
        public async Task ValidateToken_CustomAsyncOnlyIssuerValidator_Fails_MatchesAsync()
        {
            // Arrange
            string token = testTokenCreator.CreateDefaultValidToken();

            ValidationParameters syncParameters = CreateDefaultValidationParameters();
            syncParameters.IssuerValidatorAsync = new AsyncOnlyIssuerValidator(succeed: false);
            ValidationParameters asyncParameters = CreateDefaultValidationParameters();
            asyncParameters.IssuerValidatorAsync = new AsyncOnlyIssuerValidator(succeed: false);

            // Act
            ValidationResult<ValidatedToken, ValidationError> syncResult =
                jsonWebTokenHandler.ValidateToken(token, syncParameters, new CallContext());
            ValidationResult<ValidatedToken, ValidationError> asyncResult =
                await ResultBasedHandler.ValidateTokenAsync(token, asyncParameters, new CallContext(), default);

            // Assert
            Assert.False(syncResult.Succeeded);
            Assert.Equal(asyncResult.Succeeded, syncResult.Succeeded);
            Assert.Equal(asyncResult.Error.GetType(), syncResult.Error.GetType());
        }

        [Fact]
        public async Task ValidateToken_ActorValidation_Succeeds_MatchesAsync()
        {
            // Arrange - the outer token carries an "actort" claim (a nested JWT). With ValidateActor set, the actor
            // token is validated synchronously via the same sync pipeline.
            string actorToken = testTokenCreator.CreateDefaultValidToken();
            string token = CreateTokenWithActor(actorToken);

            ValidationParameters syncParameters = CreateDefaultValidationParameters();
            syncParameters.ValidateActor = true;
            syncParameters.ActorValidationParameters = CreateDefaultValidationParameters();

            ValidationParameters asyncParameters = CreateDefaultValidationParameters();
            asyncParameters.ValidateActor = true;
            asyncParameters.ActorValidationParameters = CreateDefaultValidationParameters();

            // Act
            ValidationResult<ValidatedToken, ValidationError> syncResult =
                jsonWebTokenHandler.ValidateToken(token, syncParameters, new CallContext());
            ValidationResult<ValidatedToken, ValidationError> asyncResult =
                await ResultBasedHandler.ValidateTokenAsync(token, asyncParameters, new CallContext(), default);

            // Assert
            Assert.True(syncResult.Succeeded);
            Assert.Equal(asyncResult.Succeeded, syncResult.Succeeded);
        }

        private string CreateEncryptedToken()
        {
            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
            {
                Issuer = "http://Default.Issuer.com",
                Audience = "http://Default.Audience.com",
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2,
                NotBefore = DateTime.UtcNow - TimeSpan.FromHours(1),
                Expires = DateTime.UtcNow + TimeSpan.FromHours(1),
            };

            return jsonWebTokenHandler.CreateToken(descriptor);
        }

        private string CreateTokenWithActor(string actorToken)
        {
            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
            {
                Issuer = "http://Default.Issuer.com",
                Audience = "http://Default.Audience.com",
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                NotBefore = DateTime.UtcNow - TimeSpan.FromHours(1),
                Expires = DateTime.UtcNow + TimeSpan.FromHours(1),
                Claims = new Dictionary<string, object> { { "actort", actorToken } },
            };

            return jsonWebTokenHandler.CreateToken(descriptor);
        }

        [Fact]
        public async Task ValidateTokenAsync_NoConfigurationManager_CompletesSynchronously()
        {
            // Arrange - keys are supplied directly, so no configuration is needed and nothing can suspend.
            string token = testTokenCreator.CreateDefaultValidToken();
            ValidationParameters validationParameters = CreateDefaultValidationParameters();

            // Act
            Task<ValidationResult<ValidatedToken, ValidationError>> validationTask =
                ResultBasedHandler.ValidateTokenAsync(token, validationParameters, new CallContext(), default);

            // Assert - the task is already complete before it is ever awaited, proving no async state machine suspended.
            Assert.Equal(TaskStatus.RanToCompletion, validationTask.Status);
            Assert.True((await validationTask).Succeeded);
        }

        [Fact]
        public async Task ValidateTokenAsync_CachedConfiguration_CompletesSynchronously()
        {
            // Arrange - the configuration peek hits, so ValidateTokenAsync must complete without suspending.
            string token = testTokenCreator.CreateDefaultValidToken();
            ValidationParameters validationParameters = ValidationUtils.CreateValidationParameters(audiences: ["http://Default.Audience.com"]);
            validationParameters.ConfigurationManager = new PeekableConfigurationManager(CreateConfiguration());

            // Act
            Task<ValidationResult<ValidatedToken, ValidationError>> validationTask =
                ResultBasedHandler.ValidateTokenAsync(token, validationParameters, new CallContext(), default);

            // Assert
            Assert.Equal(TaskStatus.RanToCompletion, validationTask.Status);
            Assert.True((await validationTask).Succeeded);
        }

        [Fact]
        public async Task ValidateTokenAsync_CacheMissThenCacheHits_RetrievesConfigurationOnce()
        {
            // Arrange - a real ConfigurationManager with an empty cache and a counting retriever, so the first
            // validation must retrieve configuration asynchronously and later validations must not retrieve again.
            string token = testTokenCreator.CreateDefaultValidToken();
            CountingConfigurationRetriever retriever = new CountingConfigurationRetriever(CreateConfiguration());
            ValidationParameters validationParameters = ValidationUtils.CreateValidationParameters(audiences: ["http://Default.Audience.com"]);
            validationParameters.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                "lifecycle-metadata",
                retriever);

            // Act - cold call: the cache is empty, so the peek misses and the asynchronous path retrieves once.
            Task<ValidationResult<ValidatedToken, ValidationError>> coldTask =
                ResultBasedHandler.ValidateTokenAsync(token, validationParameters, new CallContext(), default);
            ValidationResult<ValidatedToken, ValidationError> coldResult = await coldTask;

            int retrievalsAfterColdCall = retriever.RetrievalCount;

            // Act - warm calls: the cache is now primed, so each call must complete on the synchronous fast path.
            for (int i = 0; i < 5; i++)
            {
                Task<ValidationResult<ValidatedToken, ValidationError>> warmTask =
                    ResultBasedHandler.ValidateTokenAsync(token, validationParameters, new CallContext(), default);

                Assert.Equal(TaskStatus.RanToCompletion, warmTask.Status);
                Assert.True((await warmTask).Succeeded);
            }

            // Assert - exactly one retrieval for the cold call and none for any of the warm calls.
            Assert.True(coldResult.Succeeded);
            Assert.Equal(1, retrievalsAfterColdCall);
            Assert.Equal(1, retriever.RetrievalCount);
        }

        private static OpenIdConnectConfiguration CreateStaleConfiguration()
        {
            // A configuration whose signing key does not match the token, so signature validation fails recoverably.
            OpenIdConnectConfiguration configuration = new OpenIdConnectConfiguration { Issuer = "http://Default.Issuer.com" };
            configuration.SigningKeys.Add(KeyingMaterial.RsaSecurityKey_2048);
            return configuration;
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

        // A configuration manager whose synchronous peek hits with a stale configuration (wrong signing key) but whose
        // asynchronous fetch returns a good configuration. This exercises the sync fast path's recoverable-failure
        // fallback: the sync attempt fails signature validation against the stale config and routes to the async path.
        private sealed class StalePeekFreshAsyncConfigurationManager : BaseConfigurationManager
        {
            private readonly BaseConfiguration _staleConfiguration;
            private readonly BaseConfiguration _freshConfiguration;

            public StalePeekFreshAsyncConfigurationManager(BaseConfiguration staleConfiguration, BaseConfiguration freshConfiguration)
            {
                _staleConfiguration = staleConfiguration;
                _freshConfiguration = freshConfiguration;
            }

            public override bool TryGetCurrentConfiguration(out BaseConfiguration configuration)
            {
                configuration = _staleConfiguration;
                return true;
            }

            public override Task<BaseConfiguration> GetBaseConfigurationAsync(CancellationToken cancel)
            {
                return Task.FromResult(_freshConfiguration);
            }

            public override void RequestRefresh()
            {
            }
        }

        // A stateful token replay cache that records nonces, so a token added twice is detected as a replay. This lets
        // the tests catch double-consumption of the replay cache by the synchronous fast path.
        private sealed class CountingTokenReplayCache : ITokenReplayCache
        {
            private readonly HashSet<string> _cache = new HashSet<string>();

            public bool TryAdd(string nonce, DateTime expiresAt) => _cache.Add(nonce);

            public bool TryFind(string nonce) => _cache.Contains(nonce);
        }

        // Returns a fixed configuration without any I/O and counts how many times it was asked for one, so tests can
        // prove that a cache miss retrieves exactly once and subsequent cache hits never retrieve again.
        private sealed class CountingConfigurationRetriever : IConfigurationRetriever<OpenIdConnectConfiguration>
        {
            private readonly OpenIdConnectConfiguration _configuration;
            private int _retrievalCount;

            public CountingConfigurationRetriever(OpenIdConnectConfiguration configuration)
            {
                _configuration = configuration;
            }

            public int RetrievalCount => Volatile.Read(ref _retrievalCount);

            public Task<OpenIdConnectConfiguration> GetConfigurationAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
            {
                Interlocked.Increment(ref _retrievalCount);
                return Task.FromResult(_configuration);
            }
        }

        // A custom issuer validator that implements only the asynchronous IIssuerValidator (not
        // ISynchronousIssuerValidator), so the synchronous path must complete it via the async validator.
        private sealed class AsyncOnlyIssuerValidator : IIssuerValidator
        {
            private readonly bool _succeed;

            public AsyncOnlyIssuerValidator(bool succeed)
            {
                _succeed = succeed;
            }

            public Task<ValidationResult<ValidatedIssuer, ValidationError>> ValidateIssuerAsync(
                string issuer,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext,
                CancellationToken cancellationToken)
            {
                ValidationResult<ValidatedIssuer, ValidationError> result;
                if (_succeed)
                {
                    result = new ValidatedIssuer(issuer, IssuerValidationSource.IssuerMatchedValidationParameters);
                }
                else
                {
                    result = new IssuerValidationError(
                        new MessageDetail("custom async-only issuer validator rejected the issuer"),
                        IssuerValidationFailure.ValidationFailed,
                        ValidationError.GetCurrentStackFrame(),
                        issuer);
                }

                return Task.FromResult(result);
            }
        }
    }
}
