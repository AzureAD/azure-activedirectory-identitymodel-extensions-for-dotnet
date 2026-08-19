// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    // Handler-level coverage for the #3455 logging contract: the drain scope on
    // JsonWebTokenHandler.ValidateTokenAsync emits captured validator logs on completion, independent of
    // whether the caller accesses ClaimsIdentity, and does not accumulate across a reused CallContext.
    [Collection("LogHelper.Logger Tests")]
    public class JsonWebTokenHandlerLoggingContractTests
    {
        private const string Audience = "http://Default.Audience.com";
        private const string Issuer = "http://Default.Issuer.com";

        private static string CreateValidToken()
        {
            var handler = new JsonWebTokenHandler();
            return handler.CreateToken(new SecurityTokenDescriptor
            {
                Audience = Audience,
                Issuer = Issuer,
                Expires = DateTime.UtcNow.AddHours(1),
                NotBefore = DateTime.UtcNow.AddMinutes(-5),
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
            });
        }

        private static ValidationParameters CreateValidationParameters() =>
            ValidationUtils.CreateValidationParameters(
                audiences: [Audience],
                issuers: [Issuer],
                signingKeys: [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]);

        [Fact]
        public async Task ValidateTokenAsync_EmitsValidatorLogs_WithoutClaimsIdentityAccess()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            var recorder = new RecordingLogger();
            LogHelper.Logger = recorder;

            try
            {
                var handler = new JsonWebTokenHandler();
                string token = CreateValidToken();
                ValidationParameters validationParameters = CreateValidationParameters();
                var callContext = new CallContext();

                // Act
                ValidationResult<ValidatedToken, ValidationError> validationResult =
                    await ((IResultBasedValidation)handler).ValidateTokenAsync(token, validationParameters, callContext, default);

                // Assert
                Assert.True(validationResult.Succeeded);
                // The audience-match log (IDX10234) is captured by the validator and emitted by the handler's
                // end-of-validation drain — note we never touch validationResult.Result.ClaimsIdentity.
                Assert.Contains(recorder.Messages, m => m.Contains("IDX10234"));
                // The buffer was drained.
                Assert.Empty(callContext.CapturedLogEntries);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
            }
        }

        [Fact]
        public async Task ValidateTokenAsync_ReusedCallContext_DoesNotAccumulateLogsAcrossValidations()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            var recorder = new RecordingLogger();
            LogHelper.Logger = recorder;

            try
            {
                var handler = new JsonWebTokenHandler();
                string token = CreateValidToken();
                ValidationParameters validationParameters = CreateValidationParameters();
                var callContext = new CallContext();

                // Act — validate twice on the SAME CallContext.
                ValidationResult<ValidatedToken, ValidationError> first =
                    await ((IResultBasedValidation)handler).ValidateTokenAsync(token, validationParameters, callContext, default);
                int afterFirst = recorder.Messages.Count(m => m.Contains("IDX10234"));

                ValidationResult<ValidatedToken, ValidationError> second =
                    await ((IResultBasedValidation)handler).ValidateTokenAsync(token, validationParameters, callContext, default);
                int afterSecond = recorder.Messages.Count(m => m.Contains("IDX10234"));

                // Assert — each validation emits its own audience log exactly once; the second does not
                // re-emit the first's (the drain clears the buffer between validations).
                Assert.True(first.Succeeded);
                Assert.True(second.Succeeded);
                Assert.Equal(1, afterFirst);
                Assert.Equal(2, afterSecond);
                Assert.Empty(callContext.CapturedLogEntries);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
            }
        }

        [Fact]
        public async Task ValidateTokenAsync_StringEntryPoint_NestedScopes_EmitsCapturedLogExactlyOnce()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            var recorder = new RecordingLogger();
            LogHelper.Logger = recorder;

            try
            {
                var handler = new JsonWebTokenHandler();
                string token = CreateValidToken();
                ValidationParameters validationParameters = CreateValidationParameters();
                var callContext = new CallContext();

                // Act - the string overload opens a drain scope and then calls the SecurityToken overload,
                // which opens a second scope on the SAME CallContext. Only the outermost (string) scope must
                // drain, so a captured validator log is emitted exactly once, not once per nested scope.
                ValidationResult<ValidatedToken, ValidationError> validationResult =
                    await ((IResultBasedValidation)handler).ValidateTokenAsync(token, validationParameters, callContext, default);

                // Assert - the audience-match log (IDX10234) is captured once during validation and emitted
                // exactly once by the outermost scope, despite the nested string/SecurityToken scoping.
                Assert.True(validationResult.Succeeded);
                Assert.Equal(1, recorder.Messages.Count(m => m.Contains("IDX10234")));
                Assert.Empty(callContext.CapturedLogEntries);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
            }
        }

        [Fact]
        public async Task LazyClaimsIdentity_IDX10245_RedactedWhenPiiPolicyDisabledBeforeClaimsAccess()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            bool originalShowPii = IdentityModelEventSource.ShowPII;
            var recorder = new RecordingLogger();
            LogHelper.Logger = recorder;
            IdentityModelEventSource.ShowPII = true; // PII display ON during validation

            try
            {
                var handler = new JsonWebTokenHandler();
                string token = CreateValidToken();
                ValidationParameters validationParameters = CreateValidationParameters();
                var callContext = new CallContext();

                ValidationResult<ValidatedToken, ValidationError> validationResult =
                    await ((IResultBasedValidation)handler).ValidateTokenAsync(token, validationParameters, callContext, default);
                Assert.True(validationResult.Succeeded);

                // The claims identity has not been accessed yet, so the lazy IDX10245 has not been emitted.
                Assert.DoesNotContain(recorder.Messages, m => m.Contains("IDX10245"));

                // Act - the PII policy flips OFF after validation completes but before the lazy claims access.
                // The lazy path emits IDX10245 at access time on its own CallContext, so redaction must reflect
                // the policy now (off), not the policy at validation time (on).
                IdentityModelEventSource.ShowPII = false;
                _ = validationResult.Result!.ClaimsIdentity;

                // Assert - IDX10245 is emitted (the lazy path drains), but the token argument is redacted.
                string idx10245 = Assert.Single(recorder.Messages, m => m.Contains("IDX10245"));
                Assert.Contains("hidden", idx10245, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(token, idx10245);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
                IdentityModelEventSource.ShowPII = originalShowPii;
            }
        }

        [Fact]
        public async Task ValidateTokenAsync_ConfigRefreshRetry_EmitsOnlyFinalAttemptLogs()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            var recorder = new RecordingLogger();
            LogHelper.Logger = recorder;

            try
            {
                var handler = new JsonWebTokenHandler();
                string token = CreateValidToken(); // signed with JsonWebKeyRsa256

                // Initial config carries the WRONG signing key so the first validation attempt captures its
                // informational logs (e.g. the audience match) and then fails at signature validation. The
                // refreshed config carries the RIGHT key so the retry succeeds.
                var wrongConfig = new OpenIdConnectConfiguration { Issuer = Issuer };
                wrongConfig.SigningKeys.Add(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key);

                var rightConfig = new OpenIdConnectConfiguration { Issuer = Issuer };
                rightConfig.SigningKeys.Add(KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key);

                var configManager = new MockConfigurationManager<OpenIdConnectConfiguration>(
                    wrongConfig, wrongConfig, rightConfig);

                // Empty SigningKeys forces validation to rely on the configuration's keys, so the first
                // attempt genuinely fails and the config-refresh retry path is exercised.
                ValidationParameters validationParameters = ValidationUtils.CreateValidationParameters(
                    audiences: [Audience],
                    issuers: [Issuer],
                    signingKeys: new List<SecurityKey>());
                validationParameters.ConfigurationManager = configManager;

                var callContext = new CallContext();

                // Act
                ValidationResult<ValidatedToken, ValidationError> validationResult =
                    await ((IResultBasedValidation)handler).ValidateTokenAsync(token, validationParameters, callContext, default);

                // Assert - success proves the retry recovered with the refreshed key (the first attempt failed
                // at signature). The audience-match log (IDX10234) is captured on BOTH attempts, but the first
                // attempt's entry is discarded via ClearCapturedLogs before the retry, so it is emitted exactly
                // once - only the final attempt's logs survive.
                Assert.True(validationResult.Succeeded);
                Assert.Equal(1, recorder.Messages.Count(m => m.Contains("IDX10234")));
                Assert.Empty(callContext.CapturedLogEntries);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
            }
        }

        [Fact]
        public async Task ValidateTokenAsync_NullCallContext_ReturnsNullParameterErrorInsteadOfThrowing()
        {
            // Arrange
            var handler = new JsonWebTokenHandler();
            string token = CreateValidToken();
            ValidationParameters validationParameters = CreateValidationParameters();

            // Act - the handler opens a BeginLogEmissionScope at entry; a null callContext must surface as a
            // structured ValidationError (NullArgument), not an incidental NullReferenceException.
            ValidationResult<ValidatedToken, ValidationError> validationResult =
                await ((IResultBasedValidation)handler).ValidateTokenAsync(token, validationParameters, null!, default);

            // Assert
            Assert.False(validationResult.Succeeded);
            Assert.Equal(ValidationFailureType.NullArgument, validationResult.Error!.FailureType);
        }

        [Fact]
        public async Task LazyClaimsIdentity_CreationThrows_RepeatedAccessRetriesAndDoesNotCacheFailure()
        {
            // Arrange - a NameClaimTypeRetriever that throws makes lazy claims creation fail. Claims creation
            // runs lazily (after validation completes), so validation itself still succeeds.
            var handler = new JsonWebTokenHandler();
            string token = CreateValidToken();

            int retrieverCalls = 0;
            ValidationParameters validationParameters = CreateValidationParameters();
            validationParameters.NameClaimTypeRetriever = (securityToken, issuer) =>
            {
                retrieverCalls++;
                throw new InvalidOperationException("claims creation failure");
            };

            var callContext = new CallContext();

            // Act
            ValidationResult<ValidatedToken, ValidationError> validationResult =
                await ((IResultBasedValidation)handler).ValidateTokenAsync(token, validationParameters, callContext, default);
            Assert.True(validationResult.Succeeded);

            // Assert - each ClaimsIdentity access retries creation because _claimsIdentityInitialized stays
            // false when creation throws; the failure is deliberately not cached, so the retriever runs again.
            Assert.Throws<InvalidOperationException>(() => _ = validationResult.Result!.ClaimsIdentity);
            Assert.Throws<InvalidOperationException>(() => _ = validationResult.Result!.ClaimsIdentity);
            Assert.Equal(2, retrieverCalls);
        }

        [Fact]
        public async Task ValidateTokenAsync_ConfigRetrievalFails_EmitsIDX10261WarningExactlyOnce()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            var recorder = new RecordingLogger();
            LogHelper.Logger = recorder;

            try
            {
                var handler = new JsonWebTokenHandler();
                string token = CreateValidToken();

                // The configuration manager throws on the first fetch, so GetCurrentConfigurationAsync captures
                // IDX10261 (Warning) and continues; the issuer/key are set directly on the parameters so
                // validation succeeds from local data. currentConfiguration stays null, so no refresh/LKG retry
                // runs and the warning is never cleared.
                var config = new OpenIdConnectConfiguration { Issuer = Issuer };
                var configManager = new MockConfigurationManager<OpenIdConnectConfiguration>(
                    config, new InvalidOperationException("configuration retrieval failed"));

                ValidationParameters validationParameters = CreateValidationParameters();
                validationParameters.ConfigurationManager = configManager;

                var callContext = new CallContext();

                // Act
                ValidationResult<ValidatedToken, ValidationError> validationResult =
                    await ((IResultBasedValidation)handler).ValidateTokenAsync(token, validationParameters, callContext, default);

                // Assert - validation proceeded on the locally-configured issuer/key, and the config-failure
                // warning (IDX10261) is captured and emitted exactly once.
                Assert.True(validationResult.Succeeded);
                Assert.Equal(1, recorder.Messages.Count(m => m.Contains("IDX10261")));
                Assert.Empty(callContext.CapturedLogEntries);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
            }
        }

        private sealed class RecordingLogger : IIdentityLogger
        {
            public List<string> Messages { get; } = new List<string>();

            public bool IsEnabled(EventLogLevel eventLogLevel) => true;

            public void Log(LogEntry entry) => Messages.Add(entry.Message);
        }
    }
}
