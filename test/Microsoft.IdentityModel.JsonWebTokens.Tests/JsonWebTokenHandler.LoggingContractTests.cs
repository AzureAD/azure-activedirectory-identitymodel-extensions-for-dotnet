// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    // Handler-level coverage for the #3455 logging contract: the drain scope on
    // JsonWebTokenHandler.ValidateTokenAsync emits captured validator logs on completion, independent of
    // whether the caller accesses ClaimsIdentity, and does not accumulate across a reused CallContext.
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

        private sealed class RecordingLogger : IIdentityLogger
        {
            public List<string> Messages { get; } = new List<string>();

            public bool IsEnabled(EventLogLevel eventLogLevel) => true;

            public void Log(LogEntry entry) => Messages.Add(entry.Message);
        }
    }
}
