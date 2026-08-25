// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class HighPerformanceLoggingTests
    {
        [Theory]
        [InlineData(false, LogLevel.Debug)]
        [InlineData(true, LogLevel.Information)]
        [ResetAppContextSwitches]
        public void ValidateAudienceLogsThroughCallContext(bool logAsInformation, LogLevel expectedLevel)
        {
            // Arrange
            if (logAsInformation)
                AppContext.SetSwitch("Switch.Microsoft.IdentityModel.SuccessValidationLogsAsInformation", true);

            const string audience = "https://test.audience.com";
            var logger = new CapturingLogger();
            var callContext = new CallContext(logger);
            var validationParameters = new ValidationParameters();
            validationParameters.ValidAudiences.Add(audience);

            // Act
            ValidationResult<string, ValidationError> result = Validators.ValidateAudience(
                [audience],
                null,
                validationParameters,
                callContext);

            // Assert
            Assert.True(result.Succeeded);
            CapturedLog log = Assert.Single(logger.Logs);
            Assert.Equal(10234, log.EventId.Id);
            Assert.Equal(expectedLevel, log.Level);
            Assert.Contains(audience, log.Message);
        }

        [Fact]
        [ResetAppContextSwitches]
        public void ValidateAudienceSanitizesNonPiiValues()
        {
            // Arrange
            const string audience = "audience\nvalue";
            var logger = new CapturingLogger();
            var callContext = new CallContext(logger);
            var validationParameters = new ValidationParameters();
            validationParameters.ValidAudiences.Add(audience);

            // Act
            ValidationResult<string, ValidationError> result = Validators.ValidateAudience(
                [audience],
                null,
                validationParameters,
                callContext);

            // Assert
            Assert.True(result.Succeeded);
            CapturedLog log = Assert.Single(logger.Logs);
            Assert.Contains("audience\\nvalue", log.Message);
            Assert.DoesNotContain(audience, log.Message);
        }

        [Fact]
        public async Task ValidateIssuerLogsThroughCallContext()
        {
            // Arrange
            const string issuer = "https://test.issuer.com";
            var logger = new CapturingLogger();
            var callContext = new CallContext(logger);
            var validationParameters = new ValidationParameters();
            validationParameters.ValidIssuers.Add(string.Empty);
            validationParameters.ValidIssuers.Add(issuer);

            // Act
            ValidationResult<ValidatedIssuer, ValidationError> result = await Validators.ValidateIssuerAsync(
                issuer,
                null,
                validationParameters,
                callContext,
                CancellationToken.None);

            // Assert
            Assert.True(result.Succeeded);
            Assert.Collection(
                logger.Logs,
                log =>
                {
                    Assert.Equal(10262, log.EventId.Id);
                    Assert.Equal(LogLevel.Information, log.Level);
                },
                log =>
                {
                    Assert.Equal(10236, log.EventId.Id);
                    Assert.Equal(LogLevel.Information, log.Level);
                    Assert.Contains(issuer, log.Message);
                });
        }

        [Theory]
        [InlineData(false, LogLevel.Debug)]
        [InlineData(true, LogLevel.Information)]
        [ResetAppContextSwitches]
        public void ValidateLifetimeLogsThroughCallContext(bool logAsInformation, LogLevel expectedLevel)
        {
            // Arrange
            if (logAsInformation)
                AppContext.SetSwitch("Switch.Microsoft.IdentityModel.SuccessValidationLogsAsInformation", true);

            var logger = new CapturingLogger();
            var callContext = new CallContext(logger);
            var validationParameters = new ValidationParameters();
            DateTime now = DateTime.UtcNow;

            // Act
            ValidationResult<ValidatedLifetime, ValidationError> result = Validators.ValidateLifetime(
                now.AddMinutes(-1),
                now.AddMinutes(1),
                null,
                validationParameters,
                callContext);

            // Assert
            Assert.True(result.Succeeded);
            CapturedLog log = Assert.Single(logger.Logs);
            Assert.Equal(10239, log.EventId.Id);
            Assert.Equal(expectedLevel, log.Level);
        }

        private sealed class CapturingLogger : ILogger
        {
            internal IList<CapturedLog> Logs { get; } = new List<CapturedLog>();

            public IDisposable BeginScope<TState>(TState state) => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception exception,
                Func<TState, Exception, string> formatter)
            {
                Logs.Add(new CapturedLog(logLevel, eventId, formatter(state, exception)));
            }
        }

        private sealed class CapturedLog
        {
            internal CapturedLog(LogLevel level, EventId eventId, string message)
            {
                Level = level;
                EventId = eventId;
                Message = message;
            }

            internal EventId EventId { get; }
            internal LogLevel Level { get; }
            internal string Message { get; }
        }
    }
}
