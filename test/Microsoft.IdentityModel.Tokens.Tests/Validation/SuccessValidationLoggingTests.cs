// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Tests for verifying that success validation logs (IDX10239 and IDX10234) 
    /// are logged at the correct level based on the AppContext switch.
    /// </summary>
    public class SuccessValidationLoggingTests : IDisposable
    {
        private readonly IIdentityLogger _originalLogger;

        public SuccessValidationLoggingTests()
        {
            // Save original logger to restore after each test
            _originalLogger = LogHelper.Logger;
        }

        public void Dispose()
        {
            // Restore original logger after each test
            LogHelper.Logger = _originalLogger;
        }

        [Fact]
        [ResetAppContextSwitches]
        public void ValidateLifetime_LogsAtVerboseByDefault()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var notBefore = DateTime.UtcNow.AddMinutes(-10);
            var expires = DateTime.UtcNow.AddMinutes(10);
            var validationParameters = new TokenValidationParameters
            {
                ValidateLifetime = true
            };

            // Act
            ValidatorUtilities.ValidateLifetime(notBefore, expires, null, validationParameters);

            // Assert - Should log at Verbose level by default
            Assert.True(logger.ContainsLogOfSpecificLevel("IDX10239", EventLogLevel.Verbose),
                "IDX10239 should be logged at Verbose level by default");
            Assert.False(logger.ContainsLogOfSpecificLevel("IDX10239", EventLogLevel.Informational),
                "IDX10239 should not be logged at Informational level by default");
        }

        [Fact]
        [ResetAppContextSwitches]
        public void ValidateLifetime_LogsAtInformationalWhenSwitchEnabled()
        {
            // Arrange
            AppContext.SetSwitch("Switch.Microsoft.IdentityModel.SuccessValidationLogsAsInformation", true);
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var notBefore = DateTime.UtcNow.AddMinutes(-10);
            var expires = DateTime.UtcNow.AddMinutes(10);
            var validationParameters = new TokenValidationParameters
            {
                ValidateLifetime = true
            };

            // Act
            ValidatorUtilities.ValidateLifetime(notBefore, expires, null, validationParameters);

            // Assert - Should log at Informational level when switch is enabled
            Assert.True(logger.ContainsLogOfSpecificLevel("IDX10239", EventLogLevel.Informational),
                "IDX10239 should be logged at Informational level when switch is enabled");
            Assert.False(logger.ContainsLogOfSpecificLevel("IDX10239", EventLogLevel.Verbose),
                "IDX10239 should not be logged at Verbose level when switch is enabled");
        }

        [Fact]
        [ResetAppContextSwitches]
        public void ValidateAudience_LogsAtVerboseByDefault()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var audiences = new List<string> { "https://test.audience.com" };
            var validationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidAudience = "https://test.audience.com"
            };

            // Act
            Validators.ValidateAudience(audiences, null, validationParameters);

            // Assert - Should log at Verbose level by default
            Assert.True(logger.ContainsLogOfSpecificLevel("IDX10234", EventLogLevel.Verbose),
                "IDX10234 should be logged at Verbose level by default");
            Assert.False(logger.ContainsLogOfSpecificLevel("IDX10234", EventLogLevel.Informational),
                "IDX10234 should not be logged at Informational level by default");
        }

        [Fact]
        [ResetAppContextSwitches]
        public void ValidateAudience_LogsAtInformationalWhenSwitchEnabled()
        {
            // Arrange
            AppContext.SetSwitch("Switch.Microsoft.IdentityModel.SuccessValidationLogsAsInformation", true);
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var audiences = new List<string> { "https://test.audience.com" };
            var validationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidAudience = "https://test.audience.com"
            };

            // Act
            Validators.ValidateAudience(audiences, null, validationParameters);

            // Assert - Should log at Informational level when switch is enabled
            Assert.True(logger.ContainsLogOfSpecificLevel("IDX10234", EventLogLevel.Informational),
                "IDX10234 should be logged at Informational level when switch is enabled");
            Assert.False(logger.ContainsLogOfSpecificLevel("IDX10234", EventLogLevel.Verbose),
                "IDX10234 should not be logged at Verbose level when switch is enabled");
        }

        [Fact]
        [ResetAppContextSwitches]
        public void ValidateAudience_WithTrailingSlash_LogsAtVerboseByDefault()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var audiences = new List<string> { "https://test.audience.com" };
            var validationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidAudience = "https://test.audience.com/", // Has trailing slash
                IgnoreTrailingSlashWhenValidatingAudience = true
            };

            // Act
            Validators.ValidateAudience(audiences, null, validationParameters);

            // Assert - Should log at Verbose level by default
            Assert.True(logger.ContainsLogOfSpecificLevel("IDX10234", EventLogLevel.Verbose),
                "IDX10234 should be logged at Verbose level by default for trailing slash match");
            Assert.False(logger.ContainsLogOfSpecificLevel("IDX10234", EventLogLevel.Informational),
                "IDX10234 should not be logged at Informational level by default for trailing slash match");
        }

        [Fact]
        [ResetAppContextSwitches]
        public void ValidateAudience_WithTrailingSlash_LogsAtInformationalWhenSwitchEnabled()
        {
            // Arrange
            AppContext.SetSwitch("Switch.Microsoft.IdentityModel.SuccessValidationLogsAsInformation", true);
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var audiences = new List<string> { "https://test.audience.com" };
            var validationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidAudience = "https://test.audience.com/", // Has trailing slash
                IgnoreTrailingSlashWhenValidatingAudience = true
            };

            // Act
            Validators.ValidateAudience(audiences, null, validationParameters);

            // Assert - Should log at Informational level when switch is enabled
            Assert.True(logger.ContainsLogOfSpecificLevel("IDX10234", EventLogLevel.Informational),
                "IDX10234 should be logged at Informational level when switch is enabled for trailing slash match");
            Assert.False(logger.ContainsLogOfSpecificLevel("IDX10234", EventLogLevel.Verbose),
                "IDX10234 should not be logged at Verbose level when switch is enabled for trailing slash match");
        }

        // Helper class for testing logging behavior
        private class TestLogger : IIdentityLogger
        {
            readonly List<Tuple<string, EventLogLevel>> _logs = new List<Tuple<string, EventLogLevel>>();

            public bool IsEnabled(EventLogLevel logLevel)
            {
                return true;
            }

            public void Log(LogEntry entry)
            {
                _logs.Add(new Tuple<string, EventLogLevel>(entry.Message, entry.EventLogLevel));
            }

            public bool ContainsLogOfSpecificLevel(string substring, EventLogLevel logLevel)
            {
                if (string.IsNullOrEmpty(substring))
                    throw new ArgumentException("Provided value is null or empty.", nameof(substring));

                foreach (var log in _logs)
                {
                    if (log.Item1.Contains(substring) && log.Item2 == logLevel)
                        return true;
                }

                return false;
            }
        }
    }
}
