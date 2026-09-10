// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Microsoft.IdentityModel.Logging.Tests
{
    // Covers the #3361 logging context contract:
    //   - explicit correlation can be enabled or suppressed
    //   - ActivityId remains distinct from ILogger correlation
    //   - the protected LoggerContext copy constructor carries logging state
    [Collection("Relying on ShowPII and LogCompleteSecurityArtifact")]
    public class CorrelationLoggingTests
    {
        [Fact]
        public void LogCorrelationId_DefaultsToTrue()
        {
            // Arrange & Act
            var context = new LoggerContext();

            // Assert
            Assert.True(context.LogCorrelationId);
        }

        [Fact]
        public void CopyConstructor_Throws_WhenOtherIsNull()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new DerivedLoggerContext(null));
        }

        [Fact]
        public void CopyConstructor_CarriesLoggingState()
        {
            // Arrange
            var logger = new CapturingLogger();
            var activityId = Guid.NewGuid();
            var source = new LoggerContext(logger)
            {
                CorrelationId = "corr-123",
                LogCorrelationId = false,
                ActivityId = activityId,
                CaptureLogs = true,
            };

            // Act
            var copy = new DerivedLoggerContext(source);

            // Assert: logging state carried over.
            Assert.Same(logger, copy.Logger);
            Assert.Equal("corr-123", copy.CorrelationId);
            Assert.False(copy.LogCorrelationId);
            Assert.Equal(activityId, copy.ActivityId);
            Assert.True(copy.CaptureLogs);

            // Assert: the mutable Logs buffer is not shared (avoids cross-contamination).
            Assert.NotSame(source.Logs, copy.Logs);
        }

        // Exposes the protected LoggerContext copy constructor for testing.
        private sealed class DerivedLoggerContext : LoggerContext
        {
            public DerivedLoggerContext(LoggerContext other) : base(other)
            {
            }
        }

        private sealed class CapturingLogger : ILogger
        {
            public IDisposable BeginScope<TState>(TState state) => NullScope.Instance;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
            }

            private sealed class NullScope : IDisposable
            {
                public static readonly NullScope Instance = new NullScope();

                public void Dispose()
                {
                }
            }
        }
    }
}
