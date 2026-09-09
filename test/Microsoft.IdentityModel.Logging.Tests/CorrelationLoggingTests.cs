// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Microsoft.IdentityModel.Logging.Tests
{
    // Covers the #3361 logging-engine correlation behavior:
    //   - correlation id is opt-in and gated by LoggerContext.LogCorrelationId (default true, kill switch)
    //   - ActivityId is never promoted into ILogger messages
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
        public void ResolveCorrelationId_ReturnsCorrelationId_WhenSet()
        {
            // Arrange
            var context = new LoggerContext { CorrelationId = "corr-123" };

            // Act & Assert
            Assert.Equal("corr-123", context.ResolveCorrelationId());
        }

        [Fact]
        public void ResolveCorrelationId_ReturnsNull_WhenNotSet()
        {
            // Arrange
            var context = new LoggerContext();

            // Act & Assert
            Assert.Null(context.ResolveCorrelationId());
        }

        [Fact]
        public void ResolveCorrelationId_ReturnsNull_WhenKillSwitchOff()
        {
            // Arrange
            var context = new LoggerContext { CorrelationId = "corr-123", LogCorrelationId = false };

            // Act & Assert
            Assert.Null(context.ResolveCorrelationId());
        }

        [Fact]
        public void ResolveCorrelationId_DoesNotPromoteActivityId()
        {
            // Arrange: ActivityId set but no CorrelationId - must not be promoted.
            var context = new LoggerContext { ActivityId = Guid.NewGuid() };

            // Act & Assert
            Assert.Null(context.ResolveCorrelationId());
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void ResolveCorrelationId_ReturnsNull_WhenCorrelationIdNullOrEmpty(string correlationId)
        {
            // Arrange: an empty/null correlation id must not produce a trailing "CorrelationId: ." fragment.
            var context = new LoggerContext { CorrelationId = correlationId };

            // Act & Assert
            Assert.Null(context.ResolveCorrelationId());
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

        [Fact]
        public void LogWarning_WritesCorrelationId_WhenSet()
        {
            // Arrange
            var logger = new CapturingLogger();
            var context = new LoggerContext(logger) { CorrelationId = "corr-123" };

            // Act
            LogHelper.LogWarning("IDXTEST: correlation test.", context);

            // Assert
            Assert.NotEmpty(logger.Messages);
            Assert.Contains(logger.Messages, message => message.Contains("CorrelationId: corr-123"));
        }

        [Fact]
        public void LogWarning_OmitsCorrelationId_WhenKillSwitchOff()
        {
            // Arrange
            var logger = new CapturingLogger();
            var context = new LoggerContext(logger) { CorrelationId = "corr-123", LogCorrelationId = false };

            // Act
            LogHelper.LogWarning("IDXTEST: correlation test.", context);

            // Assert
            Assert.NotEmpty(logger.Messages);
            Assert.All(logger.Messages, message => Assert.DoesNotContain("CorrelationId", message));
        }

        [Fact]
        public void LogWarning_DoesNotPromoteActivityId()
        {
            // Arrange: ActivityId set but no CorrelationId.
            var logger = new CapturingLogger();
            var context = new LoggerContext(logger) { ActivityId = Guid.NewGuid() };

            // Act
            LogHelper.LogWarning("IDXTEST: correlation test.", context);

            // Assert
            Assert.NotEmpty(logger.Messages);
            Assert.All(logger.Messages, message => Assert.DoesNotContain("CorrelationId", message));
        }

        [Fact]
        public void LogWarning_OmitsCorrelationId_ByDefault()
        {
            // Arrange: nothing supplied.
            var logger = new CapturingLogger();
            var context = new LoggerContext(logger);

            // Act
            LogHelper.LogWarning("IDXTEST: correlation test.", context);

            // Assert
            Assert.NotEmpty(logger.Messages);
            Assert.All(logger.Messages, message => Assert.DoesNotContain("CorrelationId", message));
        }

        [Fact]
        public void LogWarning_OmitsCorrelationId_WhenCorrelationIdEmpty()
        {
            // Arrange: an empty correlation id must not append a "CorrelationId: ." fragment.
            var logger = new CapturingLogger();
            var context = new LoggerContext(logger) { CorrelationId = string.Empty };

            // Act
            LogHelper.LogWarning("IDXTEST: correlation test.", context);

            // Assert
            Assert.NotEmpty(logger.Messages);
            Assert.All(logger.Messages, message => Assert.DoesNotContain("CorrelationId", message));
        }

        [Fact]
        public void LogWarning_AppendsCorrelationId_AfterFormattingArgs()
        {
            // Arrange: correlation id is appended after the message is formatted with its args.
            var logger = new CapturingLogger();
            var context = new LoggerContext(logger) { CorrelationId = "corr-123" };

            // Act
            LogHelper.LogWarning("IDXTEST: value is {0}.", context, LogHelper.MarkAsNonPII("formatted-arg"));

            // Assert
            Assert.Contains(logger.Messages, message => message.Contains("formatted-arg") && message.Contains("CorrelationId: corr-123"));
        }

        [Fact]
        public void LogExceptionMessage_WritesCorrelationId_WhenSet()
        {
            // Arrange
            var logger = new CapturingLogger();
            var context = new LoggerContext(logger) { CorrelationId = "corr-123" };
            var exception = new InvalidOperationException("IDXTEST: exception path.");

            // Act
            LogHelper.LogExceptionMessage(exception, context);

            // Assert
            Assert.NotEmpty(logger.Messages);
            Assert.Contains(logger.Messages, message => message.Contains("CorrelationId: corr-123"));
        }

        [Fact]
        public void LogExceptionMessage_OmitsCorrelationId_WhenKillSwitchOff()
        {
            // Arrange
            var logger = new CapturingLogger();
            var context = new LoggerContext(logger) { CorrelationId = "corr-123", LogCorrelationId = false };
            var exception = new InvalidOperationException("IDXTEST: exception path.");

            // Act
            LogHelper.LogExceptionMessage(exception, context);

            // Assert
            Assert.NotEmpty(logger.Messages);
            Assert.All(logger.Messages, message => Assert.DoesNotContain("CorrelationId", message));
        }

        [Theory]
        [InlineData(LoggingPath.Information)]
        [InlineData(LoggingPath.Verbose)]
        [InlineData(LoggingPath.Warning)]
        [InlineData(LoggingPath.Exception)]
        public void ContextLogger_IsAuthoritative_WhenProvided(LoggingPath loggingPath)
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            bool originalHeaderWritten = LogHelper.HeaderWritten;
            var staticLogger = new TestLogger();
            var contextLogger = new CapturingLogger();
            string message = $"IDXTEST: contextual {loggingPath} message.";

            try
            {
                LogHelper.Logger = staticLogger;
                LogHelper.HeaderWritten = true;

                // Act
                Log(loggingPath, message, new LoggerContext(contextLogger));

                // Assert
                Assert.Single(contextLogger.Messages);
                Assert.Contains(message, contextLogger.Messages[0]);
                Assert.False(staticLogger.ContainsLog(message));
            }
            finally
            {
                LogHelper.Logger = originalLogger;
                LogHelper.HeaderWritten = originalHeaderWritten;
            }
        }

        [Theory]
        [InlineData(LoggingPath.Information)]
        [InlineData(LoggingPath.Verbose)]
        [InlineData(LoggingPath.Warning)]
        [InlineData(LoggingPath.Exception)]
        public void StaticLogger_IsFallback_WhenContextLoggerNotProvided(LoggingPath loggingPath)
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            bool originalHeaderWritten = LogHelper.HeaderWritten;
            var staticLogger = new TestLogger();
            string message = $"IDXTEST: fallback {loggingPath} message.";

            try
            {
                LogHelper.Logger = staticLogger;
                LogHelper.HeaderWritten = true;

                // Act
                Log(loggingPath, message, new LoggerContext());

                // Assert
                Assert.True(staticLogger.ContainsLog(message));
            }
            finally
            {
                LogHelper.Logger = originalLogger;
                LogHelper.HeaderWritten = originalHeaderWritten;
            }
        }

        private static void Log(LoggingPath loggingPath, string message, LoggerContext context)
        {
            switch (loggingPath)
            {
                case LoggingPath.Information:
                    LogHelper.LogInformation(message, context);
                    break;
                case LoggingPath.Verbose:
                    LogHelper.LogVerbose(message, context);
                    break;
                case LoggingPath.Warning:
                    LogHelper.LogWarning(message, context);
                    break;
                case LoggingPath.Exception:
                    LogHelper.LogExceptionMessage(new InvalidOperationException(message), context);
                    break;
            }
        }

        public enum LoggingPath
        {
            Information,
            Verbose,
            Warning,
            Exception,
        }

        // Exposes the protected LoggerContext copy constructor for testing.
        private sealed class DerivedLoggerContext : LoggerContext
        {
            public DerivedLoggerContext(LoggerContext other) : base(other)
            {
            }
        }

        // Minimal ILogger that captures the rendered message text.
        private sealed class CapturingLogger : ILogger
        {
            public List<string> Messages { get; } = new List<string>();

            public bool Enabled { get; set; } = true;

            public IDisposable BeginScope<TState>(TState state) => NullScope.Instance;

            public bool IsEnabled(LogLevel logLevel) => Enabled;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
                Messages.Add(formatter(state, exception));
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
