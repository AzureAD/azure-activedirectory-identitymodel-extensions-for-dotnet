// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Diagnostics.Tracing;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestExtensions;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests;

[CollectionDefinition("Correlation logging global state", DisableParallelization = true)]
public sealed class CorrelationLoggingCollection
{
}

[Collection("Correlation logging global state")]
public class CorrelationLoggingTests
{
    private const int IssuerValidatedEventId = 10236;

    [Fact]
    public async Task ValidateTokenAsync_EmitsCorrelationIdOnGeneratedValidatorLog()
    {
        // Arrange
        var logger = new CapturingLogger();
        var callContext = new CallContext(logger, "correlation-id");
        EventLevel originalLogLevel = IdentityModelEventSource.Logger.LogLevel;
        using var listener = new SampleListener();
        IdentityModelEventSource.Logger.LogLevel = EventLevel.Informational;
        listener.EnableEvents(
            IdentityModelEventSource.Logger,
            EventLevel.Informational,
            EventKeywords.All);

        try
        {
            // Act
            ValidationResult<ValidatedToken, ValidationError> result =
                await ValidateTokenAsync(callContext);

            // Assert
            Assert.True(result.Succeeded);
            LogRecord record = Assert.Single(logger.Records, record => record.EventId == IssuerValidatedEventId);
            Assert.Contains("IDX10236", record.Message);
            Assert.Contains("CorrelationId: 'correlation-id'", record.Message);
            Assert.Contains("IDX10236", listener.TraceBuffer);
        }
        finally
        {
            IdentityModelEventSource.Logger.LogLevel = originalLogLevel;
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task ValidateTokenAsync_DoesNotEmitCorrelationIdWhenNullOrEmpty(string correlationId)
    {
        // Arrange
        var logger = new CapturingLogger();
        var callContext = new CallContext(logger, correlationId);

        // Act
        ValidationResult<ValidatedToken, ValidationError> result =
            await ValidateTokenAsync(callContext);

        // Assert
        Assert.True(result.Succeeded);
        LogRecord record = Assert.Single(logger.Records, record => record.EventId == IssuerValidatedEventId);
        Assert.DoesNotContain("CorrelationId", record.Message);
        Assert.Equal(0, logger.ScopeCount);
    }

    [Fact]
    public async Task ValidateTokenAsync_IsolatesCorrelationIdsAcrossConcurrentOperations()
    {
        // Arrange
        using var logBarrier = new Barrier(2);
        var logger = new CapturingLogger(logBarrier);

        // Act
        Task<ValidationResult<ValidatedToken, ValidationError>> firstValidation =
            Task.Run(() => ValidateTokenAsync(new CallContext(logger, "correlation-one")));
        Task<ValidationResult<ValidatedToken, ValidationError>> secondValidation =
            Task.Run(() => ValidateTokenAsync(new CallContext(logger, "correlation-two")));

        ValidationResult<ValidatedToken, ValidationError>[] results =
            await Task.WhenAll(firstValidation, secondValidation);

        // Assert
        Assert.All(results, result => Assert.True(result.Succeeded));
        LogRecord[] records = logger.Records
            .Where(record => record.EventId == IssuerValidatedEventId)
            .ToArray();

        Assert.Equal(2, records.Length);
        Assert.Contains(records, record => record.Message.Contains("CorrelationId: 'correlation-one'"));
        Assert.Contains(records, record => record.Message.Contains("CorrelationId: 'correlation-two'"));
        Assert.Equal(0, logger.ScopeCount);
    }

    [Fact]
    public async Task ValidateTokenAsync_DoesNotEmitActivityIdAsCorrelationId()
    {
        // Arrange
        var logger = new CapturingLogger();
        var callContext = new CallContext(logger, Guid.NewGuid());

        // Act
        ValidationResult<ValidatedToken, ValidationError> result =
            await ValidateTokenAsync(callContext);

        // Assert
        Assert.True(result.Succeeded);
        LogRecord record = Assert.Single(logger.Records, record => record.EventId == IssuerValidatedEventId);
        Assert.DoesNotContain("CorrelationId", record.Message);
        Assert.Equal(0, logger.ScopeCount);
    }

    [Fact]
    public async Task ValidateTokenAsync_DoesNotEmitCorrelationIdWhenDisabled()
    {
        // Arrange
        var logger = new CapturingLogger();
        var callContext = new CallContext(logger, "correlation-id")
        {
            LogCorrelationId = false
        };

        // Act
        ValidationResult<ValidatedToken, ValidationError> result =
            await ValidateTokenAsync(callContext);

        // Assert
        Assert.True(result.Succeeded);
        LogRecord record = Assert.Single(logger.Records, record => record.EventId == IssuerValidatedEventId);
        Assert.DoesNotContain("CorrelationId", record.Message);
        Assert.Equal(0, logger.ScopeCount);
    }

    [Fact]
    public async Task ValidateTokenAsync_UsesLegacyLoggerWhenContextLoggerNotSupplied()
    {
        // Arrange
        IIdentityLogger originalLogger = LogHelper.Logger;
        var legacyLogger = new CapturingIdentityLogger();

        try
        {
            LogHelper.Logger = legacyLogger;

            // Act
            ValidationResult<ValidatedToken, ValidationError> result =
                await ValidateTokenAsync(new CallContext());

            // Assert
            Assert.True(result.Succeeded);
            Assert.True(legacyLogger.ContainsLog("IDX10236"));
        }
        finally
        {
            LogHelper.Logger = originalLogger;
        }
    }

    [Fact]
    public async Task ValidateTokenAsync_DoesNotUseLegacyLoggerWhenContextLoggerSupplied()
    {
        // Arrange
        IIdentityLogger originalLogger = LogHelper.Logger;
        var legacyLogger = new CapturingIdentityLogger();
        var contextLogger = new CapturingLogger();

        try
        {
            LogHelper.Logger = legacyLogger;

            // Act
            ValidationResult<ValidatedToken, ValidationError> result =
                await ValidateTokenAsync(new CallContext(contextLogger));

            // Assert
            Assert.True(result.Succeeded);
            Assert.Single(contextLogger.Records, record => record.EventId == IssuerValidatedEventId);
            Assert.False(legacyLogger.ContainsLog("IDX10236"));
        }
        finally
        {
            LogHelper.Logger = originalLogger;
        }
    }

    private static async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
        CallContext callContext)
    {
        var tokenCreator = new TestTokenCreator
        {
            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials
        };
        var handler = new JsonWebTokenHandler();
        var resultBasedHandler = (IResultBasedValidation)handler;
        string token = tokenCreator.CreateDefaultValidToken();
        ValidationParameters validationParameters = ValidationUtils.CreateValidationParameters(
            audiences: ["http://Default.Audience.com"],
            issuers: ["http://Default.Issuer.com"],
            signingKeys: [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]);

        return await resultBasedHandler.ValidateTokenAsync(
            token,
            validationParameters,
            callContext,
            default);
    }

    private sealed class CapturingLogger : ILogger
    {
        private readonly Barrier _logBarrier;
        private int _scopeCount;

        public CapturingLogger(Barrier logBarrier = null)
        {
            _logBarrier = logBarrier;
        }

        public int ScopeCount => _scopeCount;

        public ConcurrentQueue<LogRecord> Records { get; } = new ConcurrentQueue<LogRecord>();

        public IDisposable BeginScope<TState>(TState state)
        {
            Interlocked.Increment(ref _scopeCount);
            return NullScope.Instance;
        }

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception exception,
            Func<TState, Exception, string> formatter)
        {
            if (eventId.Id == IssuerValidatedEventId)
                _logBarrier?.SignalAndWait(TimeSpan.FromSeconds(10));

            Records.Enqueue(new LogRecord(
                eventId.Id,
                formatter(state, exception)));
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new NullScope();

            public void Dispose()
            {
            }
        }

    }

    private sealed class CapturingIdentityLogger : IIdentityLogger
    {
        private readonly ConcurrentQueue<LogEntry> _entries = new ConcurrentQueue<LogEntry>();

        public bool IsEnabled(EventLogLevel logLevel) => true;

        public void Log(LogEntry entry)
        {
            _entries.Enqueue(entry);
        }

        public bool ContainsLog(string value) =>
            _entries.Any(entry => entry.Message.Contains(value));
    }

    private sealed class LogRecord
    {
        public LogRecord(int eventId, string message)
        {
            EventId = eventId;
            Message = message;
        }

        public int EventId { get; }

        public string Message { get; }
    }
}
