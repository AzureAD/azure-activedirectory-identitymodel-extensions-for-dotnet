// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Logging.Tests;

public class LoggerImpl : ILogger
{
    public class LogEntry
    {
        public LogLevel LogLevel { get; set; }

        public EventId EventId { get; set; }

        public object State { get; set; }

        public Exception Exception { get; set; }
    }

    private List<LogEntry> _logEntries = new List<LogEntry>();

    public LoggerImpl(LogLevel logLevel)
    {
        LogLevel = logLevel;
    }

    public LogLevel LogLevel { get; } = LogLevel.Information;

    public IDisposable BeginScope<TState>(TState state) => throw new NotImplementedException();

    public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception exception,
        Func<TState, Exception, string> formatter)
    {
        if (!IsEnabled(logLevel))
            return;

        _logEntries.Add(new LogEntry { LogLevel = logLevel, EventId = eventId, State = state, Exception = exception });
    }

    public IList<LogEntry> GetLogEntries()
    {
        return _logEntries.AsReadOnly();
    }
}

public class ILoggerTests
{
    /// <summary>
    /// Test that the LogHelper.IsEnabled method returns false when Ilogger is null.
    /// </summary>
    [Fact]
    public void ReturnsFalse_WhenLoggerContextIsNull()
    {
        Assert.False(LogHelper.IsEnabled(LogLevel.Information, null));
    }

    /// <summary>
    /// Tests that the new LoggerConext throws when passed null to ctor.
    /// </summary>
    [Fact]
    public void ThrowsWhenILoggerNull()
    {
        Assert.Throws<ArgumentNullException>(() => new LoggerContext((ILogger)null));
    }

    /// <summary>
    /// Tests that the LogHelper.LogExceptionMessage method logs exceptions at the correct log levels.
    /// </summary>
    /// <param name="logLevel">level to set ILogger.</param>
    /// <param name="shouldLogInfo">should we be expecting logs.</param>
    [Theory]
    [InlineData(LogLevel.Trace, true)]
    [InlineData(LogLevel.Debug, true)]
    [InlineData(LogLevel.Information, true)]
    [InlineData(LogLevel.Warning, true)]
    [InlineData(LogLevel.Error, true)]
    [InlineData(LogLevel.Critical, false)]
    [InlineData(LogLevel.None, false)]
    public void LogExceptions_Levels(LogLevel logLevel, bool shouldLogInfo)
    {
        LoggerImpl logger = new LoggerImpl(logLevel);
        string correlationId = Guid.NewGuid().ToString();
        LogHelper.LogExceptionMessage(new Exception("Exception"), new LoggerContext(logger) { CorrelationId = correlationId });

        Assert.True(logger.GetLogEntries().Count == (shouldLogInfo ? 1 : 0));
        if (shouldLogInfo)
            Assert.Contains(correlationId, logger.GetLogEntries()[0].State.ToString());
    }

    /// <summary>
    /// Tests that the LogHelper.LogInformation method logs information messages at the correct log levels.
    /// </summary>
    /// <param name="logLevel">level to set ILogger.</param>
    /// <param name="shouldLogInfo">should we be expecting logs.</param>
    [Theory]
    [InlineData(LogLevel.Trace, true)]
    [InlineData(LogLevel.Debug, true)]
    [InlineData(LogLevel.Information, true)]
    [InlineData(LogLevel.Warning, false)]
    [InlineData(LogLevel.Error, false)]
    [InlineData(LogLevel.Critical, false)]
    [InlineData(LogLevel.None, false)]
    public void LogInformation_Levels(LogLevel logLevel, bool shouldLogInfo)
    {
        string correlationId = Guid.NewGuid().ToString();
        LoggerImpl logger = new LoggerImpl(logLevel);
        LogHelper.LogInformation("Information", new LoggerContext(logger) { CorrelationId = correlationId });

        Assert.True(logger.GetLogEntries().Count == (shouldLogInfo ? 1 : 0));
        if (shouldLogInfo)
            Assert.Contains(correlationId, logger.GetLogEntries()[0].State.ToString());
    }

    /// <summary>
    /// Tests that the LogHelper.LogVerbose method logs verbose messages at the correct log levels.
    /// </summary>
    /// <param name="logLevel">level to set ILogger.</param>
    /// <param name="shouldLogInfo">should we be expecting logs.</param>
    [Theory]
    [InlineData(LogLevel.Trace, true)]
    [InlineData(LogLevel.Debug, true)]
    [InlineData(LogLevel.Information, false)]
    [InlineData(LogLevel.Warning, false)]
    [InlineData(LogLevel.Error, false)]
    [InlineData(LogLevel.Critical, false)]
    [InlineData(LogLevel.None, false)]
    public void LogVerbose_Levels(LogLevel logLevel, bool shouldLogInfo)
    {
        string correlationId = Guid.NewGuid().ToString();
        LoggerImpl logger = new LoggerImpl(logLevel);
        LogHelper.LogVerbose("Verbose", new LoggerContext(logger) { CorrelationId = correlationId });

        Assert.True(logger.GetLogEntries().Count == (shouldLogInfo ? 1 : 0));
        if (shouldLogInfo)
            Assert.Contains(correlationId, logger.GetLogEntries()[0].State.ToString());
    }

    /// <summary>
    /// Tests that the LogHelper.LogWarning method logs warnings at the correct log levels.
    /// </summary>
    /// <param name="logLevel">level to set ILogger.</param>
    /// <param name="shouldLogInfo">should we be expecting logs.</param>
    [Theory]
    [InlineData(LogLevel.Trace, true)]
    [InlineData(LogLevel.Debug, true)]
    [InlineData(LogLevel.Information, true)]
    [InlineData(LogLevel.Warning, true)]
    [InlineData(LogLevel.Error, false)]
    [InlineData(LogLevel.Critical, false)]
    [InlineData(LogLevel.None, false)]
    public void LogWarnings_Levels(LogLevel logLevel, bool shouldLogInfo)
    {
        string correlationId = Guid.NewGuid().ToString();
        LoggerImpl logger = new LoggerImpl(logLevel);
        LogHelper.LogWarning("Warning", new LoggerContext(logger) { CorrelationId = correlationId });

        Assert.True(logger.GetLogEntries().Count == (shouldLogInfo ? 1 : 0));
        if (shouldLogInfo)
            Assert.Contains(correlationId, logger.GetLogEntries()[0].State.ToString());
    }

    /// <summary>
    /// Tests that the ActivityId and CorrelationId are logged correctly when logging warnings.
    /// </summary>
    /// <param name="useActivityId"> whether to use an ActivityId.</param>
    /// <param name="useCorrelationId"> whether to use a CorrelationId.</param>
    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    public void ActivityCorrelationIds(bool useActivityId, bool useCorrelationId)
    {
        string correlationId = useCorrelationId ? Guid.NewGuid().ToString() : null;
        Guid activityId = useActivityId ? Guid.NewGuid() : Guid.Empty;
        LoggerImpl logger = new LoggerImpl(LogLevel.Warning);
        CallContext callContext = new CallContext(logger) { CorrelationId = correlationId, ActivityId = activityId };
        LogHelper.LogWarning("Warning", callContext);

        if (useCorrelationId)
            Assert.Contains(correlationId, logger.GetLogEntries()[0].State.ToString(), StringComparison.InvariantCulture);

        // CorrelationId overrides ActivityId
        if (useActivityId && !useCorrelationId)
            Assert.Contains(activityId.ToString(), logger.GetLogEntries()[0].State.ToString(), StringComparison.InvariantCulture);
    }
}
