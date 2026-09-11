// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Validators.Tests
{
    public class ValidatorsLoggerExtensionsTests
    {
        [Theory, MemberData(nameof(LoggerTestCases), DisableDiscoveryEnumeration = true)]
        public void LoggerMethodEmitsExpectedLog(LoggerTestCase testCase)
        {
            // Arrange
            var logger = new TestLogger();
            var callContext = new CallContext(logger);

            // Act
            testCase.Log(callContext.Logger);

            // Assert
            LogEntry logEntry = Assert.Single(logger.Logs);
            Assert.Equal(LogLevel.Error, logEntry.LogLevel);
            Assert.Equal(testCase.EventId, logEntry.EventId.Id);
            Assert.Equal(testCase.EventName, logEntry.EventId.Name);
            Assert.Equal(testCase.Message, logEntry.Message);
            Assert.Null(logEntry.Exception);
        }

        public static TheoryData<LoggerTestCase> LoggerTestCases()
        {
            return new TheoryData<LoggerTestCase>
            {
                new LoggerTestCase(
                    40001,
                    nameof(LoggerExtensions.NoValidIssuerMatch),
                    "IDX40001: Issuer: 'issuer', does not match any of the valid issuers provided for this application. ",
                    logger => logger.NoValidIssuerMatch("issuer")),
                new LoggerTestCase(
                    40002,
                    nameof(LoggerExtensions.UnsupportedB2CIssuer),
                    "IDX40002: Microsoft.IdentityModel does not support a B2C issuer with 'tfp' in the URI. See https://aka.ms/ms-id-web/b2c-issuer for details. ",
                    logger => logger.UnsupportedB2CIssuer()),
                new LoggerTestCase(
                    40003,
                    nameof(LoggerExtensions.MissingTenantIdClaim),
                    "IDX40003: Neither `tid` nor `tenantId` claim is present in the token obtained from Microsoft identity platform. ",
                    logger => logger.MissingTenantIdClaim()),
                new LoggerTestCase(
                    40004,
                    nameof(LoggerExtensions.TokenIssuerDoesNotContainTenantId),
                    "IDX40004: Token issuer: 'tokenIssuer', does not contain the `tid` or `tenantId` claim present in the token: 'tenantId'.",
                    logger => logger.TokenIssuerDoesNotContainTenantId("tokenIssuer", "tenantId")),
                new LoggerTestCase(
                    40005,
                    nameof(LoggerExtensions.TokenIssuerDoesNotMatchSigningKeyIssuer),
                    "IDX40005: Token issuer: 'tokenIssuer', does not match the signing key issuer: 'signingKeyIssuer'.",
                    logger => logger.TokenIssuerDoesNotMatchSigningKeyIssuer("tokenIssuer", "signingKeyIssuer")),
                new LoggerTestCase(
                    40007,
                    nameof(LoggerExtensions.NullIssuerSigningKey),
                    "IDX40007: RequireSignedTokens property on ValidationParameters is set to true, but the issuer signing key is null.",
                    logger => logger.NullIssuerSigningKey()),
                new LoggerTestCase(
                    40008,
                    nameof(LoggerExtensions.InvalidLastKnownGoodLifetime),
                    "IDX40008: When setting LastKnownGoodLifetime, the value must be greater than or equal to zero. value: '-00:01:00'.",
                    logger => logger.InvalidLastKnownGoodLifetime(TimeSpan.FromMinutes(-1))),
                new LoggerTestCase(
                    40009,
                    nameof(LoggerExtensions.MissingOrEmptyTenantIdClaim),
                    "IDX40009: Either the 'tid' claim was not found or it didn't have a value.",
                    logger => logger.MissingOrEmptyTenantIdClaim()),
                new LoggerTestCase(
                    40010,
                    nameof(LoggerExtensions.InvalidSecurityTokenType),
                    "IDX40010: The SecurityToken must be a 'JsonWebToken' or 'JwtSecurityToken'",
                    logger => logger.InvalidSecurityTokenType()),
                new LoggerTestCase(
                    40011,
                    nameof(LoggerExtensions.MultipleClaimInstances),
                    "IDX40011: The SecurityToken has multiple instances of the 'tid' claim.",
                    logger => logger.MultipleClaimInstances("tid")),
                new LoggerTestCase(
                    40012,
                    nameof(LoggerExtensions.SigningKeyCloudInstanceMismatch),
                    "IDX40012: The cloud instance of the signing key: 'signingKeyCloudInstance', does not match cloud instance from configuration: 'configurationCloudInstance'.",
                    logger => logger.SigningKeyCloudInstanceMismatch("signingKeyCloudInstance", "configurationCloudInstance"))
            };
        }

        public class LoggerTestCase : TheoryDataBase
        {
            public LoggerTestCase(int eventId, string eventName, string message, Action<ILogger> log)
                : base(eventName)
            {
                EventId = eventId;
                EventName = eventName;
                Message = message;
                Log = log;
            }

            public int EventId { get; }

            public string EventName { get; }

            public Action<ILogger> Log { get; }

            public string Message { get; }
        }

        private sealed class TestLogger : ILogger
        {
            private readonly List<LogEntry> _logs = new List<LogEntry>();
            private readonly object _syncObject = new object();

            public IReadOnlyList<LogEntry> Logs
            {
                get
                {
                    lock (_syncObject)
                    {
                        return _logs.ToArray();
                    }
                }
            }

            public IDisposable BeginScope<TState>(TState state)
            {
                return NullScope.Instance;
            }

            public bool IsEnabled(LogLevel logLevel)
            {
                return true;
            }

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception exception,
                Func<TState, Exception, string> formatter)
            {
                var logEntry = new LogEntry(logLevel, eventId, formatter(state, exception), exception);

                lock (_syncObject)
                {
                    _logs.Add(logEntry);
                }
            }
        }

        private sealed class LogEntry
        {
            public LogEntry(LogLevel logLevel, EventId eventId, string message, Exception exception)
            {
                LogLevel = logLevel;
                EventId = eventId;
                Message = message;
                Exception = exception;
            }

            public EventId EventId { get; }

            public Exception Exception { get; }

            public LogLevel LogLevel { get; }

            public string Message { get; }
        }

        private sealed class NullScope : IDisposable
        {
            public static NullScope Instance { get; } = new NullScope();

            public void Dispose()
            {
            }
        }
    }
}
