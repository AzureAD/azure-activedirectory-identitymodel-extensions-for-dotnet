// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
    [CollectionDefinition(nameof(HighPerformanceLoggingTests), DisableParallelization = true)]
    public class HighPerformanceLoggingTestCollection
    {
    }

    [Collection(nameof(HighPerformanceLoggingTests))]
    public class HighPerformanceLoggingTests
    {
        private const string XmlNamespace = "http://www.w3.org/2000/09/xmldsig#";

        [Theory]
        [InlineData("<Unknown>sensitive-value</Unknown>", 0)]
        [InlineData("<X509Data><Unknown>sensitive-value</Unknown></X509Data>", 1)]
        public void ReadKeyInfoLogsUnknownElementsThroughCallContext(string childElement, int expectedX509DataCount)
        {
            // Arrange
            bool showPii = IdentityModelEventSource.ShowPII;
            IdentityModelEventSource.ShowPII = false;
            var logger = new CapturingLogger(isEnabled: true);
            var callContext = new CallContext(logger);
            string xml = $"<KeyInfo xmlns=\"{XmlNamespace}\">{childElement}</KeyInfo>";

            try
            {
                // Act
                KeyInfo keyInfo = DSigSerializer.Default.ReadKeyInfo(
                    XmlUtilities.CreateDictionaryReader(xml),
                    callContext);

                // Assert
                Assert.Equal(expectedX509DataCount, keyInfo.X509Data.Count);
                CapturedLog log = Assert.Single(logger.Logs);
                Assert.Equal(30300, log.EventId.Id);
                Assert.Equal(LogLevel.Warning, log.Level);
                Assert.Contains("IDX30300:", log.Message);
                Assert.DoesNotContain("sensitive-value", log.Message);
            }
            finally
            {
                IdentityModelEventSource.ShowPII = showPii;
            }
        }

        [Fact]
        public void ReadKeyInfoSkipsUnknownElementWhenLoggerIsDisabled()
        {
            // Arrange
            var logger = new CapturingLogger(isEnabled: false);
            var callContext = new CallContext(logger);
            string xml = $"<KeyInfo xmlns=\"{XmlNamespace}\"><Unknown /><KeyName>name</KeyName></KeyInfo>";

            // Act
            KeyInfo keyInfo = DSigSerializer.Default.ReadKeyInfo(
                XmlUtilities.CreateDictionaryReader(xml),
                callContext);

            // Assert
            Assert.Equal("name", keyInfo.KeyName);
            Assert.Empty(logger.Logs);
        }

        private sealed class CapturingLogger : ILogger
        {
            private readonly bool _isEnabled;

            internal CapturingLogger(bool isEnabled)
            {
                _isEnabled = isEnabled;
            }

            internal IList<CapturedLog> Logs { get; } = new List<CapturedLog>();

            public IDisposable BeginScope<TState>(TState state) => null;

            public bool IsEnabled(LogLevel logLevel) => _isEnabled;

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
