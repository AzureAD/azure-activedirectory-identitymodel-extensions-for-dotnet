// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class CallContextTests
    {
        [Theory, MemberData(nameof(CallContextTestTheoryData), DisableDiscoveryEnumeration = true)]
        public void LoggerInstanceTests(CallContextTheoryData theoryData)
        {
            var context = new CallContext(theoryData.ActivityId) { DebugId = theoryData.TestId };

            Assert.IsAssignableFrom<LoggerContext>(context);
            Assert.Equal(theoryData.TestId, context.DebugId);
            Assert.Equal(theoryData.ActivityId, context.ActivityId);
            Assert.False(context.CaptureLogs);
            Assert.Empty(context.Logs);
            Assert.Null(context.PropertyBag);
            Assert.Same(NullLogger.Instance, context.GetLogger());
        }

        [Fact]
        public void LoggerConstructorSetsLogger()
        {
            // Arrange
            ILogger logger = new TestLogger();
            Guid activityId = Guid.NewGuid();

            // Act
            var context = new CallContext(logger, activityId);

            // Assert
            Assert.Same(logger, context.GetLogger());
            Assert.Equal(activityId, context.ActivityId);
        }

        [Fact]
        public void LoggerConstructorRejectsNull()
        {
            // Arrange, Act and Assert
            Assert.Throws<ArgumentNullException>(() => new CallContext((ILogger)null));
        }

        public static TheoryData<CallContextTheoryData> CallContextTestTheoryData
        {
            get
            {
                var theoryData = new TheoryData<CallContextTheoryData>();

                theoryData.Add(new CallContextTheoryData
                {
                    TestId = "abdc",
                    ActivityId = new Guid()
                });

                return theoryData;
            }
        }
    }

    public class CallContextTheoryData : TheoryDataBase
    {
        public Guid ActivityId;
    }

    internal sealed class TestLogger : ILogger
    {
        public IDisposable BeginScope<TState>(TState state) => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception exception,
            Func<TState, Exception, string> formatter)
        {
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
