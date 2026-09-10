// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
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
        }

        [Fact]
        public void LoggerConstructors_SetLoggingState()
        {
            // Arrange
            var logger = NullLogger.Instance;
            var activityId = Guid.NewGuid();

            // Act
            var loggerContext = new CallContext(logger);
            var activityContext = new CallContext(logger, activityId);
            var correlationContext = new CallContext(logger, "correlation-id");

            // Assert
            Assert.Same(logger, loggerContext.Logger);
            Assert.Same(logger, activityContext.Logger);
            Assert.Equal(activityId, activityContext.ActivityId);
            Assert.Same(logger, correlationContext.Logger);
            Assert.Equal("correlation-id", correlationContext.CorrelationId);
        }

        [Fact]
        public void LoggerConstructors_Throw_WhenLoggerIsNull()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new CallContext(null));
            Assert.Throws<ArgumentNullException>(() => new CallContext(null, Guid.NewGuid()));
            Assert.Throws<ArgumentNullException>(() => new CallContext(null, "correlation-id"));
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
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
