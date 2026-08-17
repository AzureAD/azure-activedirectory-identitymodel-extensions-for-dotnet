// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics.Tracing;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;
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

        // Issue #3455: structured, PII-aware log capture on CallContext.

        [Fact]
        public void CapturedLogEntries_IsEmptyByDefault()
        {
            var context = new CallContext();

            Assert.NotNull(context.CapturedLogEntries);
            Assert.Empty(context.CapturedLogEntries);
        }

        [Fact]
        public void AddLog_CapturesLevelAndMessageDetail()
        {
            var context = new CallContext();
            var detail = new MessageDetail("IDX99999: value is '{0}'.", LogHelper.MarkAsNonPII("abc"));

            context.AddLog(EventLogLevel.Informational, detail);

            CapturedLogEntry entry = Assert.Single(context.CapturedLogEntries);
            Assert.Equal(EventLogLevel.Informational, entry.Level);
            Assert.Same(detail, entry.MessageDetail);
            Assert.Equal("IDX99999: value is 'abc'.", entry.MessageDetail.Message);
        }

        [Fact]
        public void AddLog_PreservesOrderAndLevels()
        {
            var context = new CallContext();

            context.AddLog(EventLogLevel.Informational, new MessageDetail("first"));
            context.AddLog(EventLogLevel.Verbose, new MessageDetail("second"));
            context.AddLog(EventLogLevel.Warning, new MessageDetail("third"));

            var entries = context.CapturedLogEntries.ToList();
            Assert.Equal(3, entries.Count);
            Assert.Equal(new[] { "first", "second", "third" }, entries.Select(e => e.MessageDetail.Message));
            Assert.Equal(
                new[] { EventLogLevel.Informational, EventLogLevel.Verbose, EventLogLevel.Warning },
                entries.Select(e => e.Level));
        }

        [Fact]
        public void AddLog_NullMessageDetail_Throws()
        {
            var context = new CallContext();

            Assert.Throws<ArgumentNullException>(() => context.AddLog(EventLogLevel.Informational, null));
        }

        [Fact]
        public void CreateClaimsIdentity_RecordsInformationalLog_OnCallContext()
        {
            // Arrange
            EventLevel previousLevel = IdentityModelEventSource.Logger.LogLevel;
            SampleListener listener = SampleListener.CreateLoggerListener(EventLevel.Informational);

            try
            {
                var validationParameters = new ValidationParameters();
                var callContext = new CallContext();

                // Act
                ClaimsIdentity identity = validationParameters.CreateClaimsIdentity(new DerivedSecurityToken(), "issuer", callContext);

                // Assert
                Assert.NotNull(identity);
                CapturedLogEntry entry = Assert.Single(callContext.CapturedLogEntries);
                Assert.Equal(EventLogLevel.Informational, entry.Level);
                Assert.StartsWith("IDX10245:", entry.MessageDetail.Message);
            }
            finally
            {
                listener.Dispose();
                IdentityModelEventSource.Logger.LogLevel = previousLevel;
            }
        }

        [Fact]
        public void CreateClaimsIdentity_NullCallContext_DoesNotThrow()
        {
            // Arrange
            var validationParameters = new ValidationParameters();

            // Act
            ClaimsIdentity identity = validationParameters.CreateClaimsIdentity(new DerivedSecurityToken(), "issuer", null);

            // Assert
            Assert.NotNull(identity);
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
