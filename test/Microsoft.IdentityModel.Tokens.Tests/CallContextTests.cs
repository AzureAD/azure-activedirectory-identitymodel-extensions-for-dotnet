// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
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
    [Collection("LogHelper.Logger Tests")]
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

        [Theory]
        [InlineData(EventLogLevel.LogAlways)]
        [InlineData(EventLogLevel.Critical)]
        [InlineData(EventLogLevel.Error)]
        public void AddLog_NonInformationalLevel_Throws(EventLogLevel level)
        {
            var context = new CallContext();

            // Failure-severity levels belong on the ValidationError path; the capture channel is informational.
            Assert.Throws<ArgumentOutOfRangeException>(() => context.AddLog(level, new MessageDetail("IDX99999: value.")));
        }

        [Fact]
        public void CreateClaimsIdentity_NullCallContext_Throws()
        {
            var validationParameters = new ValidationParameters();

            // CreateClaimsIdentity is a public boundary; callContext is a required (non-null) argument.
            Assert.Throws<ArgumentNullException>(() => validationParameters.CreateClaimsIdentity(new DerivedSecurityToken(), "issuer", null));
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
        public void EmitCapturedLogs_EmitsEnabledEntriesThenClearsBuffer()
        {
            // Arrange
            EventLevel previousLevel = IdentityModelEventSource.Logger.LogLevel;
            SampleListener listener = SampleListener.CreateLoggerListener(EventLevel.Informational);

            try
            {
                var context = new CallContext();
                context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: emitted."));

                // Act
                context.EmitCapturedLogs();

                // Assert
                Assert.Contains("IDX99999: emitted.", listener.TraceBuffer);
                Assert.Empty(context.CapturedLogEntries);
            }
            finally
            {
                listener.Dispose();
                IdentityModelEventSource.Logger.LogLevel = previousLevel;
            }
        }

        [Fact]
        public void ClearCapturedLogs_DiscardsEntriesWithoutEmitting()
        {
            // Arrange
            EventLevel previousLevel = IdentityModelEventSource.Logger.LogLevel;
            SampleListener listener = SampleListener.CreateLoggerListener(EventLevel.Informational);

            try
            {
                var context = new CallContext();
                context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: discarded."));

                // Act
                context.ClearCapturedLogs();
                context.EmitCapturedLogs();

                // Assert
                Assert.Empty(context.CapturedLogEntries);
                Assert.DoesNotContain("IDX99999: discarded.", listener.TraceBuffer);
            }
            finally
            {
                listener.Dispose();
                IdentityModelEventSource.Logger.LogLevel = previousLevel;
            }
        }

        [Fact]
        public void EmitCapturedLogs_RedactsPii_WhenShowPiiIsOff()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            bool originalShowPii = IdentityModelEventSource.ShowPII;
            var recorder = new RecordingLogger();
            LogHelper.Logger = recorder;
            IdentityModelEventSource.ShowPII = false;

            try
            {
                const string secret = "super-secret-user-value";
                var context = new CallContext();
                // The value is NOT marked NonPII, so it must be redacted end to end (highest-consequence path).
                context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: value is '{0}'.", secret));

                // Act
                context.EmitCapturedLogs();

                // Assert
                string emitted = Assert.Single(recorder.Messages);
                Assert.DoesNotContain(secret, emitted);
                Assert.Contains("hidden", emitted, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
                IdentityModelEventSource.ShowPII = originalShowPii;
            }
        }

        [Fact]
        public void LogEmissionScope_EmitsCapturedLogsOnDispose()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            var recorder = new RecordingLogger();
            LogHelper.Logger = recorder;

            try
            {
                var context = new CallContext();

                // Act
                using (context.BeginLogEmissionScope())
                {
                    context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: scoped."));
                }

                // Assert
                Assert.Contains(recorder.Messages, m => m.Contains("IDX99999: scoped."));
                Assert.Empty(context.CapturedLogEntries);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
            }
        }

        [Fact]
        public void LogEmissionScope_EmitsCapturedLogsWhenBodyThrows()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            var recorder = new RecordingLogger();
            LogHelper.Logger = recorder;

            try
            {
                var context = new CallContext();

                // Act
                Action act = () =>
                {
                    using (context.BeginLogEmissionScope())
                    {
                        context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: scoped-throw."));
                        throw new InvalidOperationException();
                    }
                };

                Assert.Throws<InvalidOperationException>(act);

                // Assert
                Assert.Contains(recorder.Messages, m => m.Contains("IDX99999: scoped-throw."));
                Assert.Empty(context.CapturedLogEntries);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
            }
        }

        [Fact]
        public void LogEmissionScope_NestedScopes_OnlyOutermostEmits_OncePerEntryInOrder()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            var recorder = new RecordingLogger();
            LogHelper.Logger = recorder;

            try
            {
                var context = new CallContext();

                // Act - mirror the handler shape: a string entry point opens the outer scope and captures a
                // log, then calls the SecurityToken overload (inner scope) which captures more, then captures
                // again after the inner scope returns. Only the outermost scope may drain.
                using (context.BeginLogEmissionScope())
                {
                    context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: before-inner."));

                    using (context.BeginLogEmissionScope())
                    {
                        context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: inside-inner."));
                    }

                    // The inner scope disposed but must NOT have emitted anything - the outermost scope owns emission.
                    Assert.Empty(recorder.Messages);

                    context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: after-inner."));
                }

                // Assert - the outermost scope emitted every entry exactly once (three total, no duplicates),
                // in capture order across the inner-scope boundary, then cleared the buffer.
                Assert.Equal(3, recorder.Messages.Count);
                Assert.Contains("before-inner.", recorder.Messages[0]);
                Assert.Contains("inside-inner.", recorder.Messages[1]);
                Assert.Contains("after-inner.", recorder.Messages[2]);
                Assert.Empty(context.CapturedLogEntries);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
            }
        }

        [Fact]
        public void LogEmissionScope_DisposedTwice_DoesNotUnderflowDepthAndLaterScopeStillDrains()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            var recorder = new RecordingLogger();
            LogHelper.Logger = recorder;

            try
            {
                var context = new CallContext();

                // Act - dispose the same (value-type) scope twice, simulating an accidental copy/double
                // dispose. The guarded decrement must not drive the depth below zero.
                var scope = context.BeginLogEmissionScope();
                context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: first."));
                scope.Dispose();
                scope.Dispose();

                // A subsequent scope must still be recognized as the outermost one and drain normally; if the
                // double dispose had underflowed the depth, this scope would compute isOutermost=false and
                // silently skip draining.
                using (context.BeginLogEmissionScope())
                {
                    context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: second."));
                }

                // Assert
                Assert.Contains(recorder.Messages, m => m.Contains("IDX99999: first."));
                Assert.Contains(recorder.Messages, m => m.Contains("IDX99999: second."));
                Assert.Empty(context.CapturedLogEntries);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
            }
        }

        [Fact]
        public void LogEmissionScope_OuterDisposedBeforeInner_DoesNotDrainEarlyAndOutermostDrainsOnce()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            var recorder = new RecordingLogger();
            LogHelper.Logger = recorder;

            try
            {
                var context = new CallContext();

                var outer = context.BeginLogEmissionScope(); // level 1
                context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: outer."));

                var inner = context.BeginLogEmissionScope(); // level 2
                context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: inner."));

                // Act - dispose the OUTER scope out of order, while the inner scope is still the top of the
                // stack. The ownership (level) check makes this a no-op, so it must NOT drain early.
                outer.Dispose();
                Assert.Empty(recorder.Messages);

                // Closing the inner scope pops level 2 but is not the outermost, so still no emission.
                inner.Dispose();
                Assert.Empty(recorder.Messages);

                // Closing the outermost level now drains every captured entry once, in capture order.
                outer.Dispose();

                // Assert
                Assert.Equal(2, recorder.Messages.Count);
                Assert.Contains("outer.", recorder.Messages[0]);
                Assert.Contains("inner.", recorder.Messages[1]);
                Assert.Empty(context.CapturedLogEntries);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
            }
        }

        [Fact]
        public void EmitCapturedLogs_LoggerThrows_DoesNotPropagateAndClearsBuffer()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            LogHelper.Logger = new ThrowingLogger();

            try
            {
                var context = new CallContext();
                context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: entry."));

                // Act + Assert — a throwing sink must not change the (exception-free) validation outcome...
                context.EmitCapturedLogs();

                // ...and the buffer must be cleared so a reused CallContext cannot replay the entry.
                Assert.Empty(context.CapturedLogEntries);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
            }
        }

        [Fact]
        public void EmitCapturedLogs_OneEntryThrows_StillEmitsRemainingAndClearsBuffer()
        {
            // Arrange
            IIdentityLogger originalLogger = LogHelper.Logger;
            var logger = new ThrowOnFirstLogger();
            LogHelper.Logger = logger;

            try
            {
                var context = new CallContext();
                context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: first."));
                context.AddLog(EventLogLevel.Informational, new MessageDetail("IDX99999: second."));

                // Act — emitting the first entry throws; the second must still be emitted (best-effort per entry).
                context.EmitCapturedLogs();

                // Assert
                Assert.Contains(logger.Messages, m => m.Contains("IDX99999: second."));
                Assert.Empty(context.CapturedLogEntries);
            }
            finally
            {
                LogHelper.Logger = originalLogger;
            }
        }

        // Captures emitted messages so tests can assert on the drained/emitted output (including PII redaction).
        private sealed class RecordingLogger : IIdentityLogger
        {
            public List<string> Messages { get; } = new List<string>();

            public bool IsEnabled(EventLogLevel eventLogLevel) => true;

            public void Log(LogEntry entry) => Messages.Add(entry.Message);
        }

        // A logger whose Log throws, to verify emission failures never escape the validation pipeline.
        private sealed class ThrowingLogger : IIdentityLogger
        {
            public bool IsEnabled(EventLogLevel eventLogLevel) => true;

            public void Log(LogEntry entry) => throw new InvalidOperationException("sink failure");
        }

        // A logger that throws on the first Log call and records subsequent ones, to verify per-entry
        // best-effort emission (one failing entry does not skip the rest).
        private sealed class ThrowOnFirstLogger : IIdentityLogger
        {
            private bool _threw;

            public List<string> Messages { get; } = new List<string>();

            public bool IsEnabled(EventLogLevel eventLogLevel) => true;

            public void Log(LogEntry entry)
            {
                if (!_threw)
                {
                    _threw = true;
                    throw new InvalidOperationException("first sink failure");
                }

                Messages.Add(entry.Message);
            }
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
