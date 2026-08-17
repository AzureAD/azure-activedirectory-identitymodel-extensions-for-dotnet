// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// An opaque context used to store work when working with authentication artifacts.
    /// </summary>
    public class CallContext : LoggerContext
    {
        // Structured, PII-aware log entries captured by the result-based validation pipeline (issue #3455).
        // Validators do not emit directly; they record here and the handler drains and emits (single engine
        // seam for the LoggerMessage migration, #3361). Lazily created so the common no-log path allocates nothing.
        private List<CapturedLogEntry>? _capturedLogEntries;

        /// <summary>
        /// Instantiates a new <see cref="CallContext"/> with a default activity identifier.
        /// </summary>
        public CallContext() : base()
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="CallContext"/> with an activity identifier.
        /// </summary>
        public CallContext(Guid activityId) : base(activityId)
        {
        }

        /// <summary>
        /// Gets the structured log entries recorded during validation, in the order they were recorded.
        /// Empty unless a validator recorded an entry via <see cref="AddLog(EventLogLevel, MessageDetail)"/>.
        /// </summary>
        /// <remarks>
        /// This is the informational-log analog of the failure-path <see cref="ValidationError"/>: the
        /// result-based validators are side-effect free and record here instead of calling the logger
        /// directly, so the handler can emit them once, in the right place, respecting PII.
        /// </remarks>
        public IReadOnlyList<CapturedLogEntry> CapturedLogEntries => (IReadOnlyList<CapturedLogEntry>?)_capturedLogEntries ?? Array.Empty<CapturedLogEntry>();

        /// <summary>
        /// Records a structured, PII-aware informational log entry on the context.
        /// </summary>
        /// <param name="level">The <see cref="EventLogLevel"/> the entry should be emitted at.</param>
        /// <param name="messageDetail">The lazily-formatted, PII-aware message.</param>
        /// <remarks>
        /// Call sites should guard with <see cref="LogHelper.IsEnabled(EventLogLevel)"/> so the
        /// <see cref="MessageDetail"/> is not allocated when the target level is disabled.
        /// </remarks>
        public void AddLog(EventLogLevel level, MessageDetail messageDetail)
        {
            if (messageDetail is null)
                throw LogHelper.LogArgumentNullException(nameof(messageDetail));

            (_capturedLogEntries ??= new List<CapturedLogEntry>()).Add(new CapturedLogEntry(level, messageDetail));
        }

        /// <summary>
        /// Emits every captured log entry whose level is enabled through <see cref="LogHelper"/>, then clears
        /// the buffer. When <see cref="LoggerContext.CaptureLogs"/> is set, the human-readable message is also
        /// retained in <see cref="LoggerContext.Logs"/> for post-hoc inspection.
        /// </summary>
        /// <remarks>
        /// Called once by the handler at the end of validation (issue #3455). Emitting here — rather than from
        /// each validator — keeps the result-based validators side-effect free and gives a single seam for the
        /// LoggerMessage/ILogger migration (#3361). The <see cref="MessageDetail"/> already applied
        /// <c>MarkAsNonPII</c> at capture time, so the materialized message is wrapped as non-PII to avoid the
        /// logger re-scrubbing the whole line.
        /// </remarks>
        internal void EmitCapturedLogs()
        {
            if (_capturedLogEntries is null || _capturedLogEntries.Count == 0)
                return;

            for (int i = 0; i < _capturedLogEntries.Count; i++)
            {
                CapturedLogEntry entry = _capturedLogEntries[i];
                if (!LogHelper.IsEnabled(entry.Level))
                    continue;

                string message = entry.MessageDetail.Message;

                switch (entry.Level)
                {
                    case EventLogLevel.Verbose:
                        LogHelper.LogVerbose("{0}", LogHelper.MarkAsNonPII(message));
                        break;
                    case EventLogLevel.Warning:
                        LogHelper.LogWarning("{0}", LogHelper.MarkAsNonPII(message));
                        break;
                    default:
                        LogHelper.LogInformation("{0}", LogHelper.MarkAsNonPII(message));
                        break;
                }
            }

            _capturedLogEntries.Clear();
        }
    }
}
#nullable restore
