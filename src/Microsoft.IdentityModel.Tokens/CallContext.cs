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

        // Nesting level for LogEmissionScope (issue #3455). A string entry point opens a scope and then
        // calls the SecurityToken overload, which opens a second scope on the same CallContext. Each scope
        // captures the depth after it is pushed and, on dispose, acts only when it is still the current top
        // of the stack - so only the outermost scope (level 1) drains, every captured entry is emitted
        // exactly once at the outermost boundary in capture order, and double/out-of-order disposal of a
        // copied value-type scope is a harmless no-op. Not synchronized: a CallContext represents a single
        // logical (single-threaded) call.
        private int _logEmissionScopeDepth;

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
        /// directly, so the handler can emit them once, in the right place, respecting PII. Exposed as
        /// internal because only the handler drains the buffer; callers observe the emitted logs, not this list.
        /// </remarks>
        internal IReadOnlyList<CapturedLogEntry> CapturedLogEntries => (IReadOnlyList<CapturedLogEntry>?)_capturedLogEntries ?? Array.Empty<CapturedLogEntry>();

        /// <summary>
        /// Records a structured, PII-aware informational log entry on the context.
        /// </summary>
        /// <param name="level">The <see cref="EventLogLevel"/> the entry should be emitted at.</param>
        /// <param name="messageDetail">The lazily-formatted, PII-aware message.</param>
        /// <remarks>
        /// This is an informational capture channel: only <see cref="EventLogLevel.Informational"/>,
        /// <see cref="EventLogLevel.Verbose"/>, and <see cref="EventLogLevel.Warning"/> are accepted —
        /// failure-severity levels belong on the <see cref="ValidationError"/> path, not here. Call sites
        /// should guard with <see cref="LogHelper.IsEnabled(EventLogLevel)"/> so the <see cref="MessageDetail"/>
        /// is not allocated when the target level is disabled. A <see cref="CallContext"/> represents a single
        /// logical validation call and its captured-log buffer is not synchronized; it must not be recorded to
        /// or drained from multiple threads concurrently.
        /// </remarks>
        internal void AddLog(EventLogLevel level, MessageDetail messageDetail)
        {
            if (messageDetail is null)
                throw LogHelper.LogArgumentNullException(nameof(messageDetail));

            if (level is not (EventLogLevel.Informational or EventLogLevel.Verbose or EventLogLevel.Warning))
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(
                    nameof(level),
                    level,
                    "Only Informational, Verbose, and Warning levels can be captured on the CallContext; failures use ValidationError."));

            (_capturedLogEntries ??= new List<CapturedLogEntry>()).Add(new CapturedLogEntry(level, messageDetail));
        }

        /// <summary>
        /// Emits every captured log entry whose level is enabled through <see cref="LogHelper"/>, then clears
        /// the buffer.
        /// </summary>
        /// <remarks>
        /// Called once by the handler at the end of validation (issue #3455). Emitting here — rather than from
        /// each validator — keeps the result-based validators side-effect free and gives a single seam for the
        /// LoggerMessage/ILogger migration (#3361). The <see cref="MessageDetail"/> already applied
        /// <c>MarkAsNonPII</c> to its non-sensitive arguments at capture time and redacts unmarked arguments
        /// when PII display is off, so wrapping the materialized message as non-PII here does not expose PII.
        /// Passing structured parameters through to the sink (rather than a rendered string) is tracked by #3361.
        /// </remarks>
        internal void EmitCapturedLogs()
        {
            if (_capturedLogEntries is null || _capturedLogEntries.Count == 0)
                return;

            try
            {
                for (int i = 0; i < _capturedLogEntries.Count; i++)
                {
                    // Emit each entry independently: a failure formatting or emitting one entry is best-effort
                    // and must neither skip the remaining entries nor change the (exception-free) validation
                    // outcome, so a throwing sink or IIdentityLogger is swallowed here.
                    try
                    {
                        CapturedLogEntry entry = _capturedLogEntries[i];
                        if (!LogHelper.IsEnabled(entry.Level))
                            continue;

                        string message = entry.MessageDetail.Message;

                        // AddLog restricts entries to Informational/Verbose/Warning, so no higher-severity level
                        // can be silently emitted at Informational here.
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
#pragma warning disable CA1031 // Do not catch general exception types
                    catch
#pragma warning restore CA1031 // Do not catch general exception types
                    {
                    }
                }
            }
            finally
            {
                // Always clear so a reused CallContext cannot replay these entries, even if emission threw.
                _capturedLogEntries.Clear();
            }
        }

        /// <summary>
        /// Discards every captured log entry without emitting them. Used by the handler to drop the
        /// informational logs of a validation attempt that was superseded by a retry (issue #3455).
        /// The buffer only ever holds the in-flight validation's entries — it is drained (and cleared) at the
        /// end of every validation and the lazy claims-creation path uses its own CallContext — so clearing
        /// the whole buffer here cannot discard entries belonging to a different operation.
        /// </summary>
        internal void ClearCapturedLogs() => _capturedLogEntries?.Clear();

        /// <summary>
        /// Begins a scope that emits the captured logs (via <see cref="EmitCapturedLogs"/>) when disposed.
        /// Use with a <c>using</c> declaration at the top of a validation method so the buffer is drained on
        /// every exit path — success, failure, or exception — without introducing an extra async state
        /// machine (issue #3455). Scopes are re-entrant: when a string entry point opens a scope and then
        /// calls the <see cref="SecurityToken"/> overload (which opens another scope on the same context),
        /// only the outermost scope drains, so every entry is emitted exactly once and in capture order.
        /// </summary>
        /// <remarks>
        /// Invariant: <c>_logEmissionScopeDepth</c> is the count of open scopes; each scope owns the level it
        /// was pushed at and only the top-of-stack scope may pop (so double/out-of-order disposal is a no-op),
        /// and the outermost scope (level 1) is the single owner of draining. A <see cref="CallContext"/> is a
        /// single logical (single-threaded) call, so the counter needs no synchronization.
        /// </remarks>
        internal LogEmissionScope BeginLogEmissionScope()
        {
            // Capture the level (depth after this scope is pushed) as an ownership token; Dispose acts only
            // when this scope is still the current top of the stack.
            return new LogEmissionScope(this, ++_logEmissionScopeDepth);
        }

        /// <summary>
        /// A disposable scope that drains the <see cref="CallContext"/> captured logs on <see cref="Dispose"/>,
        /// but only when it is the outermost scope on the context; nested scopes emit nothing.
        /// </summary>
        internal readonly struct LogEmissionScope : IDisposable
        {
            private readonly CallContext _callContext;
            private readonly int _level;

            internal LogEmissionScope(CallContext callContext, int level)
            {
                _callContext = callContext;
                _level = level;
            }

            /// <summary>
            /// Closes the scope. Acts only when this scope is the current top of the nesting stack, so a
            /// double or out-of-order dispose of a copied value-type scope is a harmless no-op. Emits the
            /// captured logs only when this is the outermost scope (level 1), so nested string/SecurityToken
            /// validation drains every entry exactly once, in capture order, at the outermost boundary.
            /// </summary>
            public void Dispose()
            {
                // Ownership check: only the current top-of-stack scope may pop. A stale copy (already popped,
                // or disposed out of order while an inner scope is still active) sees a mismatched depth and
                // no-ops - it neither corrupts the depth nor drains early.
                if (_callContext._logEmissionScopeDepth != _level)
                    return;

                _callContext._logEmissionScopeDepth--;

                if (_level == 1)
                    _callContext.EmitCapturedLogs();
            }
        }
    }
}
#nullable restore
