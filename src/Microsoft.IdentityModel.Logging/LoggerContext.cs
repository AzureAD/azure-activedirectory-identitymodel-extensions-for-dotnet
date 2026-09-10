// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Microsoft.Extensions.Logging;

namespace Microsoft.IdentityModel.Logging
{
    /// <summary>
    /// A context class that can be used to store work per request to aid with debugging.
    /// </summary>
    /// <remarks>
    /// A <see cref="LoggerContext"/> represents a single logical call and is not thread-safe. Its mutable
    /// properties must not be written on one thread while it is being used to log on another.
    /// </remarks>
    public class LoggerContext
    {
        /// <summary>
        /// Instantiates a new <see cref="LoggerContext"/> with the default activityId.
        /// </summary>
        public LoggerContext()
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="LoggerContext"/> with an activityId.
        /// </summary>
        /// <param name="activityId"></param>
        public LoggerContext(Guid activityId)
        {
            ActivityId = activityId;
        }

#pragma warning disable CS3001 // ILogger is not CLSCompliant
#pragma warning disable CS3003 // ILogger is not CLSCompliant
        /// <summary>
        /// Instantiates a new <see cref="LoggerContext"/>.
        /// </summary>
        /// <param name="logger"><see cref="ILogger"/> to record logs.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="logger"/> is null.</exception>
        public LoggerContext(ILogger logger)
        {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Instantiates a new <see cref="LoggerContext"/> with an activity identifier.
        /// </summary>
        /// <param name="logger"><see cref="ILogger"/> to record logs.</param>
        /// <param name="activityId">activity id to include in logs.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="logger"/> is null.</exception>
        public LoggerContext(ILogger logger, Guid activityId)
        {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            ActivityId = activityId;
        }

        /// <summary>
        /// Instantiates a new <see cref="LoggerContext"/> with a correlation identifier.
        /// </summary>
        /// <param name="logger"><see cref="ILogger"/> to record logs.</param>
        /// <param name="correlationId">correlation id to include in logs.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="logger"/> is null.</exception>
        public LoggerContext(ILogger logger, string correlationId)
        {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            CorrelationId = correlationId;
        }

        /// <summary>
        /// Instantiates a new <see cref="LoggerContext"/> by copying the logging state (logger, correlation id,
        /// <see cref="LogCorrelationId"/>, activity id, and <see cref="CaptureLogs"/>) from another context.
        /// The mutable <see cref="Logs"/> buffer and <see cref="PropertyBag"/> are intentionally not shared so a
        /// derived or nested context does not cross-contaminate the originating context.
        /// </summary>
        /// <param name="other">The context to copy logging state from.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="other"/> is null.</exception>
        protected LoggerContext(LoggerContext other)
        {
            if (other is null)
                throw new ArgumentNullException(nameof(other));

            Logger = other.Logger;
            CorrelationId = other.CorrelationId;
            LogCorrelationId = other.LogCorrelationId;
            ActivityId = other.ActivityId;
            CaptureLogs = other.CaptureLogs;
        }

        /// <summary>
        /// Gets the <see cref="ILogger"/> that will be used to log messages.
        /// </summary>
        public ILogger Logger { get; }

#pragma warning restore CS3001 // ILogger is not CLSCompliant
#pragma warning restore CS3003 // ILogger is not CLSCompliant

        /// <summary>
        /// Gets or sets an optional caller-supplied correlation id that can be added to an <see cref="ILogger"/> scope
        /// by calling <see cref="BeginCorrelationScope"/>.
        /// </summary>
        /// <remarks>Only this explicitly supplied value is logged; <see cref="ActivityId"/> is never promoted into ILogger messages.
        /// It is treated as a non-PII correlation token and is emitted verbatim, so callers must not place PII in it.</remarks>
        public string CorrelationId { get; set; }

        /// <summary>
        /// Gets or sets a boolean that controls whether <see cref="BeginCorrelationScope"/> includes
        /// <see cref="CorrelationId"/> in an <see cref="ILogger"/> scope.
        /// Defaults to <see langword="true"/>. Set to <see langword="false"/> to suppress the correlation scope.
        /// </summary>
        /// <remarks>This flag gates only the explicitly supplied <see cref="CorrelationId"/> string. It has no effect on <see cref="ActivityId"/>.</remarks>
        public bool LogCorrelationId { get; set; } = true;

        /// <summary>
        /// Begins an <see cref="ILogger"/> scope containing the explicitly supplied <see cref="CorrelationId"/>.
        /// </summary>
        /// <returns>
        /// The scope returned by <see cref="ILogger.BeginScope{TState}(TState)"/>, or a no-op scope when no logger
        /// or correlation id was supplied, or when <see cref="LogCorrelationId"/> is <see langword="false"/>.
        /// </returns>
        /// <remarks>
        /// Call this once at the operation boundary so all logs emitted during the operation, including
        /// source-generated LoggerMessage events, inherit the same structured correlation metadata.
        /// </remarks>
        public IDisposable BeginCorrelationScope()
        {
            if (Logger is null || !LogCorrelationId || string.IsNullOrEmpty(CorrelationId))
                return NullScope.Instance;

            return Logger.BeginScope("CorrelationId: {CorrelationId}", CorrelationId) ?? NullScope.Instance;
        }

        /// <summary>
        /// Gets or set a <see cref="Guid"/> that will be used in the call to EventSource.SetCurrentThreadActivityId before logging.
        /// </summary>
        /// <remarks><see cref="ActivityId"/> is used only for EventSource/ETW correlation and is not written to <see cref="ILogger"/> messages.</remarks>
        public Guid ActivityId { get; set; } = Guid.Empty;

        /// <summary>
        /// Gets or sets a boolean controlling if logs are written into the context.
        /// Useful when debugging.
        /// </summary>
        public bool CaptureLogs { get; set; }

        /// <summary>
        /// Gets or sets a string that helps with setting breakpoints when debugging.
        /// </summary>
        public virtual string DebugId { get; set; } = string.Empty;

        /// <summary>
        /// The collection of logs associated with a request. Use <see cref="CaptureLogs"/> to control capture.
        /// </summary>
        public ICollection<string> Logs { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets or sets an <see cref="IDictionary{String, Object}"/> that enables custom extensibility scenarios.
        /// </summary>
        public IDictionary<string, object> PropertyBag { get; set; }

        private sealed class NullScope : IDisposable
        {
            internal static readonly NullScope Instance = new NullScope();

            public void Dispose()
            {
            }
        }
    }
}
