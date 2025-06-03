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
        /// Gets the <see cref="ILogger"/> that will be used to log messages.
        /// </summary>
        public ILogger Logger { get; }

#pragma warning restore CS3001 // ILogger is not CLSCompliant
#pragma warning restore CS3003 // ILogger is not CLSCompliant

        /// <summary>
        /// Gets or set a <see cref="string"/> that will be logged.
        /// </summary>
        /// <remarks><see cref="CorrelationId"/> will take precedence over <see cref="ActivityId"/> when logging using ILogger.</remarks>
        public string CorrelationId { get; set; }

        /// <summary>
        /// Gets or set a <see cref="Guid"/> that will be used in the call to EventSource.SetCurrentThreadActivityId before logging.
        /// </summary>
        /// <remarks><see cref="CorrelationId"/> will take precedence over <see cref="ActivityId"/> when logging using ILogger.</remarks>
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
    }
}
