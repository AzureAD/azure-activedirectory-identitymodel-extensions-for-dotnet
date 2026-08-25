// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// An opaque context used to store work when working with authentication artifacts.
    /// </summary>
    public class CallContext : LoggerContext
    {
        private readonly ILogger _logger = NullLogger.Instance;

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
        /// Instantiates a new <see cref="CallContext"/> with a logger.
        /// </summary>
        /// <param name="logger">The logger to use for this call.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="logger"/> is null.</exception>
        [CLSCompliant(false)]
        public CallContext(ILogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Instantiates a new <see cref="CallContext"/> with a logger and activity identifier.
        /// </summary>
        /// <param name="logger">The logger to use for this call.</param>
        /// <param name="activityId">The activity identifier to use for this call.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="logger"/> is null.</exception>
        [CLSCompliant(false)]
        public CallContext(ILogger logger, Guid activityId)
            : base(activityId)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        internal ILogger Logger => _logger;
    }
}
