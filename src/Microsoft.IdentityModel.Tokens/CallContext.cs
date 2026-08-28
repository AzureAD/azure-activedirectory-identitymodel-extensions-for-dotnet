// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens;

/// <summary>
/// An opaque context used to store work when working with authentication artifacts.
/// </summary>
public class CallContext : LoggerContext
{
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
    /// Instantiates a new <see cref="CallContext"/> with an activity identifier.
    /// </summary>
    /// <param name="logger"><see cref="ILogger"/> to record logs.</param>
    /// <param name="activityId">Activity Id to include in logs.</param>
    /// <exception cref="ArgumentNullException">if <paramref name="logger"/> is null.</exception>
    [CLSCompliant(false)]
    public CallContext(ILogger logger, Guid activityId) : base(logger, activityId)
    {
    }

    /// <summary>
    /// Instantiates a new <see cref="CallContext"/> with a Correlation Id.
    /// </summary>
    /// <param name="logger"><see cref="ILogger"/> to record logs.</param>
    /// <param name="correlationId">Correlation Id to include in logs.</param>
    /// <exception cref="ArgumentNullException">if <paramref name="logger"/> is null.</exception>
    [CLSCompliant(false)]
    public CallContext(ILogger logger, string correlationId) : base(logger, correlationId)
    {
    }

    /// <summary>
    /// Instantiates a new <see cref="CallContext"/> with a logger.
    /// </summary>
    /// <param name="logger"><see cref="ILogger"/> to record logs.</param>
    /// <exception cref="ArgumentNullException">if <paramref name="logger"/> is null.</exception>
    [CLSCompliant(false)]
    public CallContext(ILogger logger) : base(logger)
    {
    }
}
