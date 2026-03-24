// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// Represents a configuration retrieval result.
    /// </summary>
    /// <typeparam name="T">The type of configuration.</typeparam>
    public class ConfigurationEventHandlerResult<T> where T : class
    {
        /// <summary>
        /// Represents a result indicating that configuration retrieval should proceed normally, with no result provided from the event handler.
        /// </summary>
        public static readonly ConfigurationEventHandlerResult<T> NoResult = new();

        /// <summary>
        /// Represents a result indicating that the configuration manager's cache should be bypassed and configuration should be retrieved fresh from the metadata endpoint.
        /// </summary>
        /// <remarks>
        /// Return this from <see cref="IConfigurationEventHandler{T}.BeforeRetrieveAsync"/> to force the manager to skip its current cached value
        /// and initiate a fresh retrieval from the metadata endpoint.
        /// </remarks>
        public static readonly ConfigurationEventHandlerResult<T> BypassCacheResult = new(bypassCache: true);

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationEventHandlerResult{T}"/> class with no result.
        /// </summary>
        private ConfigurationEventHandlerResult()
        {
            Configuration = null;
            RetrievalTime = DateTimeOffset.MinValue;
            BypassCache = false;
        }

        private ConfigurationEventHandlerResult(bool bypassCache)
        {
            Configuration = null;
            RetrievalTime = DateTimeOffset.MinValue;
            BypassCache = bypassCache;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationEventHandlerResult{T}"/> class.
        /// </summary>
        /// <param name="configuration">The configuration retrieved.</param>
        /// <param name="retrievalTime"> The time when the configuration was originally retrieved (UTC).</param>
        /// <remarks>
        /// Setting a <paramref name="configuration"/> on the <see cref="ConfigurationEventHandlerResult{T}"/> skips the existing
        /// configuration retrieval process and sets <paramref name="configuration"/> as a current valid configuration.
        /// </remarks>
        public ConfigurationEventHandlerResult(T configuration, DateTimeOffset retrievalTime)
        {
            Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            RetrievalTime = retrievalTime;
        }

        /// <summary>
        /// Gets or sets the configuration.
        /// </summary>
        public T Configuration { get; }

        /// <summary>
        /// Gets or sets the time when the configuration was originally retrieved in UTC.
        /// </summary>
        /// <remarks>
        /// This property will be set to <see cref="DateTimeOffset.MinValue"/> for <see cref="NoResult"/> and <see cref="BypassCacheResult"/>.
        /// </remarks>
        public DateTimeOffset RetrievalTime { get; }

        /// <summary>
        /// Gets a value indicating whether the configuration manager's cache should be bypassed.
        /// </summary>
        /// <remarks>
        /// When <see langword="true"/>, the manager ignores its currently cached value and initiates a fresh retrieval
        /// from the metadata endpoint. This property is <see langword="true"/> only for <see cref="BypassCacheResult"/>.
        /// </remarks>
        public bool BypassCache { get; }
    }
}
