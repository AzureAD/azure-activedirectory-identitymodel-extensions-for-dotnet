// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// Defines event handlers for configuration retrieval and update operations.
    /// </summary>
    /// <typeparam name="T">The type of configuration.</typeparam>
    public interface IConfigurationEventHandler<T> where T : class
    {
        /// <summary>
        /// Called before retrieving configuration from the metadata endpoint.
        /// </summary>
        /// <param name="metadataAddress">The metadata endpoint address.</param>
        /// <param name="cancellationToken">A cancellation token to observe while waiting for the task to complete.</param>
        /// <returns>A configuration result if available, or null to proceed with normal retrieval.</returns>
        Task<ConfigurationEventHandlerResult<T>> BeforeRetrieveAsync(string metadataAddress, CancellationToken cancellationToken = default);

        /// <summary>
        /// Called after a configuration has been successfully retrieved and updated.
        /// </summary>
        /// <param name="metadataAddress">The metadata endpoint address.</param>
        /// <param name="configuration">The updated configuration.</param>
        /// <param name="cancellationToken">A cancellation token to observe while waiting for the task to complete.</param>
        Task AfterUpdateAsync(string metadataAddress, T configuration, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Represents a configuration retrieval result.
    /// </summary>
    /// <typeparam name="T">The type of configuration.</typeparam>
    public class ConfigurationEventHandlerResult<T> where T : class
    {
        /// <summary>
        /// Instantiates a new instance of the <see cref="ConfigurationEventHandlerResult{T}"/> class with no result.
        /// </summary>
        public static readonly ConfigurationEventHandlerResult<T> NoResult = new ConfigurationEventHandlerResult<T>();

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationEventHandlerResult{T}"/> class with no result.
        /// </summary>
        private ConfigurationEventHandlerResult()
        {
            Configuration = null;
            RetrievalTime = DateTimeOffset.MinValue;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationEventHandlerResult{T}"/> class.
        /// </summary>
        /// <param name="configuration">The configuration retrieved.</param>
        /// <param name="retrievalTime"> The time when the configuration was originally retrieved (UTC).</param>
        /// <exception cref="ArgumentNullException"></exception>
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
        /// Gets or sets the time when the configuration was originally retrieved.
        /// </summary>
        public DateTimeOffset RetrievalTime { get; }
    }
}
