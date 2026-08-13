// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;

namespace Microsoft.IdentityModel.Protocols.Configuration;

/// <summary>
/// Defines synchronous event handlers for configuration retrieval and update operations.
/// </summary>
/// <typeparam name="T">The type of configuration.</typeparam>
internal interface IConfigurationEventHandlerSync<T> where T : class
{
    /// <summary>
    /// Called before retrieving configuration from the metadata endpoint.
    /// </summary>
    /// <param name="metadataAddress">The metadata endpoint address.</param>
    /// <param name="cancellationToken">A cancellation token to observe while waiting for the operation to complete.</param>
    /// <returns>
    /// A <see cref="ConfigurationEventHandlerResult{T}"/> if valid and available, or <see cref="ConfigurationEventHandlerResult{T}.NoResult"/> to proceed with normal retrieval.
    /// </returns>
    ConfigurationEventHandlerResult<T> BeforeRetrieve(string metadataAddress, CancellationToken cancellationToken = default);

    /// <summary>
    /// Called after a configuration has been successfully retrieved.
    /// </summary>
    /// <param name="metadataAddress">The metadata endpoint address.</param>
    /// <param name="configuration">The retrieved configuration.</param>
    /// <param name="cancellationToken">A cancellation token to observe while the operation completes.</param>
    void AfterUpdate(string metadataAddress, T configuration, CancellationToken cancellationToken = default);
}
