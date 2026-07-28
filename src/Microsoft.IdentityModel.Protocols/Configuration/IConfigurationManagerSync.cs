// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Interface that defines a synchronous model for retrieving configuration data.
    /// </summary>
    /// <typeparam name="T">The type of the configuration metadata.</typeparam>
    public interface IConfigurationManagerSync<T> where T : class
    {
        /// <summary>
        /// Retrieve the current configuration, refreshing and/or caching as needed.
        /// This method will throw if the configuration cannot be retrieved, instead of returning null.
        /// </summary>
        /// <param name="cancel"><see cref="CancellationToken"/></param>
        /// <returns>Configuration of type T.</returns>
        T GetConfigurationSync(CancellationToken cancel);

        /// <summary>
        /// Indicate that the configuration may be stale (as indicated by failing to process incoming tokens).
        /// </summary>
        void RequestRefresh();
    }
}
