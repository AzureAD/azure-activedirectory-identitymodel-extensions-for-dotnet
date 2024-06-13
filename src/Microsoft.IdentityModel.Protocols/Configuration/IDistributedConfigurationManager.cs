// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// 
    /// </summary>
    // L2 TODO: internal until L2 cache is implemented S2S.
    internal interface IDistributedConfigurationManager<T> where T : class
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="metadataAddress"></param>
        /// <param name="distributedConfigurationOptions"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task<T> GetConfigurationAsync(string metadataAddress, DistributedConfigurationOptions distributedConfigurationOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="metadataAddress"></param>
        /// <param name="configuration"></param>
        /// <param name="distributedConfigurationOptions"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task SetConfigurationAsync(string metadataAddress, T configuration, DistributedConfigurationOptions distributedConfigurationOptions, CancellationToken cancellationToken = default);
    }
}
