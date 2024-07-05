using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols
{
    internal interface IDistributedConfigurationManager<T> where T : class
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="metadataAddress"></param>
        /// <param name="distributedConfigurationOptions"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task<T> GetConfigurationAsync(
            string metadataAddress,
            DistributedConfigurationOptions distributedConfigurationOptions,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="metadataAddress"></param>
        /// <param name="configuration"></param>
        /// <param name="distributedConfigurationOptions"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task SetConfigurationAsync(
            string metadataAddress,
            T configuration,
            DistributedConfigurationOptions distributedConfigurationOptions,
            CancellationToken cancellationToken = default);
    }
}
