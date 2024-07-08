using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// Interface that defines a model for retrieving configuration data.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public interface IDistributedConfigurationManager<T> where T : class
    {
        /// <summary>
        /// Retrieve the current configuration, refreshing and/or caching as needed.
        /// This method will throw if the configuration cannot be retrieved, instead of returning null.
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task<T> GetConfigurationAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Store the configuration into the distributed cache.
        /// </summary>
        /// <param name="configuration"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task SetConfigurationAsync(T configuration, CancellationToken cancellationToken = default);
    }
}
