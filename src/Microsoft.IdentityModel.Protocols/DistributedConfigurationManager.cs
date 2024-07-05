using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.Configuration;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// 
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class DistributedConfigurationManager<T> : IDistributedConfigurationManager<T> where T : class
    {
        private readonly IDistributedCache _cache;
        private readonly IDistributedConfigurationRetriever<T> _retriever;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="metadataAddress"></param>
        /// <param name="distributedConfigurationOptions"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public async Task<T> GetConfigurationAsync(string metadataAddress, DistributedConfigurationOptions distributedConfigurationOptions, CancellationToken cancellationToken = default)
        {
            if (metadataAddress == null)
            {
                throw new ArgumentNullException(nameof(metadataAddress));
            }

            if (distributedConfigurationOptions == null)
            {
                throw new ArgumentNullException(nameof(distributedConfigurationOptions));
            }

            T configuration = await _cache.GetAsync<T>(metadataAddress, cancellationToken).ConfigureAwait(false);
            if (configuration == null)
            {
                configuration = await _retriever.GetConfigurationAsync(metadataAddress, distributedConfigurationOptions, cancellationToken).ConfigureAwait(false);
                await _cache.SetAsync(metadataAddress, configuration, distributedConfigurationOptions, cancellationToken).ConfigureAwait(false);
            }

            return configuration;
        }

        public async Task SetConfigurationAsync(string metadataAddress, T configuration, DistributedConfigurationOptions distributedConfigurationOptions, CancellationToken cancellationToken = default)
        {
            if (metadataAddress == null)
            {
                throw new ArgumentNullException(nameof(metadataAddress));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            if (distributedConfigurationOptions == null)
            {
                throw new ArgumentNullException(nameof(distributedConfigurationOptions));
            }

            await _cache.SetAsync(metadataAddress, configuration, distributedConfigurationOptions, cancellationToken).ConfigureAwait(false);
        }
    }
}
