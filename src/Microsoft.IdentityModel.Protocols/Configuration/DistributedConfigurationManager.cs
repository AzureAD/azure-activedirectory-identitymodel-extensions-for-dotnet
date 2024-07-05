using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// 
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class DistributedConfigurationManager<T> :
        BaseConfigurationManager,
        IConfigurationManager<T>,
        IDistributedConfigurationManager<T> where T : class
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="cancel"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public Task<T> GetConfigurationAsync(CancellationToken cancel) => throw new NotImplementedException();

        /// <summary>
        /// 
        /// </summary>
        /// <exception cref="NotImplementedException"></exception>
        public override void RequestRefresh() => throw new NotImplementedException();

        /// <summary>
        /// 
        /// </summary>
        /// <param name="metadataAddress"></param>
        /// <param name="distributedConfigurationOptions"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        Task<T> IDistributedConfigurationManager<T>.GetConfigurationAsync(
            string metadataAddress,
            DistributedConfigurationOptions distributedConfigurationOptions,
            CancellationToken cancellationToken) => throw new NotImplementedException();

        /// <summary>
        /// 
        /// </summary>
        /// <param name="metadataAddress"></param>
        /// <param name="configuration"></param>
        /// <param name="distributedConfigurationOptions"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        Task IDistributedConfigurationManager<T>.SetConfigurationAsync(
            string metadataAddress,
            T configuration,
            DistributedConfigurationOptions distributedConfigurationOptions,
            CancellationToken cancellationToken) => throw new NotImplementedException();
    }
}
