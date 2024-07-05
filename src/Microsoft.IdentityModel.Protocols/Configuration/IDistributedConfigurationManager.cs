using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    internal interface IDistributedConfigurationManager<T> where T : class
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task<T> GetConfigurationAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task SetConfigurationAsync(CancellationToken cancellationToken = default);
    }
}
