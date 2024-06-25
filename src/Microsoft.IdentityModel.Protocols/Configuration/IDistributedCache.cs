using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// 
    /// </summary>
    public interface IDistributedCache
    {
        /// <summary>
        /// Retrieves the string value associated with the specified key from the distributed cache asynchronously.
        /// This operation is cancellable via the provided `CancellationToken`.
        /// </summary>
        /// <param name="key">Property key.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>
        /// The string value associated with the specified key. If the key does not exist in the cache, result is null.
        /// </returns>
        Task<string> GetStringAsync(string key, CancellationToken cancellationToken);

        /// <summary>
        /// Stores a string value with the specified key in the distributed cache asynchronously.
        /// This operation is cancellable via the provided `CancellationToken`.
        /// </summary>
        /// <param name="key">Property key.</param>
        /// <param name="value">Property value.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        Task SetStringAsync(string key, string value, CancellationToken cancellationToken);
    }
}
