using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// Retrieves a populated configuration given an address.
    /// </summary>
    public class DistributedConfigurationRetriever<T> : IDistributedConfigurationRetriever<T> where T : class
    {
        /// <summary>
        /// Retrieves a populated configuration given an address.
        /// </summary>
        /// <param name="metadataAddress">Address of the discovery document.</param>
        /// <param name="docRetriever"></param>
        /// <param name="cancel"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public Task<T> GetAsync(
            string metadataAddress,
            IDocumentRetriever docRetriever,
            CancellationToken cancel) => throw new NotImplementedException();
    }
}
