using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// Interface that defines methods to retrieve configuration.
    /// </summary>
    public interface IDistributedConfigurationRetriever<T> where T : class
    {
        /// <summary>
        /// Retrieves a populated configuration given an address and an <see cref="IDocumentRetriever"/>.
        /// </summary>
        /// <param name="metadataAddress">Address of the discovery document.</param>
        /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> to use to read the discovery document.</param>
        /// <param name="cancel">A cancellation token that can be used by other objects or threads to receive notice of cancellation. <see cref="CancellationToken"/>.</param>
        Task<T> GetAsync(string metadataAddress, IDocumentRetriever docRetriever, CancellationToken cancel);
    }
}
