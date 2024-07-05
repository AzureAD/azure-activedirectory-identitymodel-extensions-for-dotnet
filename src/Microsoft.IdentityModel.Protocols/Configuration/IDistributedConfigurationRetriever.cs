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
    public interface IDistributedConfigurationRetriever<T> where T : class
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="metadataAddress"></param>
        /// <param name="docRetriever"></param>
        /// <param name="none"></param>
        /// <returns></returns>
        Task<T> GetConfigurationAsync(string metadataAddress, IDocumentRetriever docRetriever, CancellationToken none);
    }
}
