using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// Retrieves a populated configuration given an address.
    /// </summary>
    public class DistributedConfigurationRetriever<T> : IDistributedConfigurationRetriever<T> where T : class
    {
        private readonly IConfigurationSerializer<T> _serializer;

        /// <summary>
        /// Instantiate a new <see cref="DistributedConfigurationRetriever{T}"/>.
        /// </summary>
        /// <param name="serializer">A <see cref="IConfigurationSerializer{T}"/> for serializing or deserializing object of type <typeparamref name="T"/>.</param>
        public DistributedConfigurationRetriever(IConfigurationSerializer<T> serializer)
        {
            _serializer = serializer ?? throw LogHelper.LogArgumentNullException(nameof(serializer));
        }

        /// <summary>
        /// Retrieves a populated configuration given an address.
        /// </summary>
        /// <param name="metadataAddress">Address of the discovery document.</param>
        /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> for reading the discovery document</param>
        /// <param name="cancel">A <see cref="CancellationToken"/>.</param>
        /// <returns>A populated configuration.</returns>
        /// <exception cref="NotImplementedException"></exception>
        public async Task<T> GetAsync(
            string metadataAddress,
            IDocumentRetriever docRetriever,
            CancellationToken cancel)
        {
            if (string.IsNullOrWhiteSpace(metadataAddress))
                throw LogHelper.LogArgumentNullException(nameof(metadataAddress));

            if (docRetriever == null)
            {
                throw LogHelper.LogArgumentNullException(nameof(docRetriever));
            }

            string doc = await docRetriever.GetDocumentAsync(metadataAddress, cancel).ConfigureAwait(true);

            if (LogHelper.IsEnabled(EventLogLevel.Verbose))
                LogHelper.LogVerbose(LogMessages.IDX20811, doc);

            T configuration = _serializer.Deserialize(doc);

            return configuration;
        }
    }
}
