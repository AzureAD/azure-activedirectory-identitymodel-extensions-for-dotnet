// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;

namespace Microsoft.IdentityModel.TestUtils
{
    /// <summary>
    /// Returns a string set in the constructor.
    /// Simplifies testing.
    /// </summary>
    public class InMemoryDocumentRetriever : IDocumentRetriever
    {
        private readonly IDictionary<string, string> _configurations;

        /// <summary>
        /// Initializes a new instance of the <see cref="FileDocumentRetriever"/> class.
        /// </summary>
        public InMemoryDocumentRetriever(IDictionary<string, string> configuration)
        {
            _configurations = configuration;
        }

        /// <summary>
        /// Returns the document passed in constructor in dictionary./>
        /// </summary>
        /// <param name="address">Fully qualified path to a file. Ignored for now.</param>
        /// <param name="cancel"><see cref="CancellationToken"/> Ignored for now.</param>
        /// <returns>UTF8 decoding of bytes in the file.</returns>
        public async Task<string> GetDocumentAsync(string address, CancellationToken cancel)
        {
            return await Task.FromResult(_configurations[address]).ConfigureAwait(false);
        }
    }
}
