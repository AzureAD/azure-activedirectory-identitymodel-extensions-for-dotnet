// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Synchronous interface that defines a document retriever that returns the document as a string.
    /// </summary>
    public interface ISyncDocumentRetriever
    {
        /// <summary>
        /// Obtains a document from an address.
        /// </summary>
        /// <param name="address">location of document.</param>
        /// <param name="cancel"><see cref="CancellationToken"/>.</param>
        /// <returns>document as a string.</returns>
        string GetDocumentSync(string address, CancellationToken cancel);
    }
}
