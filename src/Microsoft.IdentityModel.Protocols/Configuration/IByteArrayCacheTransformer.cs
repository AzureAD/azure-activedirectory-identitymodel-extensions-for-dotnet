// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// Interface that defines methods to transform byte arrays before they are written to a cache and after they are retrieved from a cache.
    /// </summary>
    public interface IByteArrayCacheTransformer
    {
        /// <summary>
        /// Transform the provided <see cref="byte"/> array before it is written to a cache.
        /// </summary>
        /// <param name="data">The <see cref="byte"/>s to be transformed.</param>
        /// <returns>The result of the transformation.</returns>
        byte[] TransformBeforeCaching(byte[] data);

        /// <summary>
        /// TRansform the provided <see cref="byte"/> array after it is retrieved from a cache.
        /// </summary>
        /// <param name="data">The <see cref="byte"/>s to be transformed.</param>
        /// <returns>The result of the transformation.</returns>
        byte[] TransformAfterRetrieval(byte[] data);
    }
}
