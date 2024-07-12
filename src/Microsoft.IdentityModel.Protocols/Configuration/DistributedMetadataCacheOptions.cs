// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Extensions.Caching.Distributed;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// Specifies the DistributedMetadataCacheOptions which can be used to configure the distributed metadata cache.
    /// </summary>
    public class DistributedMetadataCacheOptions
    {
        /// <inheritdoc/>
        public IDistributedCache DistributedCache { get; set; }

        /// <inheritdoc/>
        public IByteArrayCacheTransformer ByteArrayCacheTransformer { get; set; }
    }
}
