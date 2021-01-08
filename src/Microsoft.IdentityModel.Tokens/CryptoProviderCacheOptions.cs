//------------------------------------------------------------------------------------------------
// <copyright file="TokenValidator.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

using System;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Specifies the CryptoProviderCacheOptions which can be used to configure the internal cryptoprovider cache.
    /// For the net461, net472, and netstandard2.0 targets we are using the Microsoft.Extensions.Caching.Memory.MemoryCache class:
    /// https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.caching.memory.memorycache
    /// For the net45 target we are using our own simple caching implementation which clears the entire cache
    /// once the cache is at max capacity. We recommend upgrading to net461+ for a more comprehensive caching experience.
    /// Any property on these CryptoProviderCacheOptions that corresponds directly to a property 
    /// used by Microsoft.Extensions.Caching.Memory.MemoryCache has the same name.
    /// </summary>
    public class CryptoProviderCacheOptions
    {
        private int _sizeLimit = DefaultSizeLimit;

        /// <summary>
        /// Default value for <see cref="SizeLimit"/>.
        /// </summary>
        public static readonly int DefaultSizeLimit = 1000;

        /// <summary>
        /// Gets or sets the size of the cache (in number of items). 
        /// On the net45 target, the entire cache will be cleared once the cache reaches max capacity.
        /// In the case of the netstandard2.0 target, 20% of the cache will be evicted whenever the cache gets to 95% of this size,
        /// and items will be evicted in the following order:
        /// 1) All expired items.
        /// 2) Least recently used items.
        /// 3) Items with the earliest absolute expiration.
        /// The cache on the net45 target behaves in a similar way, except it doesn't consider #3 (items with the earliest
        /// absolute expiration).
        /// </summary>
        public int SizeLimit
        {
            get
            {
                return _sizeLimit;
            }
            set
            {
                _sizeLimit = (value > 0) ? value : throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(value)));
            }
        }
    }
}
