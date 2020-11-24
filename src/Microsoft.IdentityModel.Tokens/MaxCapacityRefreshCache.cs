// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

namespace Microsoft.IdentityModel.Tokens
{
    using System.Collections.Concurrent;
    using System.Collections.Generic;

    /// <summary>
    /// A cache that clears itself upon reaching max capacity.
    /// </summary>
    /// <typeparam name="TKey">The type of cache key.</typeparam>
    /// <typeparam name="TValue">The type of cached value.</typeparam>
    internal class MaxCapacityRefreshCache
        <TKey, TValue>
        where TValue : class
    {
        /// <summary>
        /// Gets or sets the cache.
        /// </summary>
        private ConcurrentDictionary<TKey, TValue> Cache { get; set; }

        /// <summary>
        /// Gets or sets the cache size limit.
        /// </summary>
        private long SizeLimit { get; set; }

        /// <summary>
        /// Gets or sets the lock for recycle operations.
        /// </summary>
        private object RecycleLock { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="MaxCapacityRefreshCache{TKey,TValue}" /> class.
        /// </summary>
        /// <param name="sizeLimit">The max number of items the cache is capable of holding.</param>
        /// <param name="comparer">The string comparer.</param>
        internal MaxCapacityRefreshCache(
            long sizeLimit,
            IEqualityComparer<TKey> comparer = null)
        {
            RecycleLock = new object();
            SizeLimit = sizeLimit;
            Cache = new ConcurrentDictionary<TKey, TValue>(comparer ?? EqualityComparer<TKey>.Default);
        }

        internal bool Contains(TKey key)
        {
            return Cache.ContainsKey(key);
        }

        /// <summary>
        /// Gets the value corresponding to <paramref name="value"/> from the cache.
        /// </summary>
        /// <param name="cacheKey">The cache key.</param>
        /// <param name="value">The cached value.</param>
        /// <remarks>This method is non-blocking and thread-safe.</remarks>
        internal bool TryGetValue(TKey cacheKey, out TValue value)
        {
            RecycleCacheIfNeeded();
            return Cache.TryGetValue(cacheKey, out value);           
        }

        /// <summary>
        /// Sets the cache value.
        /// </summary>
        /// <param name="cacheKey">The cache key.</param>
        /// <param name="value">The value.</param>
        /// <returns><paramref name="value"/> if it was successfully set, null otherwise.</returns>
        /// <remarks>This method is non-blocking and thread-safe.</remarks>
        /// <remarks>This value will not be set if the cache already contains a key with the same name as <paramref name="cacheKey"/>.</remarks>
        internal TValue SetValue(TKey cacheKey, TValue value)
        {
            RecycleCacheIfNeeded();
            if (Cache.TryAdd(cacheKey, value))
                return value;
            else
                return null;
        }

        /// <summary>
        /// Removes a particular key from the cache.
        /// </summary>
        /// <param name="cacheKey">The cache key.</param>
        internal bool TryRemove(TKey cacheKey)
        {
            RecycleCacheIfNeeded();
            return Cache.TryRemove(cacheKey, out _);
        }

        /// <summary>
        /// Removes the value corresponding to <paramref name="cacheKey"/>.
        /// </summary>
        /// <param name="cacheKey">The cache key.</param>
        /// <param name="removedValue">The removed value.</param>
        internal bool TryRemove(TKey cacheKey, out TValue removedValue)
        {
            RecycleCacheIfNeeded();
            return Cache.TryRemove(cacheKey, out removedValue);
        }

        /// <summary>
        /// Recycles the cache if needed.
        /// </summary>
        private void RecycleCacheIfNeeded()
        {
            if (SizeLimit == Cache.Keys.Count)
            {
                lock (RecycleLock)
                    Cache.Clear();
            }           
        }
    }
}

