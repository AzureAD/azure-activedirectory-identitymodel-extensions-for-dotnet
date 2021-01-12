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

using System.Collections.Concurrent;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Tokens
{
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
        private ConcurrentDictionary<TKey, TValue> Cache { get; }

        /// <summary>
        /// Gets or sets the cache size limit.
        /// </summary>
        private long SizeLimit { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="MaxCapacityRefreshCache{TKey,TValue}" /> class.
        /// </summary>
        /// <param name="sizeLimit">The max number of items the cache is capable of holding.</param>
        /// <param name="comparer">The string comparer.</param>
        internal MaxCapacityRefreshCache(
            long sizeLimit,
            IEqualityComparer<TKey> comparer = null)
        {
            SizeLimit = sizeLimit;
            Cache = new ConcurrentDictionary<TKey, TValue>(comparer ?? EqualityComparer<TKey>.Default);
        }

        internal bool Contains(TKey key)
        {
            return Cache.ContainsKey(key);
        }

        /// <summary>
        /// Gets the value corresponding to <paramref name="cacheKey"/> from the cache.
        /// </summary>
        /// <param name="cacheKey">The cache key.</param>
        /// <param name="value">The cached value.</param>
        internal bool TryGetValue(TKey cacheKey, out TValue value)
        {
            RecycleCacheIfNeeded();
            return Cache.TryGetValue(cacheKey, out value);           
        }

        /// <summary>
        /// Sets the <paramref name="cacheKey"/> along with its corresponding <paramref name="value"/>.
        /// </summary>
        /// <param name="cacheKey">The cache key.</param>
        /// <param name="value">The value.</param>
        /// <returns><paramref name="value"/> if it was successfully set.</returns>
        /// <remarks>If the cache already contains a key with the same name as <paramref name="cacheKey"/>, the corresponding value will be overridden with <paramref name="value"/>.</remarks>
        internal TValue SetValue(TKey cacheKey, TValue value)
        {
            RecycleCacheIfNeeded();
            Cache[cacheKey] = value;
            return value;
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
            if (SizeLimit <= Cache.Keys.Count)
                    Cache.Clear();
        }
    }
}

