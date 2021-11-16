//------------------------------------------------------------------------------
//
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
// all copies or substantial portions of the Software.CryptoProviderCacheOptions
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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    internal class RandomEvictCache<TKey, TValue> : IProviderCache<TKey, TValue>
    {
        // delegates
        internal delegate void ItemRemoved(TValue Value);
        internal ItemRemoved OnItemRemoved { get; set; }

        // _capacity is used for the newCacheSize calculation in the case where the cache is experiencing overflow
        protected readonly int _capacity;

        // the percentage of the cache to be removed when _maxCapacityPercentage is reached
        protected readonly double _compactionPercentage = CryptoProviderCacheOptions.DefaultCompactionPercentage;

        // When the current cache size gets to this percentage of _capacity, _compactionPercentage% of the cache will be removed.
        protected readonly double _maxCapacityPercentage = CryptoProviderCacheOptions.DefaultMaxCapacityPercentage;

        private readonly ConcurrentDictionary<TKey, CacheItem<TKey, TValue>> _map;

        private const int CompactionStateNotRunning = 0; // no compaction running
        private const int CompactionStateInProgress = 1; // compaction in progress
        private int _compactionState = CompactionStateNotRunning;

        #region constructors

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="cryptoProviderCacheOptions">Specifies the options which can be used to configure the cache settings.</param>
        /// <param name="comparer">The equality comparison implementation to be used by the map when comparing keys.</param>
        internal RandomEvictCache(
            CryptoProviderCacheOptions cryptoProviderCacheOptions,
            IEqualityComparer<TKey> comparer = null)
        {
            _capacity = cryptoProviderCacheOptions.SizeLimit;
            _compactionPercentage = cryptoProviderCacheOptions.CompactionPercentage;
            _maxCapacityPercentage = cryptoProviderCacheOptions.MaxCapacityPercentage;
            _map = new ConcurrentDictionary<TKey, CacheItem<TKey, TValue>>(comparer ?? EqualityComparer<TKey>.Default);
        }

        #endregion

        #region public

        /// <summary>
        /// Gets or sets the value associated with the specified key.
        /// </summary>
        /// <param name="key">The key of the value to get or set.</param>
        /// For get, if the specified key is not found, a <exception cref="KeyNotFoundException"> will be thrown.</exception>
        /// For set, if the key is null throw an <exception cref="ArgumentNullException"> will be thrown.</exception>
        public CacheItem<TKey, TValue> this[TKey key]
        {
            get => _map[key];
            set => _map[key] = value;
        }

        /// <inheritdoc/>
        public virtual bool Contains(TKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            return _map.ContainsKey(key);
        }

        /// <inheritdoc/>
        public virtual void SetValue(TKey key, TValue value)
        {
            SetValue(key, value, DateTime.MaxValue);
        }

        /// <inheritdoc/>
        public virtual bool SetValue(TKey key, TValue value, DateTime expirationTime)
        {
            ValidateValues(key, value, expirationTime);
            if (NeedsCompaction && Interlocked.CompareExchange(ref _compactionState, CompactionStateInProgress, CompactionStateNotRunning) == CompactionStateNotRunning)
                ThreadPool.QueueUserWorkItem(CompactCache);

            _map[key] = new CacheItem<TKey, TValue>(key, value, expirationTime);

            return true;
        }

        /// <inheritdoc/>
        public virtual bool TryGetValue(TKey key, out TValue value)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            value = default;
            var found = TryGetValueInternal(key, out CacheItem<TKey, TValue> val);
            if (found)
                value = val.Value;

            return found;
        }

        /// <inheritdoc/>
        public virtual bool TryRemove(TKey key, out TValue value)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            value = default;

            var found = TryRemoveInternal(key, out CacheItem<TKey, TValue> val);
            if (found)
                value = val.Value;

            return found;
        }

        #endregion


        #region protected

        /// <summary>
        /// The internal version of TryGetValue that gets the LRUCacheItem from the hash.
        /// </summary>
        /// <param name="key">The key of the value to get.</param>
        /// <param name="value">The object that has the specified key, or the default value of the type if the not found.</param>
        /// <returns>true if the key was found, otherwise, false.</returns>
        protected virtual bool TryGetValueInternal(TKey key, out CacheItem<TKey, TValue> value)
        {
            value = default;

            var found = _map.TryGetValue(key, out CacheItem<TKey, TValue> val);
            if (found)
                value = val;

            return found;
        }

        /// <summary>
        /// Attempts to remove and return the value that has the specified key from the cache.
        /// </summary>
        /// <param name="key">The key of the element to remove and return.</param>
        /// <param name="value">The object removed from the cache, or the default value of the TValue type if key does not exist.</param>
        /// <returns>true if the object was removed successfully; otherwise, false.</returns>
        protected virtual bool TryRemoveInternal(TKey key, out CacheItem<TKey, TValue> value)
        {
            value = default;

            var found = _map.TryRemove(key, out CacheItem<TKey, TValue> val);
            if (found)
                value = val;

            return found;
        }

        /// <summary>
        /// Validate the key, value and check the expiration time before adding the item is added to the cache.
        /// </summary>
        /// <param name="key">The key of the item to be added to the cache.</param>
        /// <param name="value">The value of the item to be added to the cache.</param>
        /// <param name="expirationTime">The expiration time of the item.</param>
        /// <returns>true if valid, false otherwise.</returns>
        protected static bool ValidateValues(TKey key, TValue value, DateTime expirationTime)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (value == null)
                throw LogHelper.LogArgumentNullException(nameof(value));

            // if item already expired, do not add it to the cache
            return expirationTime >= DateTime.UtcNow;
        }

        /// <summary>
        /// When the cache is at _maxCapacityPercentage, it needs to be compacted by _compactionPercentage.
        /// This method calculates the new size of the cache after being compacted.
        /// </summary>
        /// <returns>The new target cache size after compaction.</returns>
        protected int CalculateNewCacheSize()
        {
            // use the smaller of _map.Count and _capacity
            int currentCount = Math.Min(_map.Count, _capacity);
            return currentCount - (int)(currentCount * _compactionPercentage);
        }

        /// <summary>
        /// Determine if the cache needs compaction.
        /// </summary>
        protected bool NeedsCompaction => (double)_map.Count / _capacity >= _maxCapacityPercentage;

        #endregion

        /// <summary>
        /// Remove items from the map by the desired compaction percentage.
        /// Since this is a simple hash-based cache that does not track the last used time of items, simply remove the desired number of items.
        /// This should be a private method.
        /// </summary>
        private void CompactCache(object state)
        {
            // use the _capacity for the newCacheSize calculation in the case where the cache is experiencing overflow
            var newCacheSize = CalculateNewCacheSize();
            while (_map.Count > newCacheSize)
            {
                var item = _map.FirstOrDefault();
                if (_map.TryRemove(item.Key, out var cacheItem))
                    OnItemRemoved?.Invoke(cacheItem.Value);
            }

            // reset the _compactionState to CompactionStateNotRunning
            _compactionState = CompactionStateNotRunning;
        }

        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
        internal int Count => _map.Count;

        #region FOR TESTING (INTERNAL ONLY)

        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
        internal virtual long EventQueueCount => 0;

        /// <summary>
        /// FOR TESTING PURPOSES ONLY.
        /// </summary>
        internal virtual int TaskCount => 0;

        internal virtual void WaitForProcessing()
        {
            while (true)
            {
                if (_compactionState == CompactionStateNotRunning)
                    return;
            }
        }

        #endregion
    }
}
