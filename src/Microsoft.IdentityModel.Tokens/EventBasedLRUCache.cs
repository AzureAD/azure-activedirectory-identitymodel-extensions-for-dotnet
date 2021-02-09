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
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    internal class EventBasedLRUCache<TKey, TValue> : ILRUCache<TKey,TValue>, IDisposable
    {
        private int _capacity;
        private ConcurrentDictionary<TKey, LRUCacheItem<TKey, TValue>> _map;
        private LinkedList<LRUCacheItem<TKey, TValue>> _doubleLinkedList = new LinkedList<LRUCacheItem<TKey, TValue>>();
        private readonly BlockingCollection<Action> _eventQueue = new BlockingCollection<Action>();
        private bool _disposed = false;

        internal EventBasedLRUCache(int capacity, IEqualityComparer<TKey> comparer = null)
        {
            _capacity = capacity > 0 ? capacity : throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(capacity)));
            _map = new ConcurrentDictionary<TKey, LRUCacheItem<TKey, TValue>>(comparer ?? EqualityComparer<TKey>.Default);

            var thread = new Thread(new ThreadStart(OnStart));
            thread.IsBackground = true;
            thread.Start();

            Task timerTask = RemoveExpiredValuesPeriodically(TimeSpan.FromMinutes(5));
        }

        private void OnStart()
        {
            while (true)
            {
                _eventQueue.Take().Invoke();
            }
        }

        public bool Contains(TKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            return _map.ContainsKey(key);
        }

        public int RemoveExpiredValues()
        {
            int numItemsRemoved = 0;
            var node = _doubleLinkedList.First;
            while (node != null)
            {
                var nextNode = node.Next;
                if (node.Value.ExpirationTime < DateTime.UtcNow)
                {
                    _doubleLinkedList.Remove(node);
                    _map.TryRemove(node.Value.Key, out _);
                    numItemsRemoved++;
                }

                node = nextNode;
            }

            return numItemsRemoved;
        }

        async Task RemoveExpiredValuesPeriodically(TimeSpan interval)
        {
            while (true)
            {
                _eventQueue.Add(() => RemoveExpiredValues());
                await Task.Delay(interval).ConfigureAwait(false);
            }
        }

        public void SetValue(TKey key, TValue value)
        {
            SetValue(key, value, DateTime.MaxValue);
        }

        public bool SetValue(TKey key, TValue value, DateTime? expirationTime)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (value == null)
                throw LogHelper.LogArgumentNullException(nameof(value));

            if (expirationTime == null)
                throw LogHelper.LogArgumentNullException(nameof(expirationTime));

            // item already expired
            if (expirationTime < DateTime.UtcNow)
                return false;

            // just need to update value and move it to the top
            if (_map.ContainsKey(key))
            {
                // make sure node hasn't been removed by a different thread
                if (_map.TryGetValue(key, out var cacheItem))
                    _eventQueue.Add(() => _doubleLinkedList.Remove(cacheItem));

                // add a new item regardless of whether the old item was removed or not
                _eventQueue.Add(() => _doubleLinkedList.AddFirst(new LRUCacheItem<TKey, TValue>(key, value, expirationTime)));

                return true;
            }
            else
            {
                // if cache is full, then remove the least recently used node
                if (_map.Count >= _capacity)
                {                
                    _eventQueue.Add(() =>
                    {
                        var lru = _doubleLinkedList.Last;
                        _map.TryRemove(lru.Value.Key, out _);
                        _doubleLinkedList.Remove(lru);
                    });
                }

                // add a new node
                var node = new LRUCacheItem<TKey, TValue>(key, value, expirationTime);
                _eventQueue.Add(() => _doubleLinkedList.AddFirst(node));
                _map[key] = node;

                return true;
            }
        }

        /// Each time a node gets accessed, it gets moved to the beginning (head) of the list.
        public bool TryGetValue(TKey key, out TValue value)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (!_map.ContainsKey(key))
            {
                value = default;
                return false;
            }

            LRUCacheItem<TKey, TValue> cacheItem;
            // make sure node hasn't been removed by a different thread
            if (_map.TryGetValue(key, out cacheItem))
                _eventQueue.Add(() =>
                {
                    _doubleLinkedList.Remove(cacheItem);
                    _doubleLinkedList.AddFirst(cacheItem);
                });

            value = cacheItem != null ? cacheItem.Value : default;
            return cacheItem != null;
        }

        /// Removes a particular key from the cache.
        public bool TryRemove(TKey key, out TValue value)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (!_map.ContainsKey(key))
            {
                value = default;
                return false;
            }

            // check to make sure node wasn't removed by a different thread
            if (!_map.TryGetValue(key, out var cacheItem))
            {
                value = default;
                return false;
            }

            _eventQueue.Add(() => _doubleLinkedList.Remove(cacheItem));
            _map.TryRemove(key, out _);
            value = cacheItem.Value;

            return true;
        }

        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
        /// <returns></returns>
        internal LinkedList<LRUCacheItem<TKey, TValue>> LinkedListValues()
        {
            return _doubleLinkedList;
        }

        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
        /// <returns></returns>
        internal ICollection<LRUCacheItem<TKey, TValue>> MapValues()
        {
            return _map.Values;
        }

        /// <summary>
        /// Calls <see cref="Dispose(bool)"/> and <see cref="GC.SuppressFinalize"/>
        /// </summary>
        public void Dispose()
        {
            // Dispose of unmanaged resources.
            Dispose(true);
            // Suppress finalization.
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// If <paramref name="disposing"/> is true, this method disposes of <see cref="_eventQueue"/>.
        /// </summary>
        /// <param name="disposing">True if called from the <see cref="Dispose()"/> method, false otherwise.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;
                if (disposing)
                {
                    _eventQueue.Dispose();
                }
            }
        }
    }


    /// <summary>
    /// 
    /// </summary>
    /// <typeparam name="TKey"></typeparam>
    /// <typeparam name="TValue"></typeparam>
    internal class LRUCacheItem<TKey, TValue>
    {
        /// <summary>
        /// 
        /// </summary>
        internal TKey Key { get; set; }
        /// <summary>
        /// 
        /// </summary>
        internal TValue Value { get; set; }
        /// <summary>
        /// 
        /// </summary>
        internal DateTime ExpirationTime { get; set; }

        internal LRUCacheItem(TKey key, TValue value)
        {

            Key = key ?? throw LogHelper.LogArgumentNullException(nameof(key));
            Value = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }

        internal LRUCacheItem(TKey key, TValue value, DateTime? expirationTime)
        {

            Key = key ?? throw LogHelper.LogArgumentNullException(nameof(key));
            Value = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
            ExpirationTime = expirationTime ?? throw LogHelper.LogArgumentNullException(nameof(expirationTime));
        }
    }
}

