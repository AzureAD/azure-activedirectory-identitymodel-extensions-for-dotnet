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
using System.Collections.Generic;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    internal class LRUCache<TKey, TValue>
    {
        private int _capacity;
        private int _count = 0;
        private Dictionary<TKey, LinkedListNode<CacheItem<TKey, TValue>>> _map;
        private LinkedList<CacheItem<TKey, TValue>> _doubleLinkedList = new LinkedList<CacheItem<TKey, TValue>>();
        // Used to ensure that the cache is thread-safe.
        private object _cacheLock = new object();

        internal LRUCache(int capacity, IEqualityComparer<TKey> comparer = null)
        {
            _capacity = capacity > 0 ? capacity : throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(capacity)));
            _map = new Dictionary<TKey, LinkedListNode<CacheItem<TKey, TValue>>>(comparer ?? EqualityComparer<TKey>.Default);
        }

        internal bool Contains(TKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            return _map.ContainsKey(key);
        }

        // [[TODO]]: How often and when should this method be called?
        internal int RemoveExpiredValues()
        {
            int numItemsRemoved = 0;
            var node = _doubleLinkedList.First;
            lock (_cacheLock)
            {
                while (node != null)
                {
                    var nextNode = node.Next;
                    if (node.Value.ExpirationTime < DateTime.UtcNow)
                    {
                        _doubleLinkedList.Remove(node);
                        numItemsRemoved++;
                    }

                    node = nextNode;
                }
            }

            return numItemsRemoved;
        }

        internal void SetValue(TKey key, TValue value)
        {
            SetValue(key, value, DateTime.MaxValue);
        }

        internal bool SetValue(TKey key, TValue value, DateTime? expirationTime)
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
                lock (_cacheLock)
                {
                    // make sure node hasn't been removed by a different thread
                    if (_map.TryGetValue(key, out var node))
                        _doubleLinkedList.Remove(node);

                    // add a new item regardless of whether the old item was removed or not
                    _doubleLinkedList.AddFirst(new CacheItem<TKey, TValue>(key, value, expirationTime));
                }
    
                return true;
            }
            else
            {
                // if cache is full, then remove the least recently used node
                if (_count == _capacity)
                {
                    lock (_cacheLock)
                    {
                        var lru = _doubleLinkedList.Last;
                        _map.Remove(lru.Value.Key);
                        _doubleLinkedList.RemoveLast();
                        _count--;
                    }
                 
                }

                // add a new node
                var node = new LinkedListNode<CacheItem<TKey, TValue>>(new CacheItem<TKey, TValue>(key, value, expirationTime));

                lock (_cacheLock)
                {
                    _doubleLinkedList.AddFirst(node);
                    _map[key] = node;
                    _count++;
                }
              
                return true;
            }
        }

        // Each time a node gets accessed, it gets moved to the beginning (head) of the list.
        internal bool TryGetValue(TKey key, out TValue value)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (!_map.ContainsKey(key))
            {
                value = default;
                return false;
            }

            LinkedListNode<CacheItem<TKey, TValue>> node;
            lock (_cacheLock)
            {
                // make sure node hasn't been removed by a different thread
                if (_map.TryGetValue(key, out node))
                {
                    _doubleLinkedList.Remove(node);
                    _doubleLinkedList.AddFirst(node);
                }
            }

            // node.Value is a <key,value> pair containing a key and the node corresponding to it. To get the value that the user
            // is actually caching, we need to return the value of the node itself (Value.Value).
            value = node != null ? node.Value.Value : default;
            return node != null;
        }

        /// <summary>
        /// Removes a particular key from the cache.
        /// </summary>
        /// <param name="key">The cache key.</param>
        /// <param name="value">The cache value.</param>
        internal bool TryRemove(TKey key, out TValue value)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (!_map.ContainsKey(key))
            {
                value = default;
                return false;
            }

            lock (_cacheLock)
            {
                // check to make sure node wasn't removed by a different thread
                if (!_map.TryGetValue(key, out var node))
                {
                    value = default;
                    return false;
                }

                _doubleLinkedList.Remove(node);
                _map.Remove(key);
                value = node.Value.Value;
                _count--;
            }
         
            return true;
        }
    }

    internal class CacheItem<TKey, TValue>
    {
        internal TKey Key { get; set; }
        internal TValue Value { get; set; }
        internal DateTime ExpirationTime { get; set; }

        internal CacheItem(TKey key, TValue value)
        {

            Key = key ?? throw LogHelper.LogArgumentNullException(nameof(key));
            Value = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }

        internal CacheItem(TKey key, TValue value, DateTime? expirationTime)
        {

            Key = key ?? throw LogHelper.LogArgumentNullException(nameof(key));
            Value = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
            ExpirationTime = expirationTime ?? throw LogHelper.LogArgumentNullException(nameof(expirationTime));
        }
    }
}
