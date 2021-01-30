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
        private int capacity;
        private int count = 0;
        Dictionary<TKey, LinkedListNode<CacheItem<TKey, TValue>>> map;
        LinkedList<CacheItem<TKey, TValue>> doubleLinkedList = new LinkedList<CacheItem<TKey, TValue>>();

        internal LRUCache(int capacity, IEqualityComparer<TKey> comparer = null)
        {
            this.capacity = capacity;
            map = new Dictionary<TKey, LinkedListNode<CacheItem<TKey, TValue>>>(comparer ?? EqualityComparer<TKey>.Default);
        }

        internal bool Contains(TKey key)
        {
            return map.ContainsKey(key);
        }

        // [[TODO]]: How often and when should this method be called?
        //internal int RemoveExpiredValues()
        //{
        //    // [[TODO]]: Iterate through list, mark items as expired, and then remove from the cache.
        //}

        internal void SetValue(TKey key, TValue value)
        {
            SetValue(key, value, DateTime.MaxValue);
        }

        // [[TODO]]: Needs locks and null checks.
        internal bool SetValue(TKey key, TValue value, DateTime? expirationTime)
        {
            // item already expired
            if (expirationTime < DateTime.UtcNow)
                return false;

            // just need to update value and move it to the top
            if (map.ContainsKey(key))
            {
                var node = map[key];
                doubleLinkedList.Remove(node);
                doubleLinkedList.AddFirst(new CacheItem<TKey, TValue>(key, value, expirationTime));
                return true;
            }
            else
            {
                // if cache is full, then remove the least recently used node
                if (count == capacity)
                {
                    var lru = doubleLinkedList.Last;
                    map.Remove(lru.Value.Key);
                    doubleLinkedList.RemoveLast();
                    count--;
                }

                // add a new node
                var node = new LinkedListNode<CacheItem<TKey, TValue>>(new CacheItem<TKey, TValue>(key, value, expirationTime));
                doubleLinkedList.AddFirst(node);
                map[key] = node;
                count++;
                return true;
            }
        }

        // [[TODO]]: Needs locks and null checks.
        // Each time a node gets accessed, it gets moved to the beginning (head) of the list.
        internal bool TryGetValue(TKey key, out TValue value)
        {
            if (!map.ContainsKey(key))
            {
                value = default;
                return false;
            }

            var node = map[key];
            doubleLinkedList.Remove(node);
            doubleLinkedList.AddFirst(node);
            // node.Value is a <key,value> pair containing a key and the node corresponding to it. To get the value that the user
            // is actually caching, we need to return the value of the node itself (Value.Value).
            value = node.Value.Value;
            return true;
        }

        /// <summary>
        /// Removes a particular key from the cache.
        /// </summary>
        /// <param name="key">The cache key.</param>
        /// <param name="value">The cache value.</param>
        internal bool TryRemove(TKey key, out TValue value)
        {
            // [[TODO]]: Needs locks and null checks.
            if (!map.ContainsKey(key))
            {
                value = default;
                return false;
            }

            var node = map[key];
            doubleLinkedList.Remove(node);
            map.Remove(key);
            value = node.Value.Value;
            count--;
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
