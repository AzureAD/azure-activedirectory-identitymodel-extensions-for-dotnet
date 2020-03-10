// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.ServiceModel.Caching
{
    /// <summary>
    /// An in-memory cache of security token responses which will not expire unless removed from the cache.
    /// </summary>
    public class InMemorySecurityTokenResponseCache<TKey, TValue> : ISecurityTokenResponseCache<TKey, TValue> where TValue: class
    {
        private readonly ConcurrentDictionary<TKey, TValue> _dictionary;

        /// <summary>
        /// Creates a new instance of the InMemorySecurityTokenResponseCache type, using the default comparer
        /// for TKey to compare keys.
        /// </summary>
        public InMemorySecurityTokenResponseCache() : this(EqualityComparer<TKey>.Default) { }

        /// <summary>
        /// Creates a new instance of the InMemorySecurityTokenResponseCache type. 
        /// </summary>
        /// <param name="comparer">The comparer to use for comparing TKey instances.</param>
        public InMemorySecurityTokenResponseCache(IEqualityComparer<TKey> comparer)
        {
            _dictionary = new ConcurrentDictionary<TKey, TValue>(comparer);
        }

        /// <summary>
        /// Store a security token response in the cache with a particular key.
        /// </summary>
        /// <param name="key">The key to use for the provided response.</param>
        /// <param name="response">The security token response to store.</param>
        public void CacheSecurityTokenResponse(TKey key, TValue response)
        {
            if (response is null)
            {
                throw new ArgumentNullException(nameof(response));
            }

            _dictionary.AddOrUpdate(key, response, (_, __) => response);
        }

        /// <summary>
        /// Asynchronously store a security token response in the cache with a particular key.
        /// </summary>
        /// <param name="key">The key to use for the provided response.</param>
        /// <param name="response">The security token response to store.</param>
        public Task CacheSecurityTokenResponseAsync(TKey key, TValue response)
        {
            CacheSecurityTokenResponse(key, response);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Retrieve a security token response from the cache.
        /// </summary>
        /// <param name="key">The key corresponding to the security token response to return.</param>
        /// <returns>The security token response corresponding to the key or null if the key is not present in the cache.</returns>
        public TValue GetSecurityTokenResponse(TKey key) => _dictionary.TryGetValue(key, out TValue response)
            ? response
            : null;

        /// <summary>
        /// Asynchronously retrieve a security token response from the cache.
        /// </summary>
        /// <param name="key">The key corresponding to the security token response to return.</param>
        /// <returns>The security token response corresponding to the key or null if the key is not present in the cache.</returns>
        public Task<TValue> GetSecurityTokenResponseAsync(TKey key) => Task.FromResult(GetSecurityTokenResponse(key));

        /// <summary>
        /// Remove a security token response from the cache. The response is found in the cache with reference equality.
        /// </summary>
        /// <param name="response">The security token response to be removed from the cache.</param>
        /// <returns>True if the response was removed from the cache, otherwise false.</returns>
        public bool RemoveSecurityTokenResponse(TValue response)
        {
            bool ret = false;

            foreach (TKey key in _dictionary.Where(kvp => ReferenceEquals(kvp.Value, response)).Select(kvp => kvp.Key))
            {
                ret |= RemoveSecurityTokenResponseByKey(key);
            }

            return ret;
        }

        /// <summary>
        /// Asynchronously remove a security token response from the cache. The response is found in the cache with reference equality.
        /// </summary>
        /// <param name="response">The security token response to be removed from the cache.</param>
        /// <returns>True if the response was removed from the cache, otherwise false.</returns>
        public Task<bool> RemoveSecurityTokenResponseAsync(TValue response) => Task.FromResult(RemoveSecurityTokenResponse(response));

        /// <summary>
        /// Remove a security token response from the cache.
        /// </summary>
        /// <param name="key">The key corresponding to the security token response to be removed from the cache.</param>
        /// <returns>True if the response was removed from the cache, otherwise false.</returns>
        public bool RemoveSecurityTokenResponseByKey(TKey key) => _dictionary.TryRemove(key, out _);

        /// <summary>
        /// Asynchronously remove a security token response from the cache.
        /// </summary>
        /// <param name="key">The key corresponding to the security token response to be removed from the cache.</param>
        /// <returns>True if the response was removed from the cache, otherwise false.</returns>
        public Task<bool> RemoveSecurityTokenResponseByKeyAsync(TKey key) => Task.FromResult(RemoveSecurityTokenResponseByKey(key));
    }
}
