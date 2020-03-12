// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Threading.Tasks;

namespace System.ServiceModel.Caching
{
    /// <summary>
    /// An in-memory cache of security tokens which will not expire unless removed from the cache.
    /// </summary>
    public class InMemoryWSTrustSecurityTokenCache<TKey> : ISecurityTokenCache<TKey>
    {
        private readonly ConcurrentDictionary<TKey, SecurityToken> _dictionary;

        /// <summary>
        /// Creates a new instance of the InMemoryWSTrustSecurityTokenCache type. 
        /// </summary>
        /// <param name="comparer">The comparer to use for comparing TKey instances.</param>
        public InMemoryWSTrustSecurityTokenCache(IEqualityComparer<TKey> comparer)
        {
            _dictionary = new ConcurrentDictionary<TKey, SecurityToken>(comparer);
        }

        /// <summary>
        /// Store a security token in the cache with a particular key.
        /// </summary>
        /// <param name="tokenKey">The key to use for the provided security token.</param>
        /// <param name="securityToken">The security token to store.</param>
        public void CacheSecurityToken(TKey tokenKey, SecurityToken securityToken)
        {
            if (securityToken is null)
            {
                throw new ArgumentNullException(nameof(securityToken));
            }

            _dictionary.AddOrUpdate(tokenKey, securityToken, (_, __) => securityToken);
        }

        /// <summary>
        /// Asynchronously store a security token in the cache with a particular key.
        /// </summary>
        /// <param name="tokenKey">The key to use for the provided security token.</param>
        /// <param name="securityToken">The security token to store.</param>
        public Task CacheSecurityTokenAsync(TKey tokenKey, SecurityToken securityToken)
        {
            CacheSecurityToken(tokenKey, securityToken);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Retrieve a security token from the cache.
        /// </summary>
        /// <param name="tokenKey">The key corresponding to the security token to return.</param>
        /// <returns>The security token corresponding to the key or null if the key is not present in the cache.</returns>
        public SecurityToken GetSecurityToken(TKey tokenKey) => _dictionary.TryGetValue(tokenKey, out SecurityToken token)
            ? token
            : null;

        /// <summary>
        /// Asynchronously retrieve a security token from the cache.
        /// </summary>
        /// <param name="tokenKey">The key corresponding to the security token to return.</param>
        /// <returns>The security token corresponding to the key or null if the key is not present in the cache.</returns>
        public Task<SecurityToken> GetSecurityTokenAsync(TKey tokenKey) => Task.FromResult(GetSecurityToken(tokenKey));

        /// <summary>
        /// Remove a security token from the cache.
        /// </summary>
        /// <param name="securityToken">The security token to be removed from the cache.</param>
        /// <returns>True if the security token was removed from the cache, otherwise false.</returns>
        public bool RemoveSecurityToken(SecurityToken securityToken)
        {
            bool ret = false;

            foreach (TKey key in _dictionary.Where(kvp => ReferenceEquals(kvp.Value, securityToken)).Select(kvp => kvp.Key))
            {
                ret |= RemoveSecurityTokenByKey(key);
            }

            return ret;
        }

        /// <summary>
        /// Asynchronously remove a security token from the cache.
        /// </summary>
        /// <param name="securityToken">The security token to be removed from the cache.</param>
        /// <returns>True if the security token was removed from the cache, otherwise false.</returns>
        public Task<bool> RemoveSecurityTokenAsync(SecurityToken securityToken) => Task.FromResult(RemoveSecurityToken(securityToken));

        /// <summary>
        /// Remove a security token from the cache.
        /// </summary>
        /// <param name="tokenKey">The key corresponding to the security token to be removed from the cache.</param>
        /// <returns>True if the security token was removed from the cache, otherwise false.</returns>
        public bool RemoveSecurityTokenByKey(TKey tokenKey) => _dictionary.TryRemove(tokenKey, out _);

        /// <summary>
        /// Asynchronously remove a security token from the cache.
        /// </summary>
        /// <param name="tokenKey">The key corresponding to the security token to be removed from the cache.</param>
        /// <returns>True if the security token was removed from the cache, otherwise false.</returns>
        public Task<bool> RemoveSecurityTokenByKeyAsync(TKey tokenKey) => Task.FromResult(RemoveSecurityTokenByKey(tokenKey));
    }
}
